using System;
using System.Security.Claims;
using System.Threading.Tasks;
using GST.Fake.Builder;
using Microsoft.AspNetCore.Authentication;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Collections;
using GST.Fake.Authentication.JwtBearer.Events;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using GST.Fake.Authentication.JwtBearer.Core;
using System.Security.Cryptography;

namespace GST.Fake.Authentication.JwtBearer
{
    internal class FakeJwtBearerHandler : AuthenticationHandler<FakeJwtBearerOptions>
    {
        public FakeJwtBearerHandler(IOptionsMonitor<FakeJwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, IDataProtectionProvider dataProtection, ISystemClock clock)
            : base(options, logger, encoder, clock)
        { }


        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring. 
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new JwtBearerEvents Events
        {
            get {
                if(base.Events is JwtBearerEvents)
                {
                    return base.Events as JwtBearerEvents;
                }
                base.Events = new JwtBearerEvents();
                return base.Events as JwtBearerEvents; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Searches the 'Authorization' header for a 'Bearer' token.
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string token = null;
            string JWTToken = null;
            try
            {
                // Give application opportunity to find from a different location, adjust, or reject token
                MessageReceivedContext messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);

                // event can set the token
                await Events.MessageReceived(messageReceivedContext);
                if (messageReceivedContext.Result != null)
                {
                    return messageReceivedContext.Result;
                }

                // If application retrieved token from somewhere else, use that.
                token = messageReceivedContext.Token;

                if (string.IsNullOrEmpty(token))
                {
                    string authorization = Request.Headers["Authorization"];

                    // If no authorization header found, nothing to process further
                    if (string.IsNullOrEmpty(authorization))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    if (authorization.StartsWith(Constant.SCHEME_NAME + " ", StringComparison.OrdinalIgnoreCase))
                    {
                        token = authorization.Substring((Constant.SCHEME_NAME + " ").Length).Trim();

                        string header = "{\"alg\": \"HS256\",\"typ\": \"JWT\"}";
                        string headerB64 = Base64UrlEncode(GetBytes(header));

                        string payloadB64 = Base64UrlEncode(GetBytes(token));

                        byte[] bytesToSign = GetBytes(string.Join(".", headerB64, payloadB64));

                        string computedSignature = Base64UrlEncode(new HMACSHA256(GetBytes("secret")).ComputeHash(bytesToSign));

                        JWTToken = string.Join(".", headerB64, payloadB64, computedSignature);
                    }

                    // If no token found, no further work possible
                    if (string.IsNullOrEmpty(token))
                    {
                        return AuthenticateResult.NoResult();
                    }
                }

                Dictionary<string, dynamic> tokenDecoded = JsonConvert.DeserializeObject<Dictionary<string, dynamic>>(token);

                ClaimsIdentity id = new ClaimsIdentity("Identity.Application", "name", "role");

                foreach (KeyValuePair<string, dynamic> td in tokenDecoded)
                {
                    if (td.Key == "sub")
                    {
                        id.AddClaim(new Claim("sub", td.Value.ToString()));
                        if (!tokenDecoded.Any(c => c.Key == "name"))
                        {
                            id.AddClaim(new Claim("name", td.Value.ToString()));
                        }
                    }
                    else
                    {
                        if (td.Value is string)
                        {
                            id.AddClaim(new Claim(td.Key, td.Value));
                        }
                        else if (td.Value is IEnumerable)
                        {
                            foreach (string subValue in td.Value)
                            {
                                id.AddClaim(new Claim(td.Key, subValue));
                            }
                        }
                        else
                        {
                            throw new Exception("Unknown type");
                        }
                    }
                }

                ClaimsPrincipal principal = new ClaimsPrincipal(id);

                TokenValidatedContext tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
                {
                    Principal = principal
                };

                await Events.TokenValidated(tokenValidatedContext);
                if (tokenValidatedContext.Result != null)
                {
                    return tokenValidatedContext.Result;
                }

                if (Options.SaveToken)
                {
                    tokenValidatedContext.Properties.StoreTokens(new[]
                    {
                        new AuthenticationToken { Name = "access_token", Value = JWTToken }
                    });
                }

                tokenValidatedContext.Success();
                return tokenValidatedContext.Result;
            }
            catch (Exception ex)
            {
                AuthenticationFailedContext authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex
                };

                await Events.AuthenticationFailed(authenticationFailedContext);
                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                throw;
            }
        }

        protected override async Task HandleChallengeAsync(Microsoft.AspNetCore.Authentication.AuthenticationProperties properties)
        {
            AuthenticateResult authResult = await HandleAuthenticateOnceSafeAsync();
            JwtBearerChallengeContext eventContext = new JwtBearerChallengeContext(Context, Scheme, Options, properties)
            {
                AuthenticateFailure = authResult?.Failure
            };

            await Events.Challenge(eventContext);
            if (eventContext.Handled)
            {
                return;
            }

            Response.StatusCode = 401;

            if (string.IsNullOrEmpty(eventContext.Error) &&
                string.IsNullOrEmpty(eventContext.ErrorDescription) &&
                string.IsNullOrEmpty(eventContext.ErrorUri))
            {
                Response.Headers.Append(HeaderNames.WWWAuthenticate, Options.Challenge);
            }
            else
            {
                // https://tools.ietf.org/html/rfc6750#section-3.1
                // WWW-Authenticate: Bearer realm="example", error="invalid_token", error_description="The access token expired"
                StringBuilder builder = new StringBuilder(Options.Challenge);
                if (Options.Challenge.IndexOf(" ", StringComparison.Ordinal) > 0)
                {
                    // Only add a comma after the first param, if any
                    builder.Append(',');
                }
                if (!string.IsNullOrEmpty(eventContext.Error))
                {
                    builder.Append(" error=\"");
                    builder.Append(eventContext.Error);
                    builder.Append("\"");
                }
                if (!string.IsNullOrEmpty(eventContext.ErrorDescription))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_description=\"");
                    builder.Append(eventContext.ErrorDescription);
                    builder.Append('\"');
                }
                if (!string.IsNullOrEmpty(eventContext.ErrorUri))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error) ||
                        !string.IsNullOrEmpty(eventContext.ErrorDescription))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_uri=\"");
                    builder.Append(eventContext.ErrorUri);
                    builder.Append('\"');
                }

                Response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());
            }
        }
        /// <summary>
        /// https://stackoverflow.com/questions/38725038/c-sharp-how-to-verify-signature-on-jwt-token
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static byte[] GetBytes(string value)
        {
            return Encoding.UTF8.GetBytes(value);
        }

        /// <summary>
        /// from JWT spec
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        private static string Base64UrlEncode(byte[] input)
        {
            string output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }
    }
}
