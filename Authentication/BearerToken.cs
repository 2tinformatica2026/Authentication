using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace [Application Name].UserAuthentication
{
    public class BearerToken: abstractAuthentication
    {
        private const string JwtConfig_Key256 = "JwtConfig:Key256";
        private const string JwtConfig_ExpiresMinutes = "JwtConfig:ExpiresMinutes";
        private const string JwtConfig_Issuer = "JwtConfig:Issuer";
        private const string JwtConfig_Audience = "JwtConfig:Audience";
        /// <summary>
        /// add and configure the Jwt Bearer authentication service
        /// </summary>
        /// <param name="builder"></param>
        public static void AddAuthentication(WebApplicationBuilder builder)
        {
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(jwtOption =>
            {
                string? key = builder.Configuration.GetValue<string>(JwtConfig_Key256);
                var keyBytes = Encoding.ASCII.GetBytes(key != null ? key : "");
                string? Issuer = builder.Configuration.GetValue<string>(JwtConfig_Issuer);
                string? Audience = builder.Configuration.GetValue<string>(JwtConfig_Audience);

                jwtOption.SaveToken = true;
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key != null ? key : ""));
                var algorithm = SecurityAlgorithms.HmacSha256;
                var signingCredentials = new SigningCredentials(securityKey, algorithm);
                jwtOption.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = signingCredentials.Key,
                    ValidateLifetime = true,
                    ValidIssuer = Issuer,
                    ValidAudience = Audience,
                    ValidateIssuer = !string.IsNullOrEmpty(Issuer),
                    ValidateAudience = !string.IsNullOrEmpty(Audience),
                    ClockSkew = TimeSpan.Zero,
                };
            });
        }
        public static string ClaimValue(JwtSecurityToken token, string ClaimType)
        {
            if (token.Claims.Any(x => x.Type == ClaimType))
            {
               return token.Claims.First(x=>x.Type == ClaimType).Value;
            } else return string.Empty;
        }
        public static List<Claim> Claims(JwtSecurityToken token, bool TokenIncluded = true)
        {
            var result = token.Claims.Where(x=>x.Type!= "exp")
                .Where(x => x.Type != "nbf")
                .Where(x => x.Type != "iat")
                .Where(x => x.Type != "iss")
                .Where(x => x.Type != "aud").ToList();
            if (TokenIncluded) result.Add(new Claim(JwtBearerDefaults.AuthenticationScheme, JwtBearerDefaults.AuthenticationScheme + " " + token.RawData));
            return result;
        }
        public static List<Claim> Claims(string token, bool TokenIncluded = true)
        {
            return Claims(Token(token),TokenIncluded);
        }
        public static bool TokenExist(ClaimsPrincipal User)
        {
            return (User.Claims.Any(X => X.Type == JwtBearerDefaults.AuthenticationScheme));
        }
        /// <summary>
        /// generates the token by retrieving its parameters from the appsettings.json configuration file
        /// List<Claim> Claims - claims attributed to the user
        /// int UserId - user identification id
        /// </summary>
        public static string Token(List<Claim> Claims, HttpContext context,int UserId)
        {
            var builder = WebApplication.CreateBuilder();
            var Issuer = builder.Configuration.GetValue<string>(JwtConfig_Issuer);
            var Audience = builder.Configuration.GetValue<string>(JwtConfig_Audience);
            var ExpiresMinutes = builder.Configuration.GetValue<string>(JwtConfig_ExpiresMinutes);
            var _32Keybyte = builder.Configuration.GetValue<string>(JwtConfig_Key256);
            return Token(Claims, 
                         context, 
                         Issuer==null?"":Issuer, 
                         Audience==null?"":Audience, 
                         ExpiresMinutes==null?null:int.Parse(ExpiresMinutes), 
                         _32Keybyte==null?"": _32Keybyte, 
                         UserId);
        }
        /// <summary>
        /// generates a token using the following parameters
        /// List<Claim> Claims - claims attributed to the user
        /// string Issuer, string Audience to validate the token across multiple service platforms
        /// int? ExpiresMinutes - validity in minutes of the token starting from the miment of its generation
        /// string Key256 - 32-character sequence for generating the symmetric security key
        /// int UserId - user identification id
        /// </summary>
        public static string Token(List<Claim> Claims,
                                   HttpContext context,
                                   string Issuer, 
                                   string Audience, 
                                   int? ExpiresMinutes,
                                   string Key256,
                                   int UserId)
        {
            var keyBytes = Encoding.UTF8.GetBytes(Key256);
            var tokenHandler = new JwtSecurityTokenHandler();
            ClaimsIdentity claims = new ClaimsIdentity();
            claims.AddClaims(Claims);
            claims.AddClaim(new Claim(userid, UserId.ToString()));
            claims.AddClaim(new Claim(hostip, context.Connection.RemoteIpAddress == null ? "" : context.Connection.RemoteIpAddress.ToString()));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = Issuer == "" ? null: Issuer,
                Audience = Audience == "" ? null: Audience,
                Subject = claims,
                Expires = ExpiresMinutes == null? null: DateTime.UtcNow.AddMinutes((int)ExpiresMinutes),
                SigningCredentials = new SigningCredentials(
                                     new SymmetricSecurityKey(keyBytes),
                                     SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return JwtBearerDefaults.AuthenticationScheme + " " + tokenHandler.WriteToken(token);
        }
        public static string Token(ClaimsPrincipal User)
        {
            if (TokenExist(User))
            return User.Claims.First(X=> X.Type == JwtBearerDefaults.AuthenticationScheme).Value;
            return string.Empty;
        }
        public static JwtSecurityToken Token(string StringToken)
        {
            StringToken = StringToken.ToString().Split(JwtBearerDefaults.AuthenticationScheme)[1].Trim();
            var handler = new JwtSecurityTokenHandler();
            return (JwtSecurityToken)handler.ReadToken(StringToken);
        }
        public static JwtSecurityToken Token(HttpRequest Request)
        {
            var token = Request.Headers["Authorization"];
            return Token(token.ToString());
        }
        public static bool Expired(string token)
        {
           return Expired(Token(token));
        }
        public static bool Expired(JwtSecurityToken token)
        {
            return (token.ValidTo < DateTime.UtcNow);
        }
    }
}
