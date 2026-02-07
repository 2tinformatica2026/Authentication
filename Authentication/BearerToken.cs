using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
namespace [Application Name].UserAuthentication
{
    public class BearerToken
    {
        public static string ClaimName { get { return JwtBearerDefaults.AuthenticationScheme;} }
        public static string ClaimValue(JwtSecurityToken token, string ClaimType)
        {
            if (token.Claims.Any(x => x.Type == ClaimType))
            {
               return token.Claims.First(x=>x.Type == ClaimType).Value;
            } else return string.Empty;
        }
        public static List<Claim> Claims(JwtSecurityToken token, bool includeToken = true)
        {
            var result = token.Claims.ToList();
            if (includeToken) result.Add(new Claim(ClaimName, ClaimName + " " + token.RawData));
            return result;
        }
        public static List<Claim> Claims(string token, bool includeToken = true)
        {
            return Claims(Token(token),includeToken);
        }
        public static bool TokenExist(ClaimsPrincipal User)
        {
            return (User.Claims.Any(X => X.Type == ClaimName));
        }
        public static string Token(List<Claim> Claims, 
                                   string Issuer, 
                                   string Audience, 
                                   int? ExpiresMinutes,
                                   string _32Keybyte)
        {
            var keyBytes = Encoding.UTF8.GetBytes(_32Keybyte);
            var tokenHandler = new JwtSecurityTokenHandler();
            ClaimsIdentity claims = new ClaimsIdentity();
            foreach (var claim in Claims) { claims.AddClaim(claim); }
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
            return User.Claims.First(X=> X.Type == ClaimName).Value;
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
