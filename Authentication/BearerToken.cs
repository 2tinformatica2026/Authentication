using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace [Application Name].UserAuthentication
{
    public class BearerToken
    {
        public static string ClaimName { get { return JwtBearerDefaults.AuthenticationScheme;} } 
        public static List<Claim> Claims(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            string bearer = token.Split(ClaimName)[1].Trim().Replace("\"", "");
            var jwt = (JwtSecurityToken)handler.ReadToken(bearer);
            var cls = jwt.Claims.ToList();
            cls.Add(new Claim(ClaimName, bearer));
            return cls;
        }
        public static bool TokenExist(ClaimsPrincipal User)
        {
            return (User.Claims.Any(X => X.Type == ClaimName));
        }
        public static string Token(ClaimsPrincipal User)
        {
            if (TokenExist(User))
            return ClaimName + " " + User.Claims.First(X=> X.Type == ClaimName).Value;
            return string.Empty;
        }
        public static bool Expired(ClaimsPrincipal User)
        {
            if (User.Claims.Any(X=>X.Type == "exp"))
            {
                var exp = User.FindFirstValue("exp");
                if (exp != null)
                {
                    return (DateTimeOffset.FromUnixTimeSeconds(long.Parse(exp)).UtcDateTime <= DateTime.Now.ToUniversalTime());
                } else return true;
            } else return true;
        }
    }
}
