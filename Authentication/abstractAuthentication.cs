using System.Security.Claims;

namespace [Application Name].UserAuthentication
{
    public abstract class abstractAuthentication
    {
        public const string userid = "userid";
        public const string hostip = "hostip";
        public static int? UserId(ClaimsPrincipal User)
        {
            if (User.Identity != null)
            {
                var result = User.Claims.FirstOrDefault(C => (C.Type == userid && C.Value.Trim() != ""));
                if (result != null) { return Convert.ToInt32(result.Value); } else { return null; }
            }
            else return null;
        }
        public static string? HostIp(ClaimsPrincipal User)
        {
            if (User.Identity != null)
            {
                var result = User.Claims.FirstOrDefault(C => (C.Type == hostip && C.Value.Trim() != ""));
                return result != null ? result.Value : null;
            }
            else return null;
        }
        public static bool IsAuthenticated(ClaimsPrincipal User)
        {
            if (User?.Identity != null)
            {
                return User.Identity.IsAuthenticated;
            }
            else return false;
        }
    }
}
