using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
namespace [Application Name].UserAuthentication
{
    public class Authentication
    {
        private const string CookieTypeName = "UserSession";
        public static string userid { get { return "userid";} }
        public static string hostip { get { return "hostip"; } } 
        //LoginPath: redirect if action is colored with [Authorize] and user not authenticated
        //LogoutPath: redirect url on SignOutAsync invocation
        //AccessDeniedPath: redirect if action is colored with [AuthorizePolicy] and user does not have the necessary policy
        public static void AddAuthentication(WebApplicationBuilder builder,
                                             int ExpireMinutesUserSessionTimeSpan,
                                             string? LoginPath = null,
                                             string? LogoutPath = null,
                                             string? AccessDeniedPath = null,
                                             bool CheckBearerTokenExpiration = true)
        {
            builder.Services.AddAuthentication(CookieTypeName).AddCookie(CookieTypeName, options =>
            {
                options.Cookie.Name = CookieTypeName;
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(ExpireMinutesUserSessionTimeSpan);
                options.Cookie.MaxAge = options.ExpireTimeSpan;
                options.SlidingExpiration = true; //the expiration date of the cookie is updated automatically
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // https only
                options.Cookie.IsEssential = true;
                if (!String.IsNullOrEmpty(LoginPath)) options.LoginPath = new PathString(LoginPath);
                if (!String.IsNullOrEmpty(LogoutPath)) options.LogoutPath = new PathString(LogoutPath);
                if (!String.IsNullOrEmpty(AccessDeniedPath)) options.AccessDeniedPath = new PathString(AccessDeniedPath);
                if (CheckBearerTokenExpiration)
                {
                    //If the BearerToken exists, check whether it is still valid
                    var onTokenValidated = options.Events.OnValidatePrincipal;
                    options.Events.OnValidatePrincipal = async context =>
                    {
                        if (context.Principal != null)
                        {
                            string token = BearerToken.Token(context.Principal);
                            if (token != string.Empty)
                            {
                                await onTokenValidated(context);
                                if (BearerToken.Expired(token))
                                {
                                    SignOut(context.HttpContext);
                                }
                            }
                        }
                    };
                }
            });
        }
        public static void SignIn(string Bearer, HttpContext context, bool rememberme)
        {
            SignIn(BearerToken.Claims(Bearer), context, rememberme);
        }
        public static void SignIn(List<Claim> claims, HttpContext context, bool rememberme, int UserId)
        {
            claims.Add(new Claim(userid, UserId.ToString()));
            if (context.Connection.RemoteIpAddress!=null) claims.Add(new Claim(hostip, context.Connection.RemoteIpAddress.ToString()));
            SignIn(claims, context, rememberme);
        }
        public static async void SignIn(List<Claim> claims, HttpContext context, bool rememberme)
        {
            var identity = new ClaimsIdentity(claims, CookieTypeName);
            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);
            AuthenticationProperties aut = new AuthenticationProperties();
            aut.IsPersistent = rememberme;
            await context.SignInAsync(CookieTypeName, claimsPrincipal, aut);
        }
        public static async void SignOut(HttpContext context)
        {
            await context.SignOutAsync(CookieTypeName);
        }
        public static bool IsAuthenticated(ClaimsPrincipal User)
        {
            if (User?.Identity != null)
            {
                return User.Identity.IsAuthenticated;
            }
            else return false;
        }
        public static int? UserId(ClaimsPrincipal User)
        {
            if (User.Identity != null)
            {
                var result = User.Claims.FirstOrDefault(C => C.Type == userid);
                if (result != null) { return Convert.ToInt32(result.Value); } else { return null; }
            }
            else return null;
        }
        public static string? HostIp(ClaimsPrincipal User)
        {
            if (User.Identity != null)
            {
                var result = User.Claims.FirstOrDefault(C => C.Type == hostip);
                return result != null ? result.Value : null;
            }
            else return null;
        }
    }
}
