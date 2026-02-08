using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace [Application Name].UserAuthentication
{
    public class Authentication: abstractAuthentication
    {
        private const string CookieTypeName = "UserSession";

        //LoginPath: redirect if action is colored with [Authorize] and user not authenticated
        //LogoutPath: redirect url on SignOutAsync invocation
        //AccessDeniedPath: redirect if action is colored with [AuthorizePolicy] and user does not have the necessary policy
        public static void AddAuthentication(WebApplicationBuilder builder,
                                             int ExpireMinutesUserSessionTimeSpan,
                                             bool SlidingExpiration,
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
                options.SlidingExpiration = SlidingExpiration; //the expiration date of the cookie is updated automatically
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
            claims.Add(new Claim(hostip, context.Connection.RemoteIpAddress==null? "": context.Connection.RemoteIpAddress.ToString()));
            SignIn(claims, context, rememberme);
        }
        private static async void SignIn(List<Claim> claims, HttpContext context, bool rememberme)
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
    }
}
