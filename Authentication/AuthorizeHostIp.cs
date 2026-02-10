using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
namespace [Project name].UserAuthentication
{
    public class AuthorizeHostIp : Attribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var RemoteIpAddress = context.HttpContext.Connection.RemoteIpAddress;
            var hasClaim = context.HttpContext.User.Claims.Any(c => c.Type == abstractAuthentication.hostip && c.Value == (RemoteIpAddress == null?string.Empty: RemoteIpAddress.ToString()));
            if (!hasClaim)
            {
                context.Result = new ForbidResult();
            }
        }
    }
}
