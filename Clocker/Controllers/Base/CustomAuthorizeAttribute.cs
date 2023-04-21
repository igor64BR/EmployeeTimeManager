using System.Web.Mvc;

namespace Clocker.Controllers.Base
{
    public class CustomAuthorizeAttribute : AuthorizeAttribute
    {
        protected override void HandleUnauthorizedRequest(AuthorizationContext filterContext) =>
            filterContext.Result = new HttpUnauthorizedResult();
    }
}