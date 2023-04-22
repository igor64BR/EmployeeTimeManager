using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Clocker.Controllers.Base
{
    [Route("[controller]")]
    [ApiController]
    [Authorize]
    public class BaseController : ControllerBase
    {
        protected Guid? CurrentUserId => GetCurrentUserId(User);

        private static Guid? GetCurrentUserId(ClaimsPrincipal user)
        {
            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            return userId == null
                ? null
                : Guid.Parse(userId);
        }
    }
}
