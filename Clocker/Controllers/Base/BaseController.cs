using Microsoft.AspNetCore.Mvc;

namespace Clocker.Controllers.Base
{
    [Route("[controller]")]
    [ApiController]
    [CustomAuthorize]
    public class BaseController : ControllerBase
    {
    }
}
