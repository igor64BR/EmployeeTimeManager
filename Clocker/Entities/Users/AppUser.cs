using Microsoft.AspNetCore.Identity;

namespace Clocker.Entities.Users
{
    public class AppUser : IdentityUser<Guid>
    {
        public string Name { get; internal set; }
    }
}
