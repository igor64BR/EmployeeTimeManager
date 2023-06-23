using Microsoft.AspNetCore.Identity;

namespace Clocker.Entities.Users
{
    public class AppUser : IdentityUser<Guid>
    {
        public AppUser()
        {
            Name = string.Empty;
            Address = string.Empty;
        }

        public string Name { get; internal set; }
        public string Address { get; set; }
    }
}
