using Clocker.Entities.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Clocker
{
    public class ClockerDbContext : IdentityDbContext<AppUser, IdentityRole<Guid>, Guid>
    {
        public ClockerDbContext(DbContextOptions options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder) => base.OnModelCreating(builder);
    }
}
