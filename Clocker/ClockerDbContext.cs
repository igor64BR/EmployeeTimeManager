using Clocker.Entities;
using Clocker.Entities.Users;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Clocker
{
    public class ClockerDbContext : IdentityDbContext<AppUser, Role, Guid>
    {
        public ClockerDbContext(DbContextOptions options) : base(options) { }

        public DbSet<Ponto> Ponto { get; set; }

        protected override void OnModelCreating(ModelBuilder builder) => base.OnModelCreating(builder);
    }
}
