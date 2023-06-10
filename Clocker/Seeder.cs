using Clocker.Entities.Users;
using Clocker.Globals;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Clocker
{
    public class Seeder
    {
        private readonly ClockerDbContext _context;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<Role> _roleManager;

        public Seeder(
            ClockerDbContext context,
            UserManager<AppUser> userManager,
            RoleManager<Role> roleManager)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task SeedAsync()
        {
            if ((await _context.Database.GetPendingMigrationsAsync()).Any())
                await _context.Database.MigrateAsync();

            await SeedRolesAsync();
            await SeedAdminAsync();
        }

        private async Task SeedRolesAsync()
        {
            foreach (var role in Roles.AllRoles)
                if (!await _roleManager.RoleExistsAsync(role))
                    await _roleManager.CreateAsync(new Role { Name = role });
        }

        private async Task SeedAdminAsync()
        {

            const string email = "admin@admin.com";
            const string userName = "Administrador";
            const string password = "Password@123";

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                var result = await _userManager.CreateAsync(new AppUser
                {
                    Id = Guid.NewGuid(),
                    Email = email,
                    UserName = userName,
                    Name = userName,
                }, password);

                if (result != IdentityResult.Success)
                    throw new Exception("Failed to seed admin");

                user = await _userManager.FindByEmailAsync(email);

                await _userManager.SetLockoutEnabledAsync(user, false);
            }

            var role = await _roleManager.FindByNameAsync(Roles.Admin);

            if (role == null)
            {
                var result = await _roleManager.CreateAsync(new Role { Name = Roles.Admin });

                if (result != IdentityResult.Success)
                    throw new InvalidOperationException($"Error while seeding {Roles.Admin}");
            }

            if (!await _userManager.IsInRoleAsync(user, Roles.Admin))
                await _userManager.AddToRoleAsync(user, Roles.Admin);
        }
    }
}
