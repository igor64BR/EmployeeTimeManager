using Clocker.Controllers.Base;
using Clocker.Controllers.VMs;
using Clocker.Controllers.VMs.Authorization;
using Clocker.Entities.Users;
using Clocker.Globals;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Clocker.Controllers
{
    public class AuthorizationController : BaseController
    {
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthorizationController(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager, IConfiguration configuration)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpGet("{id}")]
        [Authorize(Roles = Roles.Admin)]
        public async Task<IActionResult> GetById(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());

            if (user is null)
                return BadRequest(new BaseOutput("Usuário não encontrado"));

            return Ok(new BaseOutput(new
            {
                user.Id,
                user.Email,
                user.UserName
            }));
        }

        [HttpPost]
        [Authorize(Roles = Roles.Admin)]
        public async Task<IActionResult> Create(FormUserInput input)
        {
            var user = new AppUser()
            {
                Email = input.Email,
                UserName = input.Email,
                Name = input.UserName,
            };

            var result = await _userManager.CreateAsync(user, input.Password);

            return result.Succeeded
                ? Ok(new BaseOutput(result))
                : BadRequest(new BaseOutput(result.Errors.Select(x => x.Description)));
        }

        [HttpPut("{id}")]
        [Authorize(Roles = Roles.Admin)]
        public async Task<IActionResult> Edit(FormUserInput input, Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());

            user.Email = input.Email;
            user.Name = input.UserName;

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
                return BadRequest(new BaseOutput(result.Errors.Select(x => x.Description)));

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            result = await _userManager.ResetPasswordAsync(user, token, input.Password);

            if (!result.Succeeded)
                return BadRequest(new BaseOutput(result.Errors.Select(x => x.Description)));

            return Ok(new BaseOutput(new { user.Id }));
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = Roles.Admin)]
        public async Task<IActionResult> Delete(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());

            if (user is null) return BadRequest(new BaseOutput("Usuário não encontrado"));

            await _userManager.DeleteAsync(user);

            return Ok(new BaseOutput(id));
        }

        [HttpGet]
        [Authorize(Roles = Roles.Admin)]
        public async Task<IActionResult> List()
        {
            var users = await _userManager.Users.ToListAsync();

            return Ok(new BaseOutput(users.Select(x => new
            {
                x.Id,
                x.Name,
                x.Email
            })));
        }

        [HttpGet("CurrentUser")]
        public async Task<IActionResult> GetCurrentUser()
        {
            var user = await _userManager.FindByIdAsync(CurrentUserId!.Value.ToString());

            return Ok(new
            {
                user.Id,
                user.UserName,
                user.Email,
                Roles = await _userManager.GetRolesAsync(user)
            });
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginInput model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
                return BadRequest(new BaseOutput("Email não encontrado"));

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);

            if (!result.Succeeded)
                return BadRequest(new BaseOutput("Senha incorreta"));

            var claims = await _userManager.GetClaimsAsync(user);
            var token = await GenerateTokenAsync(user, claims, _configuration);
            return Ok(new BaseOutput(new
            {
                User = new
                {
                    user.Id,
                },

                Token = new JwtSecurityTokenHandler().WriteToken(token)
            }));
        }

        private async Task<JwtSecurityToken> GenerateTokenAsync(
            AppUser user,
            IList<Claim> userClaims,
            IConfiguration configuration)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
            };

            var identityOptions = configuration.Get<ClaimsIdentityOptions>();

            claims.Add(new Claim(identityOptions.SecurityStampClaimType, user.SecurityStamp));
            claims.AddRange(userClaims);

            var userRoles = await _userManager.GetRolesAsync(user);

            claims.AddRange(userRoles.Select(r => new Claim(ClaimTypes.Role, r)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:SecretKey"].PadRight(32, '\0')));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                claims: claims,
                signingCredentials: credentials,
                expires: DateTime.Now.AddDays(1));

            return token;
        }
    }
}
