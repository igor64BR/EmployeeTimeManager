using Clocker;
using Clocker.Entities.Users;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var configuration = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .Build();

builder.Services.AddControllers();

builder.Services.AddIdentity<AppUser, Role>()
    .AddEntityFrameworkStores<ClockerDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(opt =>
{
    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(config =>
    {
        config.TokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"].PadRight(32, '\0'))),
            ValidateIssuer = false,
            ValidateAudience = false
        };

        config.Events = new JwtBearerEvents
        {
            OnTokenValidated = async (ctx) =>
            {
                var signInManager = ctx.HttpContext.RequestServices
                    .GetRequiredService<SignInManager<AppUser>>();

                var user = await signInManager.ValidateSecurityStampAsync(ctx.Principal);

                if (user == null)
                    ctx.Fail("Invalid Security Stamp");
            }
        };
    });

builder.Services.AddCors(opt => opt.AddPolicy("CorsPolicy", builder =>
{
    builder.AllowAnyHeader()
        .AllowAnyMethod()
        .SetIsOriginAllowed((x) => true)
        .AllowCredentials();
}));

// Sqlite3
builder.Services.AddDbContext<ClockerDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"))
);

builder.Services.Configure<IISServerOptions>(opt => opt.MaxRequestBodySize = int.MaxValue);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddTransient<Seeder>();

var app = builder.Build();

await RunSeederAsync(app);

app.UseCors("CorsPolicy");

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseDeveloperExceptionPage();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

static async Task RunSeederAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var seeder = scope.ServiceProvider.GetRequiredService<Seeder>();
    await seeder.SeedAsync();
};