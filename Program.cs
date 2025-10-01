using JWTAuth;
using JWTAuth.Authorization;
using JWTAuth.Helpers;
using JWTAuth.Models;
using JWTAuth.Seed;
using JWTAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;




// Add services to the container.
builder.Services.AddSingleton<TokenHelper>();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddScoped<ITokenService, JwtTokenService>();
// Partial Example:


builder.Services.AddScoped<IAuthorizationHandler, PermissionHandler>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdministratorRole", p => p.RequireRole("Admin"));

    foreach (var perm in Permissions.All)
    {
        options.AddPolicy($"Permission.{perm}", policy =>
        {
            policy.RequireClaim("permission", perm);
            policy.Requirements.Add(new PermissionRequirement(perm));
        });
    }
});

builder.Services.AddDbContext<ProjectDBContext>(options =>
    options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"),
        sqlOptions => sqlOptions.EnableRetryOnFailure())
);



builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options => {
    options.Password.RequiredLength = 8;
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ProjectDBContext>()
.AddDefaultTokenProviders();

// JWT
var jwt = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwt["Key"]);

builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options => {
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwt["Issuer"],
        ValidateAudience = true,
        ValidAudience = jwt["Audience"],
        ValidateLifetime = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuerSigningKey = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };
});



var app = builder.Build();

// Move the seeding code after app is built
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    await RoleSeeder.SeedRolesAndPermissionsAsync(roleManager);
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
