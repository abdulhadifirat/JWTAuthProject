using JWTAuth.Dtos;
using JWTAuth.Helpers;
using JWTAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuth.Services
{
    public class JwtTokenService : ITokenService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;
        private readonly byte[] key;
        private readonly TokenHelper _tokenHelper;

        public JwtTokenService(
            IConfiguration config,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            TokenHelper tokenHelper)
        {
            _config = config;
            _userManager = userManager;
            _roleManager = roleManager;
            _tokenHelper = tokenHelper;

            key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]);
        }

        public async Task<AuthResponseDto> CreateTokenAsync(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>{
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("fullname", user.FullName ?? "")
            };

            foreach (var r in roles)
                claims.Add(new Claim(ClaimTypes.Role, r));

            foreach (var role in roles)
            {
                var identityRole = await _roleManager.FindByNameAsync(role);
                var roleClaims = await _roleManager.GetClaimsAsync(identityRole);
                claims.AddRange(roleClaims);
            }

            var creds = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddMinutes(double.Parse(_config["Jwt:AccessTokenMinutes"]));

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            var accessToken = new JwtSecurityTokenHandler().WriteToken(token);

            var refreshToken = _tokenHelper.GenerateRandomToken();
            var refreshHash = _tokenHelper.Hash(refreshToken);

            user.RefreshTokens.Add(new RefreshToken
            {
                TokenHash = refreshHash,
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow
            });

            await _userManager.UpdateAsync(user);

            return new AuthResponseDto(accessToken, refreshToken, expires);
        }

        public string GenerateAccessToken(ClaimsIdentity claims, string key, string issuer, string audience, int expireMinutes)
        {
            var creds = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddMinutes(expireMinutes);
            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims.Claims,
                expires: expires,
                signingCredentials: creds
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}
