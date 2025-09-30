using JWTAuth.Dtos;
using JWTAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuth.Services
{
    public class JwtTokenService 
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;
        private readonly byte[] key;

        public JwtTokenService(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
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

            foreach (var r in roles) claims.Add(new Claim(ClaimTypes.Role, r));

            // role'lerin claim'lerini de ekle (permission vb.)
            foreach (var role in roles)
            {
                var identityRole = await _roleManager.FindByNameAsync(role);
                var roleClaims = await _roleManager.GetClaimsAsync(identityRole);
                claims.AddRange(roleClaims);
            }

            var creds = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddMinutes(double.Parse(_config["Jwt:AccessTokenMinutes"]));

            var token = new JwtSecurityToken();
            var accessToken = new JwtSecurityTokenHandler().WriteToken(token);

            // Refresh token üret ve hash'ini kaydet
            var refreshToken = GenerateRandomToken();
            var refreshHash = Hash(refreshToken);
            user.RefreshTokens.Add(new RefreshToken { TokenHash = refreshHash, Expires = DateTime.UtcNow.AddDays(7), Created = DateTime.UtcNow /*, CreatedByIp = ip*/});
            await _userManager.UpdateAsync(user);

            return new AuthResponseDto(accessToken, refreshToken, expires);
        }

        private string Hash(string refreshToken)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(refreshToken);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        private string GenerateRandomToken()
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
