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
    public interface ITokenService
    {
        string GenerateRefreshToken();
        string GenerateAccessToken(ClaimsIdentity claims, string key, string issuer, string audience, int expireMinutes);
        Task<AuthResponseDto> CreateTokenAsync(ApplicationUser user);
    }
}
