using Microsoft.AspNetCore.Identity;

namespace JWTAuth.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; }
        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }
}
