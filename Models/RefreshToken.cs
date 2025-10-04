namespace JWTAuth.Models
{
    public class RefreshToken
    {
        public string Id { get; set; }
        public string TokenHash { get; set; } = "";

        public DateTime Expires { get; set; }
        public DateTime Created { get; set; }

        // Revokes
        public bool IsRevoked { get; set; } = false;
        public DateTime? RevokedAt { get; set; }
        public string? RevokedBy { get; set; }
        public string? RevokedByUserId { get; set; }

        // Token rotation
        public string? ReplacedByTokenHash { get; set; }

        // Audit log
        public string? CreatedByIp { get; set; }

        public string UserId { get; set; } 
        public ApplicationUser User { get; set; } = null!;
    }
}
