namespace JWTAuth.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string TokenHash { get; set; } // SHA256 hash
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; }
        public bool Revoked { get; set; }
        public string ReplacedByTokenHash { get; set; }
        public string CreatedByIp { get; set; }
        public string RevokedByIp { get; set; }
        public string UserId { get; set; } // FK
        public ApplicationUser User { get; set; }
    }
}
