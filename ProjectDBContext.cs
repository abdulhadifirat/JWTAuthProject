using JWTAuth.Models;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth
{
    public class ProjectDBContext : DbContext
    {
        public ProjectDBContext(DbContextOptions<ProjectDBContext> options)
            : base(options)
        {
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }


        // Define your DbSets here, e.g.:
        // public DbSet<YourEntity> YourEntities { get; set; }
    }
}
