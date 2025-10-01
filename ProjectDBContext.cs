using JWTAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth
{
    public class ProjectDBContext : IdentityDbContext<IdentityUser>
    {
        public ProjectDBContext(DbContextOptions<ProjectDBContext> options)
            : base(options)
        {
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            
            base.OnModelCreating(modelBuilder);

            // rpimary key for RefreshToken
            modelBuilder.Entity<RefreshToken>().HasKey(rt => rt.Id);
        }
    }
}