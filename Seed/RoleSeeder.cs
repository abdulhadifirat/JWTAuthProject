using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace JWTAuth.Seed
{
    public class RoleSeeder
    {
        public static async Task SeedRolesAndPermissionsAsync(RoleManager<IdentityRole> roleManager)
        {
            var rolePermissions = new Dictionary<string, string[]>
            {
                ["Admin"] = new[] { Permissions.ManageUsers, Permissions.ManageRoles, Permissions.ViewReports, Permissions.CreateReports },
                ["Manager"] = new[] { Permissions.ViewReports, Permissions.CreateReports },
                ["User"] = new[] { Permissions.ViewUsers }
            };

            foreach (var kv in rolePermissions)
            {
                var roleName = kv.Key;
                var perms = kv.Value;

                if (!await roleManager.RoleExistsAsync(roleName))
                    await roleManager.CreateAsync(new IdentityRole(roleName));

                var role = await roleManager.FindByNameAsync(roleName);
                var existingClaims = await roleManager.GetClaimsAsync(role);

                foreach (var perm in perms)
                {
                    if (!existingClaims.Any(c => c.Type == "permission" && c.Value == perm))
                        await roleManager.AddClaimAsync(role, new Claim("permission", perm));
                }
            }
        }
    }
}
