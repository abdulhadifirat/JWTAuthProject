using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using JWTAuth.Models; // ApplicationUser
using System.Threading.Tasks;

namespace JWTAuth.Authorization
{
    public class PermissionHandler : AuthorizationHandler<PermissionRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {
            // 1) if user has the required permission claim in their JWT
            if (context.User.HasClaim(c => c.Type == "permission" && c.Value == requirement.Permission))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // 2) Resource-based: if context.Resource is ApplicationUser and matches the user id in JWT
            if (context.Resource is ApplicationUser targetUser)
            {
                
                var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                             ?? context.User.FindFirst("uid")?.Value;

                if (!string.IsNullOrEmpty(userId) && targetUser.Id == userId)
                {
                  
                    context.Succeed(requirement);
                }
            }

           
            return Task.CompletedTask;
        }
    }
}
