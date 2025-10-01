using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using JWTAuth.Authorization;
    using JWTAuth.Models;

    [ApiController]
    [Route("api/users")]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuthorizationService _authService;

        public UsersController(UserManager<ApplicationUser> userManager, IAuthorizationService authService)
        {
            _userManager = userManager;
            _authService = authService;
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> EditUser(string id, [FromBody] EditUserDto dto)
        {
            var targetUser = await _userManager.FindByIdAsync(id);
            if (targetUser == null) return NotFound();

            // Resource-based authorize: "manage_users" permission or resource owner
            var authResult = await _authService.AuthorizeAsync(User, targetUser, new PermissionRequirement(Permissions.ManageUsers));

            if (!authResult.Succeeded)
                return Forbid();

            // if authorized, update the user
            targetUser.FullName = dto.FullName;
            var res = await _userManager.UpdateAsync(targetUser);
            if (!res.Succeeded) return BadRequest(res.Errors);

            return Ok();
        }
    }

}
