using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using JWTAuth.Dtos;
using JWTAuth.Models;
using JWTAuth; // ApplicationDbContext

[ApiController]
[Route("api/admin")]
[Authorize(Policy = "RequireAdministratorRole")] // veya [Authorize(Roles = "Admin")]
public class AdminController : ControllerBase
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ProjectDBContext _db;

    public AdminController(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager, ProjectDBContext db)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _db = db;
    }

    
    [HttpPost("roles")]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.RoleName)) return BadRequest("RoleName is required");
        if (await _roleManager.RoleExistsAsync(dto.RoleName)) return Conflict("Role already exists");

        var res = await _roleManager.CreateAsync(new IdentityRole(dto.RoleName));
        return res.Succeeded ? Ok() : BadRequest(res.Errors);
    }

    [HttpDelete("roles/{roleName}")]
    public async Task<IActionResult> DeleteRole(string roleName)
    {
        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null) return NotFound();
        var res = await _roleManager.DeleteAsync(role);
        return res.Succeeded ? Ok() : BadRequest(res.Errors);
    }

    // list roles
    [HttpGet("roles")]
    public async Task<IActionResult> ListRoles()
    {
        var roles = await _roleManager.Roles.ToListAsync();
        var list = new List<RoleDto>();
        foreach (var r in roles)
        {
            var claims = await _roleManager.GetClaimsAsync(r);
            var perms = claims.Where(c => c.Type == "permission").Select(c => c.Value).ToList();
            list.Add(new RoleDto { Name = r.Name!, Permissions = perms });
        }
        return Ok(list);
    }

    // 4) add permission to role
    [HttpPost("roles/{roleName}/permissions")]
    public async Task<IActionResult> AddPermissionToRole(string roleName, [FromBody] AddPermissionDto dto)
    {
        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null) return NotFound();

        var existing = await _roleManager.GetClaimsAsync(role);
        if (existing.Any(c => c.Type == "permission" && c.Value == dto.Permission))
            return Conflict("Permission already exists on role");

        var res = await _roleManager.AddClaimAsync(role, new Claim("permission", dto.Permission));
        return res.Succeeded ? Ok() : BadRequest(res.Errors);
    }

    // 5) remove permission from role
    [HttpDelete("roles/{roleName}/permissions/{permission}")]
    public async Task<IActionResult> RemovePermissionFromRole(string roleName, string permission)
    {
        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null) return NotFound();

        var claims = await _roleManager.GetClaimsAsync(role);
        var claim = claims.FirstOrDefault(c => c.Type == "permission" && c.Value == permission);
        if (claim == null) return NotFound("Permission not found on role");

        var res = await _roleManager.RemoveClaimAsync(role, claim);
        return res.Succeeded ? Ok() : BadRequest(res.Errors);
    }

    // 6) Kullanıcıya rol ata
    [HttpPost("users/{userId}/roles")]
    public async Task<IActionResult> AddRoleToUser(string userId, [FromBody] AssignRoleDto dto)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound();

        if (!await _roleManager.RoleExistsAsync(dto.Role)) return BadRequest("Role does not exist");

        var res = await _userManager.AddToRoleAsync(user, dto.Role);
        return res.Succeeded ? Ok() : BadRequest(res.Errors);
    }

    // 7) Kullanıcıdan rol çıkar
    [HttpDelete("users/{userId}/roles/{roleName}")]
    public async Task<IActionResult> RemoveRoleFromUser(string userId, string roleName)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound();

        var res = await _userManager.RemoveFromRoleAsync(user, roleName);
        return res.Succeeded ? Ok() : BadRequest(res.Errors);
    }

    // 8) Kullanıcıların listesi (paging)
    [HttpGet("users")]
    public async Task<IActionResult> ListUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = 20;

        var total = await _userManager.Users.CountAsync();
        var users = await _userManager.Users
            .OrderBy(u => u.UserName)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var items = new List<UserDto>();
        foreach (var u in users)
        {
            var roles = await _userManager.GetRolesAsync(u);
            items.Add(new UserDto { Id = u.Id, Email = u.Email ?? "", FullName = u.FullName ?? "", Roles = roles.ToList() });
        }

        return Ok(new { total, page, pageSize, items });
    }

    // 9) Kullanıcının rollerini getir
    [HttpGet("users/{userId}/roles")]
    public async Task<IActionResult> GetUserRoles(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound();

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(roles);
    }

    // 10) Kullanıcının refresh token'larını iptal et (revoke all)
    [HttpPost("users/{userId}/revoke-refresh")]
    public async Task<IActionResult> RevokeUserRefreshTokens(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound();

        var tokens = await _db.RefreshTokens
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .ToListAsync();

        if (!tokens.Any()) return Ok("No active refresh tokens");

        foreach (var t in tokens)
        {
            t.IsRevoked = true;
            t.RevokedAt = DateTime.UtcNow;
            t.RevokedBy = User?.FindFirst(ClaimTypes.NameIdentifier)?.Value; // optional
        }

        await _db.SaveChangesAsync();
        return Ok("Refresh tokens revoked");
    }
}

