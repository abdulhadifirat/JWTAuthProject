
namespace JWTAuth.Dtos
{
    // Dtos/RoleDto.cs
    public class RoleDto
    {
        public string Name { get; set; } = "";
        public List<string> Permissions { get; set; } = new();
    }

}
