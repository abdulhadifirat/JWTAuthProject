
namespace JWTAuth.Dtos
{
    // Dtos/UserDto.cs
    public class UserDto
    {
        public string Id { get; set; } = "";
        public string Email { get; set; } = "";
        public string FullName { get; set; } = "";
        public List<string> Roles { get; set; } = new();
    }

}
