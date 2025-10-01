
namespace JWTAuth.Dtos
{
    public class AuthResponseDto
    {
        public AuthResponseDto(string accessToken, string refreshToken, DateTime expires)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            Expires = expires;
        }

        public string AccessToken { get; }
        public string RefreshToken { get; }
        public DateTime Expires { get; }
    }

}
