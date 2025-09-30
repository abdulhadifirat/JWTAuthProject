using System.Security.Cryptography;
using System.Text;

namespace JWTAuth.Helpers;

public class TokenHelper
{
    private readonly string _secret = "super-secret-key-change-this";

    public string Hash(string refreshToken)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_secret));
        var bytes = Encoding.UTF8.GetBytes(refreshToken);
        var hash = hmac.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }
    
}
