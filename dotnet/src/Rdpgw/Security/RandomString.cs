using System.Security.Cryptography;

namespace Rdpgw.Security;

public static class RandomString
{
    private const string Letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-";
    public static byte[] GenerateRandomBytes(int count) => RandomNumberGenerator.GetBytes(count);
    public static string GenerateRandomString(int count) => RandomNumberGenerator.GetString(Letters, count);
}
