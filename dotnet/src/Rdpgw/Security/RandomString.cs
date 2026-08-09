using System.Security.Cryptography;

namespace Rdpgw.Security;

/// <summary>
/// Generates cryptographically strong random byte arrays and URL-safe strings for keys, nonces, and identifiers.
/// </summary>
public static class RandomString
{
    private const string Letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-";
    /// <summary>Generates cryptographically strong random bytes.</summary>
    /// <param name="count">Number of bytes to generate.</param>
    /// <returns>A byte array containing <paramref name="count"/> random bytes.</returns>
    public static byte[] GenerateRandomBytes(int count) => RandomNumberGenerator.GetBytes(count);
    /// <summary>Generates a random string using the rdpgw URL-safe alphabet.</summary>
    /// <param name="count">Number of characters to generate.</param>
    /// <returns>A random string containing digits, letters, and hyphens.</returns>
    public static string GenerateRandomString(int count) => RandomNumberGenerator.GetString(Letters, count);
}
