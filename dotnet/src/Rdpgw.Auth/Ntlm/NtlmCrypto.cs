using System.Security.Cryptography;
using System.Text;

namespace Rdpgw.Auth.Ntlm;

/// <summary>
/// Cryptographic helpers for NTLMv2 response verification.
/// </summary>
internal static class NtlmCrypto
{
    /// <summary>
    /// Computes the NTOWFv2 key for a user credential.
    /// </summary>
    /// <param name="username">User name from the NTLM Authenticate message.</param>
    /// <param name="password">Configured plaintext password for the user.</param>
    /// <param name="domain">Domain name from the NTLM Authenticate message.</param>
    /// <returns>The 16-byte NTOWFv2 key.</returns>
    /// <remarks>
    /// Implements MS-NLMP section 3.3.2: NTOWFv2 is HMAC-MD5 of the uppercase
    /// username and user domain keyed by the MD4 hash of the UTF-16LE password.
    /// </remarks>
    public static byte[] NtowfV2(string username, string password, string domain)
    {
        var ntHash = Md4.Hash(Encoding.Unicode.GetBytes(password));
        return HmacMd5(ntHash, Encoding.Unicode.GetBytes(username.ToUpperInvariant() + domain));
    }

    /// <summary>
    /// Computes an HMAC-MD5 digest.
    /// </summary>
    /// <param name="key">HMAC key bytes.</param>
    /// <param name="data">Message bytes to authenticate.</param>
    /// <returns>The 16-byte HMAC-MD5 digest.</returns>
    public static byte[] HmacMd5(byte[] key, byte[] data) => HMACMD5.HashData(key, data);
}
