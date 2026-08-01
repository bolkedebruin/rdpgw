using System.Security.Cryptography;
using System.Text;

namespace Rdpgw.Auth.Ntlm;

internal static class NtlmCrypto
{
    public static byte[] NtowfV2(string username, string password, string domain)
    {
        var ntHash = Md4.Hash(Encoding.Unicode.GetBytes(password));
        return HmacMd5(ntHash, Encoding.Unicode.GetBytes(username.ToUpperInvariant() + domain));
    }

    public static byte[] HmacMd5(byte[] key, byte[] data) => HMACMD5.HashData(key, data);
}
