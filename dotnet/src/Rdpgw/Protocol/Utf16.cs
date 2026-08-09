using System.Text;

namespace Rdpgw.Protocol;

/// <summary>Helpers for MS-TSGU UTF-16LE strings used in tunnel and channel packets.</summary>
public static class Utf16
{
    /// <summary>Decodes a UTF-16LE byte sequence and strips one trailing NUL terminator when present.</summary>
    /// <param name="b">Even-length UTF-16LE byte sequence from the wire format.</param>
    /// <returns>The decoded .NET string without a terminal NUL.</returns>
    public static string DecodeUtf16(byte[] b)
    {
        if (b.Length % 2 != 0)
        {
            throw new ArgumentException("must have even length byte slice", nameof(b));
        }
        var s = Encoding.Unicode.GetString(b);
        return s.EndsWith('\0') ? s[..^1] : s;
    }

    /// <summary>Encodes a .NET string as UTF-16LE bytes for RD Gateway wire fields.</summary>
    /// <param name="s">String to encode.</param>
    /// <returns>UTF-16LE encoded bytes.</returns>
    public static byte[] EncodeUtf16(string s) => Encoding.Unicode.GetBytes(s);
}
