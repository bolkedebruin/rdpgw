using System.Text;

namespace Rdpgw.Protocol;

public static class Utf16
{
    public static string DecodeUtf16(byte[] b)
    {
        if (b.Length % 2 != 0)
        {
            throw new ArgumentException("must have even length byte slice", nameof(b));
        }
        var s = Encoding.Unicode.GetString(b);
        return s.EndsWith('\0') ? s[..^1] : s;
    }

    public static byte[] EncodeUtf16(string s) => Encoding.Unicode.GetBytes(s);
}
