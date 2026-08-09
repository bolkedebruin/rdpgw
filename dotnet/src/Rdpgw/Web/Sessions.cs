using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Rdpgw.Identity;
using Rdpgw.Logging;

namespace Rdpgw.Web;

public static class Sessions
{
    public const string CookieName = "RDPGWSESSION";
    public const int MaxAge = 120;
    private const string IdentityKey = "RDPGWID";
    private static byte[] _sessionKey = [];
    private static byte[] _encryptionKey = [];

    public static void InitStore(byte[] sessionKey, byte[] encryptionKey, string storeType, int maxLength)
    {
        if (sessionKey.Length < 32) throw new InvalidOperationException("Session key too small");
        if (encryptionKey.Length < 32) throw new InvalidOperationException("Session key too small");
        _sessionKey = sessionKey[..32];
        _encryptionKey = encryptionKey[..32];
        if (storeType == "file") Log.For(typeof(Sessions)).LogWarning("Filesystem session storage is unsupported in the .NET port; cookies are used as session storage");
        else Log.For(typeof(Sessions)).LogInformation("Cookies are used as session storage");
    }

    public static IIdentity? GetSessionIdentity(HttpContext ctx)
    {
        var data = Read(ctx);
        if (!data.TryGetValue(IdentityKey, out var encoded) || string.IsNullOrEmpty(encoded)) return null;
        var id = new User();
        id.Unmarshal(Convert.FromBase64String(encoded));
        return id;
    }

    public static void SaveSessionIdentity(HttpContext ctx, IIdentity id)
    {
        var data = Read(ctx);
        data[IdentityKey] = Convert.ToBase64String(id.Marshal());
        Write(ctx, data, TimeSpan.FromSeconds(MaxAge));
    }

    internal static void SetValue(HttpContext ctx, string key, string value, TimeSpan maxAge)
    {
        var data = Read(ctx);
        data[key] = value;
        Write(ctx, data, maxAge);
    }

    internal static bool TryGetValue(HttpContext ctx, string key, out string value) => Read(ctx).TryGetValue(key, out value!);

    private static Dictionary<string, string> Read(HttpContext ctx)
    {
        if (_sessionKey.Length == 0 || _encryptionKey.Length == 0) return [];
        var cookie = ctx.Request.Cookies[CookieName];
        if (string.IsNullOrEmpty(cookie)) return [];
        try
        {
            var raw = Base64UrlDecode(cookie);
            if (raw.Length < 12 + 16 + 32) return [];
            var nonce = raw.AsSpan(0, 12).ToArray();
            var tag = raw.AsSpan(raw.Length - 48, 16).ToArray();
            var sig = raw.AsSpan(raw.Length - 32, 32).ToArray();
            var cipher = raw.AsSpan(12, raw.Length - 60).ToArray();
            var signed = raw.AsSpan(0, raw.Length - 32).ToArray();
            var expected = HMACSHA256.HashData(_sessionKey, signed);
            if (!CryptographicOperations.FixedTimeEquals(sig, expected)) return [];
            var plain = new byte[cipher.Length];
            using var aes = new AesGcm(_encryptionKey, 16);
            aes.Decrypt(nonce, cipher, tag, plain);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(plain) ?? [];
        }
        catch { return []; }
    }

    private static void Write(HttpContext ctx, Dictionary<string, string> data, TimeSpan maxAge)
    {
        var plain = JsonSerializer.SerializeToUtf8Bytes(data);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(_encryptionKey, 16)) aes.Encrypt(nonce, plain, cipher, tag);
        var signed = nonce.Concat(cipher).Concat(tag).ToArray();
        var sig = HMACSHA256.HashData(_sessionKey, signed);
        ctx.Response.Cookies.Append(CookieName, Base64UrlEncode(signed.Concat(sig).ToArray()), new CookieOptions
        {
            HttpOnly = true,
            Secure = ctx.Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            MaxAge = maxAge,
            Path = "/"
        });
    }

    private static string Base64UrlEncode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Base64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        return Convert.FromBase64String(s);
    }
}
