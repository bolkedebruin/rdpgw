namespace Rdpgw.Security;

public static class SecurityOptions
{
    public static byte[] SigningKey { get; set; } = [];
    public static byte[] EncryptionKey { get; set; } = [];
    public static byte[] UserSigningKey { get; set; } = [];
    public static byte[] UserEncryptionKey { get; set; } = [];
    public static byte[] QuerySigningKey { get; set; } = [];
    public static bool VerifyClientIP { get; set; } = true;
    public static string HostSelection { get; set; } = string.Empty;
    public static Func<string, IReadOnlyList<string>> HostsProvider { get; set; } = _ => [];
    public static TimeSpan ExpiryTime { get; set; } = TimeSpan.FromMinutes(5);

    public const string TunnelTargetServerKey = "Rdpgw.Security.TargetServer";
    public const string TunnelRemoteAddrKey = "Rdpgw.Security.RemoteAddr";
}
