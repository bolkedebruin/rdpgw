namespace Rdpgw.Security;

/// <summary>
/// Holds process-wide security settings consumed by token generation and gateway authorization helpers.
/// </summary>
/// <remarks>Program.cs initializes these values from the validated application configuration during startup.</remarks>
public static class SecurityOptions
{
    /// <summary>Symmetric key used to sign Protected Application Access (PAA) gateway tokens.</summary>
    public static byte[] SigningKey { get; set; } = [];
    /// <summary>Reserved symmetric encryption key for PAA token compatibility.</summary>
    public static byte[] EncryptionKey { get; set; } = [];
    /// <summary>Optional symmetric key used to sign encrypted user tokens.</summary>
    public static byte[] UserSigningKey { get; set; } = [];
    /// <summary>Symmetric key used to encrypt user tokens returned to RDP files.</summary>
    public static byte[] UserEncryptionKey { get; set; } = [];
    /// <summary>Symmetric key used to validate signed host-selection query tokens.</summary>
    public static byte[] QuerySigningKey { get; set; } = [];
    /// <summary>Gets or sets whether PAA token client IP claims must match the current request identity.</summary>
    public static bool VerifyClientIP { get; set; } = true;
    /// <summary>Gets or sets the configured host-selection mode.</summary>
    public static string HostSelection { get; set; } = string.Empty;
    /// <summary>Gets or sets the callback that returns hosts visible to a username.</summary>
    public static Func<string, IReadOnlyList<string>> HostsProvider { get; set; } = _ => [];
    /// <summary>Gets or sets the lifetime assigned to newly generated tokens.</summary>
    public static TimeSpan ExpiryTime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Context item key holding the target server authorized by a validated PAA token.</summary>
    public const string TunnelTargetServerKey = "Rdpgw.Security.TargetServer";
    /// <summary>Context item key holding the client IP bound into a validated PAA token.</summary>
    public const string TunnelRemoteAddrKey = "Rdpgw.Security.RemoteAddr";
}
