using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Rdpgw.Config;

/// <summary>
/// Root application configuration bound from appsettings files and RDPGW_ environment variables.
/// </summary>
public sealed class Configuration
{
    /// <summary>Configuration value that disables TLS in Kestrel.</summary>
    public const string TlsDisable = "disable";
    /// <summary>Configuration value reserved for automatic TLS behavior.</summary>
    public const string TlsAuto = "auto";
    /// <summary>Host-selection mode requiring a signed host query token.</summary>
    public const string HostSelectionSigned = "signed";
    /// <summary>Host-selection mode that chooses a configured host at random.</summary>
    public const string HostSelectionRoundRobin = "roundrobin";
    /// <summary>Session-store mode that keeps encrypted session state in cookies.</summary>
    public const string SessionStoreCookie = "cookie";
    /// <summary>Session-store mode name retained for compatibility with the Go implementation.</summary>
    public const string SessionStoreFile = "file";
    /// <summary>Authentication mode for OpenID Connect browser login.</summary>
    public const string AuthenticationOpenId = "openid";
    /// <summary>Authentication mode for gRPC-backed basic/local authentication.</summary>
    public const string AuthenticationBasic = "local";
    /// <summary>Authentication mode for SPNEGO/Kerberos gateway authentication.</summary>
    public const string AuthenticationKerberos = "kerberos";
    /// <summary>Authentication mode for trusted reverse-proxy header authentication.</summary>
    public const string AuthenticationHeader = "header";

    private static readonly string[] KnownDefaultSecrets =
    [
        "thisisasessionkeyreplacethisjetzt",
        "thisisasessionkeyreplacethisjetz",
        "thisisasessionkeyreplacethisnunu!",
        "thisisasessionkeyreplacethisnunu",
        "thisisasessionencryptionkey12345",
    ];

    /// <summary>Gets or sets listener, host-selection, session, and gateway server options.</summary>
    public ServerConfig Server { get; set; } = new();
    /// <summary>Gets or sets OpenID Connect provider options.</summary>
    public OpenIDConfig OpenId { get; set; } = new();
    /// <summary>Gets or sets Kerberos and KDC proxy options.</summary>
    public KerberosConfig Kerberos { get; set; } = new();
    /// <summary>Gets or sets trusted header-authentication options.</summary>
    public HeaderConfig Header { get; set; } = new();
    /// <summary>Gets or sets RDP gateway capability flags advertised to clients.</summary>
    public CapsConfig Caps { get; set; } = new();
    /// <summary>Gets or sets token, session-key, and gateway-federation security options.</summary>
    public SecurityConfig Security { get; set; } = new();
    /// <summary>Gets or sets RDP file rendering and client-side option controls.</summary>
    public ClientConfig Client { get; set; } = new();

    /// <summary>
    /// Binds configuration data, fills in runtime defaults, and validates incompatible settings.
    /// </summary>
    /// <param name="configuration">ASP.NET configuration root.</param>
    /// <returns>A validated configuration instance.</returns>
    public static Configuration Load(IConfiguration configuration)
    {
        var config = configuration.Get<Configuration>() ?? new Configuration();
        ValidateAndFixup(config);
        return config;
    }

    private static void ValidateAndFixup(Configuration c)
    {
        CheckDefaultSecrets(c);
        // Keep legacy deployments running by generating ephemeral keys when fixed 32-byte keys are not configured.
        if (c.Security.PAATokenEncryptionKey.Length != 32) c.Security.PAATokenEncryptionKey = GenerateRandomString(32);
        if (c.Security.PAATokenSigningKey.Length != 32) c.Security.PAATokenSigningKey = GenerateRandomString(32);
        if (c.Security.EnableUserToken && c.Security.UserTokenEncryptionKey.Length != 32) c.Security.UserTokenEncryptionKey = GenerateRandomString(32);
        if (c.Server.SessionKey.Length != 32) c.Server.SessionKey = GenerateRandomString(32);
        if (c.Server.SessionEncryptionKey.Length != 32) c.Server.SessionEncryptionKey = GenerateRandomString(32);
        if (c.Server.HostSelection == HostSelectionSigned && c.Security.QueryTokenSigningKey.Length == 0) throw new OptionsValidationException(nameof(Configuration), typeof(Configuration), ["host selection is set to `signed` but `QueryTokenSigningKey` is not set"]);
        if (c.Server.BasicAuthEnabled() && c.Server.Tls == TlsDisable) throw new OptionsValidationException(nameof(Configuration), typeof(Configuration), ["basicauth=local and tls=disable are mutually exclusive"]);
        if (c.Server.NtlmEnabled() && c.Server.KerberosEnabled()) throw new OptionsValidationException(nameof(Configuration), typeof(Configuration), ["ntlm and kerberos authentication are not stackable"]);
        if (!c.Caps.TokenAuth && c.Server.OpenIDEnabled()) throw new OptionsValidationException(nameof(Configuration), typeof(Configuration), ["openid is configured but tokenauth disabled"]);
        if (c.Server.KerberosEnabled() && string.IsNullOrEmpty(c.Kerberos.Keytab)) throw new OptionsValidationException(nameof(Configuration), typeof(Configuration), ["kerberos is configured but no keytab was specified"]);
        if (c.Server.HeaderEnabled() && string.IsNullOrEmpty(c.Header.UserHeader)) throw new OptionsValidationException(nameof(Configuration), typeof(Configuration), ["header authentication is configured but no user header was specified"]);
        // UriBuilder later expects scheme-relative gateway addresses to start with "//".
        if (!string.IsNullOrEmpty(c.Server.GatewayAddress) && !c.Server.GatewayAddress.Contains("//", StringComparison.Ordinal)) c.Server.GatewayAddress = "//" + c.Server.GatewayAddress;
        if (!string.IsNullOrEmpty(c.Server.PrimaryGateway))
        {
            if (c.Security.GatewaySharedKey.Length < 32) throw new OptionsValidationException(nameof(Configuration), typeof(Configuration), ["`Server:PrimaryGateway` is set but `Security:GatewaySharedKey` is missing or shorter than 32 characters; subservient gateways must share a strong key with the primary"]);
            if (!c.Server.PrimaryGateway.Contains("://", StringComparison.Ordinal)) c.Server.PrimaryGateway = "https://" + c.Server.PrimaryGateway;
        }
        if (c.Security.GatewaySharedKey.Length > 0 && c.Security.GatewaySharedKey.Length < 32) throw new OptionsValidationException(nameof(Configuration), typeof(Configuration), ["`Security:GatewaySharedKey` must be at least 32 characters"]);
    }

    private static void CheckDefaultSecrets(Configuration c)
    {
        (string Name, string Value)[] fields =
        [
            ("Server:SessionKey", c.Server.SessionKey), ("Server:SessionEncryptionKey", c.Server.SessionEncryptionKey),
            ("Security:PAATokenSigningKey", c.Security.PAATokenSigningKey), ("Security:PAATokenEncryptionKey", c.Security.PAATokenEncryptionKey),
            ("Security:UserTokenSigningKey", c.Security.UserTokenSigningKey), ("Security:UserTokenEncryptionKey", c.Security.UserTokenEncryptionKey),
            ("Security:QueryTokenSigningKey", c.Security.QueryTokenSigningKey),
        ];
        foreach (var field in fields.Where(f => !string.IsNullOrEmpty(f.Value)))
        foreach (var known in KnownDefaultSecrets)
            if (field.Value == known) throw new OptionsValidationException(nameof(Configuration), typeof(Configuration), [$"{field.Name} is set to a known placeholder value ({known}); replace it with a unique secret before starting"]);
    }

    private static string GenerateRandomString(int n)
    {
        const string letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-";
        return RandomNumberGenerator.GetString(letters, n);
    }
}

/// <summary>
/// Listener, session, authentication, and destination settings for the gateway server.
/// </summary>
public sealed class ServerConfig
{
    /// <summary>Gets or sets the public gateway address written into generated RDP files.</summary>
    public string GatewayAddress { get; set; } = string.Empty;
    /// <summary>Gets or sets the TCP port Kestrel listens on.</summary>
    public int Port { get; set; }
    /// <summary>Gets or sets the PEM certificate file used for HTTPS.</summary>
    public string CertFile { get; set; } = string.Empty;
    /// <summary>Gets or sets the PEM private-key file used for HTTPS.</summary>
    public string KeyFile { get; set; } = string.Empty;
    /// <summary>Gets or sets legacy configured host addresses imported into the database on first run.</summary>
    public List<string> Hosts { get; set; } = [];
    /// <summary>Gets or sets how destination hosts are selected for generated RDP files.</summary>
    public string HostSelection { get; set; } = string.Empty;
    /// <summary>Gets or sets the SQLite database file path.</summary>
    public string DatabaseFile { get; set; } = string.Empty;
    /// <summary>Gets or sets the HMAC key used to sign encrypted session cookies.</summary>
    public string SessionKey { get; set; } = string.Empty;
    /// <summary>Gets or sets the AES-GCM key used to encrypt session cookies.</summary>
    public string SessionEncryptionKey { get; set; } = string.Empty;
    /// <summary>Gets or sets the requested session storage backend.</summary>
    public string SessionStore { get; set; } = string.Empty;
    /// <summary>Gets or sets the maximum configured session length in seconds.</summary>
    public int MaxSessionLength { get; set; }
    /// <summary>Gets or sets the gateway protocol send buffer size.</summary>
    public int SendBuf { get; set; }
    /// <summary>Gets or sets the gateway protocol receive buffer size.</summary>
    public int ReceiveBuf { get; set; }
    /// <summary>Gets or sets TLS mode for Kestrel.</summary>
    public string Tls { get; set; } = string.Empty;
    /// <summary>Gets or sets enabled authentication mode names.</summary>
    public List<string> Authentication { get; set; } = [];
    /// <summary>Gets or sets the Unix socket path for gRPC basic/NTLM authentication.</summary>
    public string AuthSocket { get; set; } = string.Empty;
    /// <summary>Gets or sets the gRPC authentication timeout in seconds.</summary>
    public int BasicAuthTimeout { get; set; }
    /// <summary>Gets or sets destination ports allowed when host-selection mode permits arbitrary hosts.</summary>
    public List<int> AllowedDestinationPorts { get; set; } = [];
    /// <summary>Gets or sets whether arbitrary-host mode may connect to private or non-routable addresses.</summary>
    public bool AllowPrivateDestinations { get; set; }
    /// <summary>Gets or sets proxy CIDR ranges trusted for X-Forwarded-For processing.</summary>
    public List<string> TrustedProxies { get; set; } = [];
    /// <summary>URL of the primary gateway. When set, this instance runs as a subservient gateway and validates PAA tokens against the primary.</summary>
    public string PrimaryGateway { get; set; } = string.Empty;
    /// <summary>Returns whether OpenID Connect authentication is enabled.</summary>
    /// <returns><see langword="true"/> when openid appears in <see cref="Authentication"/>.</returns>
    public bool OpenIDEnabled() => MatchAuth("openid");
    /// <summary>Returns whether Kerberos/SPNEGO authentication is enabled.</summary>
    /// <returns><see langword="true"/> when kerberos appears in <see cref="Authentication"/>.</returns>
    public bool KerberosEnabled() => MatchAuth("kerberos");
    /// <summary>Returns whether basic/local gRPC authentication is enabled.</summary>
    /// <returns><see langword="true"/> when local or basic appears in <see cref="Authentication"/>.</returns>
    public bool BasicAuthEnabled() => MatchAuth("local") || MatchAuth("basic");
    /// <summary>Returns whether NTLM gRPC authentication is enabled.</summary>
    /// <returns><see langword="true"/> when ntlm appears in <see cref="Authentication"/>.</returns>
    public bool NtlmEnabled() => MatchAuth("ntlm");
    /// <summary>Returns whether trusted-header authentication is enabled.</summary>
    /// <returns><see langword="true"/> when header appears in <see cref="Authentication"/>.</returns>
    public bool HeaderEnabled() => MatchAuth("header");
    private bool MatchAuth(string needle) => Authentication.Any(a => a == needle);
}

/// <summary>
/// Kerberos configuration used by SPNEGO authentication and the KDC proxy endpoint.
/// </summary>
public sealed class KerberosConfig
{
    /// <summary>Gets or sets the keytab path required when Kerberos authentication is enabled.</summary>
    public string Keytab { get; set; } = string.Empty;
    /// <summary>Gets or sets the krb5.conf path used to discover realms and KDCs.</summary>
    public string Krb5Conf { get; set; } = string.Empty;
}

/// <summary>
/// OpenID Connect provider and client settings.
/// </summary>
public sealed class OpenIDConfig
{
    /// <summary>Gets or sets the issuer/provider base URL.</summary>
    public string ProviderUrl { get; set; } = string.Empty;
    /// <summary>Gets or sets the OIDC client identifier.</summary>
    public string ClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the OIDC client secret.</summary>
    public string ClientSecret { get; set; } = string.Empty;
}

/// <summary>
/// Trusted reverse-proxy header authentication settings.
/// </summary>
public sealed class HeaderConfig
{
    /// <summary>Gets or sets the required header that contains the authenticated username.</summary>
    public string UserHeader { get; set; } = string.Empty;
    /// <summary>Gets or sets the optional header that contains a stable user identifier.</summary>
    public string UserIdHeader { get; set; } = string.Empty;
    /// <summary>Gets or sets the optional header that contains the user's email address.</summary>
    public string EmailHeader { get; set; } = string.Empty;
    /// <summary>Gets or sets the optional header that contains the user's display name.</summary>
    public string DisplayNameHeader { get; set; } = string.Empty;
    /// <summary>Gets or sets CIDR ranges allowed to assert identity headers.</summary>
    public List<string> TrustedProxies { get; set; } = [];
}

/// <summary>
/// RDP gateway capability flags advertised to clients.
/// </summary>
public sealed class CapsConfig
{
    /// <summary>Gets or sets whether smart-card authentication is advertised.</summary>
    public bool SmartCardAuth { get; set; }
    /// <summary>Gets or sets whether PAA token authentication is enabled for gateway connections.</summary>
    public bool TokenAuth { get; set; }
    /// <summary>Gets or sets the idle timeout sent to the gateway protocol layer.</summary>
    public int IdleTimeout { get; set; }
    /// <summary>Gets or sets whether all device redirection is enabled.</summary>
    public bool RedirectAll { get; set; }
    /// <summary>Gets or sets whether all device redirection is disabled.</summary>
    public bool DisableRedirect { get; set; }
    /// <summary>Gets or sets whether clipboard redirection is enabled.</summary>
    public bool EnableClipboard { get; set; }
    /// <summary>Gets or sets whether printer redirection is enabled.</summary>
    public bool EnablePrinter { get; set; }
    /// <summary>Gets or sets whether serial/parallel port redirection is enabled.</summary>
    public bool EnablePort { get; set; }
    /// <summary>Gets or sets whether Plug and Play device redirection is enabled.</summary>
    public bool EnablePnp { get; set; }
    /// <summary>Gets or sets whether drive redirection is enabled.</summary>
    public bool EnableDrive { get; set; }
}

/// <summary>
/// Cryptographic and federation settings for sessions, tokens, and gateway-to-gateway validation.
/// </summary>
public sealed class SecurityConfig
{
    /// <summary>Gets or sets the PAA token encryption key retained for compatibility.</summary>
    public string PAATokenEncryptionKey { get; set; } = string.Empty;
    /// <summary>Gets or sets the symmetric key used to sign PAA tokens.</summary>
    public string PAATokenSigningKey { get; set; } = string.Empty;
    /// <summary>Gets or sets the symmetric key used to encrypt user tokens.</summary>
    public string UserTokenEncryptionKey { get; set; } = string.Empty;
    /// <summary>Gets or sets the optional symmetric key used to sign user tokens.</summary>
    public string UserTokenSigningKey { get; set; } = string.Empty;
    /// <summary>Gets or sets the symmetric key used to validate signed host query tokens.</summary>
    public string QueryTokenSigningKey { get; set; } = string.Empty;
    /// <summary>Gets or sets the issuer expected for signed host query tokens.</summary>
    public string QueryTokenIssuer { get; set; } = string.Empty;
    /// <summary>Gets or sets whether gateway tokens are bound to the client IP address.</summary>
    public bool VerifyClientIp { get; set; }
    /// <summary>Gets or sets whether encrypted user tokens can be embedded in generated usernames.</summary>
    public bool EnableUserToken { get; set; }
    /// <summary>Gets or sets the shared bearer key used between primary and subservient gateways.</summary>
    public string GatewaySharedKey { get; set; } = string.Empty;
}

/// <summary>
/// RDP client file rendering and override settings.
/// </summary>
public sealed class ClientConfig
{
    /// <summary>Gets or sets the default RDP template file path.</summary>
    public string Defaults { get; set; } = string.Empty;
    /// <summary>Gets or sets the username template applied to generated RDP files.</summary>
    public string UsernameTemplate { get; set; } = string.Empty;
    /// <summary>Gets or sets whether usernames of the form user@domain are split into username and domain fields.</summary>
    public bool SplitUserDomain { get; set; }
    /// <summary>Gets or sets whether generated RDP files omit the username field.</summary>
    public bool NoUsername { get; set; }
    /// <summary>Gets or sets the certificate path intended for RDP file signing.</summary>
    public string SigningCert { get; set; } = string.Empty;
    /// <summary>Gets or sets the private-key path intended for RDP file signing.</summary>
    public string SigningKey { get; set; } = string.Empty;
    /// <summary>Gets or sets RDP setting keys that authenticated users may override via query string.</summary>
    public List<string> RdpOverridableKeys { get; set; } = [];
}
