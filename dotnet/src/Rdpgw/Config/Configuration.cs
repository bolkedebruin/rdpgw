using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Rdpgw.Config;

public sealed class Configuration
{
    public const string TlsDisable = "disable";
    public const string TlsAuto = "auto";
    public const string HostSelectionSigned = "signed";
    public const string HostSelectionRoundRobin = "roundrobin";
    public const string SessionStoreCookie = "cookie";
    public const string SessionStoreFile = "file";
    public const string AuthenticationOpenId = "openid";
    public const string AuthenticationBasic = "local";
    public const string AuthenticationKerberos = "kerberos";
    public const string AuthenticationHeader = "header";

    private static readonly string[] KnownDefaultSecrets =
    [
        "thisisasessionkeyreplacethisjetzt",
        "thisisasessionkeyreplacethisjetz",
        "thisisasessionkeyreplacethisnunu!",
        "thisisasessionkeyreplacethisnunu",
        "thisisasessionencryptionkey12345",
    ];

    public ServerConfig Server { get; set; } = new();
    public OpenIDConfig OpenId { get; set; } = new();
    public KerberosConfig Kerberos { get; set; } = new();
    public HeaderConfig Header { get; set; } = new();
    public CapsConfig Caps { get; set; } = new();
    public SecurityConfig Security { get; set; } = new();
    public ClientConfig Client { get; set; } = new();

    public static Configuration Load(IConfiguration configuration)
    {
        var config = configuration.Get<Configuration>() ?? new Configuration();
        ValidateAndFixup(config);
        return config;
    }

    private static void ValidateAndFixup(Configuration c)
    {
        CheckDefaultSecrets(c);
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

public sealed class ServerConfig
{
    public string GatewayAddress { get; set; } = string.Empty;
    public int Port { get; set; }
    public string CertFile { get; set; } = string.Empty;
    public string KeyFile { get; set; } = string.Empty;
    public List<string> Hosts { get; set; } = [];
    public string HostSelection { get; set; } = string.Empty;
    public string DatabaseFile { get; set; } = string.Empty;
    public string SessionKey { get; set; } = string.Empty;
    public string SessionEncryptionKey { get; set; } = string.Empty;
    public string SessionStore { get; set; } = string.Empty;
    public int MaxSessionLength { get; set; }
    public int SendBuf { get; set; }
    public int ReceiveBuf { get; set; }
    public string Tls { get; set; } = string.Empty;
    public List<string> Authentication { get; set; } = [];
    public string AuthSocket { get; set; } = string.Empty;
    public int BasicAuthTimeout { get; set; }
    public List<int> AllowedDestinationPorts { get; set; } = [];
    public bool AllowPrivateDestinations { get; set; }
    public List<string> TrustedProxies { get; set; } = [];
    /// <summary>URL of the primary gateway. When set, this instance runs as a subservient gateway and validates PAA tokens against the primary.</summary>
    public string PrimaryGateway { get; set; } = string.Empty;
    public bool OpenIDEnabled() => MatchAuth("openid");
    public bool KerberosEnabled() => MatchAuth("kerberos");
    public bool BasicAuthEnabled() => MatchAuth("local") || MatchAuth("basic");
    public bool NtlmEnabled() => MatchAuth("ntlm");
    public bool HeaderEnabled() => MatchAuth("header");
    private bool MatchAuth(string needle) => Authentication.Any(a => a == needle);
}

public sealed class KerberosConfig { public string Keytab { get; set; } = string.Empty; public string Krb5Conf { get; set; } = string.Empty; }
public sealed class OpenIDConfig { public string ProviderUrl { get; set; } = string.Empty; public string ClientId { get; set; } = string.Empty; public string ClientSecret { get; set; } = string.Empty; }
public sealed class HeaderConfig { public string UserHeader { get; set; } = string.Empty; public string UserIdHeader { get; set; } = string.Empty; public string EmailHeader { get; set; } = string.Empty; public string DisplayNameHeader { get; set; } = string.Empty; public List<string> TrustedProxies { get; set; } = []; }
public sealed class CapsConfig { public bool SmartCardAuth { get; set; } public bool TokenAuth { get; set; } public int IdleTimeout { get; set; } public bool RedirectAll { get; set; } public bool DisableRedirect { get; set; } public bool EnableClipboard { get; set; } public bool EnablePrinter { get; set; } public bool EnablePort { get; set; } public bool EnablePnp { get; set; } public bool EnableDrive { get; set; } }
public sealed class SecurityConfig { public string PAATokenEncryptionKey { get; set; } = string.Empty; public string PAATokenSigningKey { get; set; } = string.Empty; public string UserTokenEncryptionKey { get; set; } = string.Empty; public string UserTokenSigningKey { get; set; } = string.Empty; public string QueryTokenSigningKey { get; set; } = string.Empty; public string QueryTokenIssuer { get; set; } = string.Empty; public bool VerifyClientIp { get; set; } public bool EnableUserToken { get; set; } public string GatewaySharedKey { get; set; } = string.Empty; }
public sealed class ClientConfig { public string Defaults { get; set; } = string.Empty; public string UsernameTemplate { get; set; } = string.Empty; public bool SplitUserDomain { get; set; } public bool NoUsername { get; set; } public string SigningCert { get; set; } = string.Empty; public string SigningKey { get; set; } = string.Empty; public List<string> RdpOverridableKeys { get; set; } = []; }
