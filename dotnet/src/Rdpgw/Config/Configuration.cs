using System.Collections;
using System.Security.Cryptography;
using YamlDotNet.Serialization;

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

    public static Configuration Load(string path)
    {
        var config = WithDefaults();
        if (File.Exists(path))
        {
            using var reader = File.OpenText(path);
            var yaml = new DeserializerBuilder().Build().Deserialize<object?>(reader);
            if (yaml is not null)
            {
                ApplyMap(config, FlattenYaml(yaml));
            }
        }
        else
        {
            Console.Error.WriteLine($"Config file {path} not found, using defaults and environment");
        }

        ApplyMap(config, EnvironmentOverrides());
        ValidateAndFixup(config);
        return config;
    }

    public static string ToCamel(string s)
    {
        s = s.Trim();
        var chars = new List<char>(s.Length);
        var capNext = true;
        for (var i = 0; i < s.Length; i++)
        {
            var ch = s[i];
            var isCap = ch is >= 'A' and <= 'Z';
            var isLow = ch is >= 'a' and <= 'z';
            if (capNext && isLow) ch = (char)(ch - 'a' + 'A');
            else if (i == 0 && isCap) ch = (char)(ch - 'A' + 'a');

            if (isCap || isLow)
            {
                chars.Add(ch);
                capNext = false;
            }
            else if (ch is >= '0' and <= '9')
            {
                chars.Add(ch);
                capNext = true;
            }
            else
            {
                capNext = ch is '_' or ' ' or '-' or '.';
                if (ch == '.') chars.Add(ch);
            }
        }
        return new string(chars.ToArray());
    }

    private static Configuration WithDefaults() => new()
    {
        Server = new ServerConfig
        {
            Tls = TlsAuto,
            Port = 443,
            SessionStore = SessionStoreCookie,
            HostSelection = HostSelectionRoundRobin,
            Authentication = [AuthenticationOpenId],
            AuthSocket = "/tmp/rdpgw-auth.sock",
            BasicAuthTimeout = 5,
        },
        Security = new SecurityConfig { VerifyClientIp = true },
        Caps = new CapsConfig { TokenAuth = true },
    };

    private static Dictionary<string, object?> EnvironmentOverrides()
    {
        var result = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            var name = entry.Key?.ToString();
            if (name is null || !name.StartsWith("RDPGW_", StringComparison.OrdinalIgnoreCase)) continue;
            var key = name[6..].ToLowerInvariant().Replace("__", ".");
            key = ToCamel(key);
            var value = entry.Value?.ToString()?.Trim(' ') ?? string.Empty;
            result[key] = value.Contains(' ', StringComparison.Ordinal) ? value.Split(' ', StringSplitOptions.None) : value;
        }
        return result;
    }

    private static Dictionary<string, object?> FlattenYaml(object yaml)
    {
        var result = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        void Walk(string prefix, object? value)
        {
            if (value is IDictionary<object, object?> map)
            {
                foreach (var (k, v) in map)
                {
                    var key = NormalizeYamlKey(k.ToString() ?? string.Empty);
                    Walk(string.IsNullOrEmpty(prefix) ? key : $"{prefix}.{key}", v);
                }
            }
            else
            {
                result[prefix] = value;
            }
        }
        Walk(string.Empty, yaml);
        return result;
    }

    private static string NormalizeYamlKey(string key) => key.Trim().ToLowerInvariant().Replace("_", string.Empty).Replace("-", string.Empty);

    private static void ApplyMap(Configuration c, IReadOnlyDictionary<string, object?> values)
    {
        foreach (var (rawKey, value) in values)
        {
            var key = rawKey.ToLowerInvariant();
            switch (key)
            {
                case "server.gatewayaddress": c.Server.GatewayAddress = AsString(value); break;
                case "server.port": c.Server.Port = AsInt(value); break;
                case "server.certfile": c.Server.CertFile = AsString(value); break;
                case "server.keyfile": c.Server.KeyFile = AsString(value); break;
                case "server.hosts": c.Server.Hosts = AsStringList(value); break;
                case "server.hostselection": c.Server.HostSelection = AsString(value); break;
                case "server.sessionkey": c.Server.SessionKey = AsString(value); break;
                case "server.sessionencryptionkey": c.Server.SessionEncryptionKey = AsString(value); break;
                case "server.sessionstore": c.Server.SessionStore = AsString(value); break;
                case "server.maxsessionlength": c.Server.MaxSessionLength = AsInt(value); break;
                case "server.sendbuf": c.Server.SendBuf = AsInt(value); break;
                case "server.receivebuf": c.Server.ReceiveBuf = AsInt(value); break;
                case "server.tls": c.Server.Tls = AsString(value); break;
                case "server.authentication": c.Server.Authentication = AsStringList(value); break;
                case "server.authsocket": c.Server.AuthSocket = AsString(value); break;
                case "server.basicauthtimeout": c.Server.BasicAuthTimeout = AsInt(value); break;
                case "server.alloweddestinationports": c.Server.AllowedDestinationPorts = AsIntList(value); break;
                case "server.allowprivatedestinations": c.Server.AllowPrivateDestinations = AsBool(value); break;
                case "server.trustedproxies": c.Server.TrustedProxies = AsStringList(value); break;
                case "openid.providerurl": c.OpenId.ProviderUrl = AsString(value); break;
                case "openid.clientid": c.OpenId.ClientId = AsString(value); break;
                case "openid.clientsecret": c.OpenId.ClientSecret = AsString(value); break;
                case "kerberos.keytab": c.Kerberos.Keytab = AsString(value); break;
                case "kerberos.krb5conf": c.Kerberos.Krb5Conf = AsString(value); break;
                case "header.userheader": c.Header.UserHeader = AsString(value); break;
                case "header.useridheader": c.Header.UserIdHeader = AsString(value); break;
                case "header.emailheader": c.Header.EmailHeader = AsString(value); break;
                case "header.displaynameheader": c.Header.DisplayNameHeader = AsString(value); break;
                case "header.trustedproxies": c.Header.TrustedProxies = AsStringList(value); break;
                case "caps.smartcardauth": c.Caps.SmartCardAuth = AsBool(value); break;
                case "caps.tokenauth": c.Caps.TokenAuth = AsBool(value); break;
                case "caps.idletimeout": c.Caps.IdleTimeout = AsInt(value); break;
                case "caps.redirectall": c.Caps.RedirectAll = AsBool(value); break;
                case "caps.disableredirect": c.Caps.DisableRedirect = AsBool(value); break;
                case "caps.enableclipboard": c.Caps.EnableClipboard = AsBool(value); break;
                case "caps.enableprinter": c.Caps.EnablePrinter = AsBool(value); break;
                case "caps.enableport": c.Caps.EnablePort = AsBool(value); break;
                case "caps.enablepnp": c.Caps.EnablePnp = AsBool(value); break;
                case "caps.enabledrive": c.Caps.EnableDrive = AsBool(value); break;
                case "security.paatokenencryptionkey": c.Security.PAATokenEncryptionKey = AsString(value); break;
                case "security.paatokensigningkey": c.Security.PAATokenSigningKey = AsString(value); break;
                case "security.usertokenencryptionkey": c.Security.UserTokenEncryptionKey = AsString(value); break;
                case "security.usertokensigningkey": c.Security.UserTokenSigningKey = AsString(value); break;
                case "security.querytokensigningkey": c.Security.QueryTokenSigningKey = AsString(value); break;
                case "security.querytokenissuer": c.Security.QueryTokenIssuer = AsString(value); break;
                case "security.verifyclientip": c.Security.VerifyClientIp = AsBool(value); break;
                case "security.enableusertoken": c.Security.EnableUserToken = AsBool(value); break;
                case "client.defaults": c.Client.Defaults = AsString(value); break;
                case "client.usernametemplate": c.Client.UsernameTemplate = AsString(value); break;
                case "client.splituserdomain": c.Client.SplitUserDomain = AsBool(value); break;
                case "client.nousername": c.Client.NoUsername = AsBool(value); break;
                case "client.signingcert": c.Client.SigningCert = AsString(value); break;
                case "client.signingkey": c.Client.SigningKey = AsString(value); break;
                case "client.rdpoverridablekeys": c.Client.RdpOverridableKeys = AsStringList(value); break;
            }
        }
    }

    private static void ValidateAndFixup(Configuration c)
    {
        CheckDefaultSecrets(c);
        if (c.Security.PAATokenEncryptionKey.Length != 32) c.Security.PAATokenEncryptionKey = GenerateRandomString(32);
        if (c.Security.PAATokenSigningKey.Length != 32) c.Security.PAATokenSigningKey = GenerateRandomString(32);
        if (c.Security.EnableUserToken && c.Security.UserTokenEncryptionKey.Length != 32) c.Security.UserTokenEncryptionKey = GenerateRandomString(32);
        if (c.Server.SessionKey.Length != 32) c.Server.SessionKey = GenerateRandomString(32);
        if (c.Server.SessionEncryptionKey.Length != 32) c.Server.SessionEncryptionKey = GenerateRandomString(32);
        if (c.Server.HostSelection == HostSelectionSigned && c.Security.QueryTokenSigningKey.Length == 0) throw new InvalidOperationException("host selection is set to `signed` but `querytokensigningkey` is not set");
        if (c.Server.BasicAuthEnabled() && c.Server.Tls == TlsDisable) throw new InvalidOperationException("basicauth=local and tls=disable are mutually exclusive");
        if (c.Server.NtlmEnabled() && c.Server.KerberosEnabled()) throw new InvalidOperationException("ntlm and kerberos authentication are not stackable");
        if (!c.Caps.TokenAuth && c.Server.OpenIDEnabled()) throw new InvalidOperationException("openid is configured but tokenauth disabled");
        if (c.Server.KerberosEnabled() && string.IsNullOrEmpty(c.Kerberos.Keytab)) throw new InvalidOperationException("kerberos is configured but no keytab was specified");
        if (c.Server.HeaderEnabled() && string.IsNullOrEmpty(c.Header.UserHeader)) throw new InvalidOperationException("header authentication is configured but no user header was specified");
        if (!string.IsNullOrEmpty(c.Server.GatewayAddress) && !c.Server.GatewayAddress.Contains("//", StringComparison.Ordinal)) c.Server.GatewayAddress = "//" + c.Server.GatewayAddress;
    }

    private static void CheckDefaultSecrets(Configuration c)
    {
        (string Name, string Value)[] fields =
        [
            ("server.sessionkey", c.Server.SessionKey), ("server.sessionencryptionkey", c.Server.SessionEncryptionKey),
            ("security.paatokensigningkey", c.Security.PAATokenSigningKey), ("security.paatokenencryptionkey", c.Security.PAATokenEncryptionKey),
            ("security.usertokensigningkey", c.Security.UserTokenSigningKey), ("security.usertokenencryptionkey", c.Security.UserTokenEncryptionKey),
            ("security.querytokensigningkey", c.Security.QueryTokenSigningKey),
        ];
        foreach (var field in fields.Where(f => !string.IsNullOrEmpty(f.Value)))
        foreach (var known in KnownDefaultSecrets)
            if (field.Value == known) throw new InvalidOperationException($"{field.Name} is set to a known placeholder value ({known}); replace it with a unique secret before starting");
    }

    private static string GenerateRandomString(int n)
    {
        const string letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-";
        return RandomNumberGenerator.GetString(letters, n);
    }

    private static string AsString(object? value) => value?.ToString() ?? string.Empty;
    private static int AsInt(object? value) => value is int i ? i : int.TryParse(AsString(value), out var n) ? n : 0;
    private static bool AsBool(object? value) => value is bool b ? b : AsString(value).Equals("true", StringComparison.OrdinalIgnoreCase) || AsString(value) == "1";
    private static List<string> AsStringList(object? value) => value switch
    {
        null => [],
        IEnumerable<string> e => e.ToList(),
        IEnumerable<object> e => e.Select(AsString).ToList(),
        string s when s.Contains(' ') => s.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList(),
        string s when s.Length > 0 => [s],
        _ => [AsString(value)]
    };
    private static List<int> AsIntList(object? value) => AsStringList(value).Select(v => int.TryParse(v, out var i) ? i : 0).ToList();
}

public sealed class ServerConfig
{
    public string GatewayAddress { get; set; } = string.Empty;
    public int Port { get; set; }
    public string CertFile { get; set; } = string.Empty;
    public string KeyFile { get; set; } = string.Empty;
    public List<string> Hosts { get; set; } = [];
    public string HostSelection { get; set; } = string.Empty;
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
public sealed class SecurityConfig { public string PAATokenEncryptionKey { get; set; } = string.Empty; public string PAATokenSigningKey { get; set; } = string.Empty; public string UserTokenEncryptionKey { get; set; } = string.Empty; public string UserTokenSigningKey { get; set; } = string.Empty; public string QueryTokenSigningKey { get; set; } = string.Empty; public string QueryTokenIssuer { get; set; } = string.Empty; public bool VerifyClientIp { get; set; } public bool EnableUserToken { get; set; } }
public sealed class ClientConfig { public string Defaults { get; set; } = string.Empty; public string UsernameTemplate { get; set; } = string.Empty; public bool SplitUserDomain { get; set; } public bool NoUsername { get; set; } public string SigningCert { get; set; } = string.Empty; public string SigningKey { get; set; } = string.Empty; public List<string> RdpOverridableKeys { get; set; } = []; }
