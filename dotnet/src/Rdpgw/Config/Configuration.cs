using Microsoft.Extensions.Options;

namespace Rdpgw.Config;

/// <summary>
/// Execution mode the application runs in.
/// </summary>
public enum ServerMode
{
    /// <summary>Runs as the central orchestrator that gateways register with.</summary>
    Orchestrator,

    /// <summary>Runs as a gateway that registers itself with an orchestrator.</summary>
    Gateway,
}

/// <summary>
/// Listener, session, authentication, and destination settings for the gateway server.
/// </summary>
public sealed class ServerConfig
{
    /// <summary>Gets or sets whether this instance runs as the orchestrator or as a gateway.</summary>
    public ServerMode Mode { get; set; } = ServerMode.Orchestrator;

    /// <summary>Gets or sets the public gateway address written into generated RDP files.</summary>
    public string GatewayAddress { get; set; } = string.Empty;

    /// <summary>Gets or sets the TCP port Kestrel listens on.</summary>
    public int Port { get; set; }

    /// <summary>Gets or sets the PEM certificate file used for HTTPS.</summary>
    public string CertFile { get; set; } = string.Empty;

    /// <summary>Gets or sets the PEM private-key file used for HTTPS.</summary>
    public string KeyFile { get; set; } = string.Empty;

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

    public bool Validate()
    {
#warning add validation logic
        return true;
    }
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
