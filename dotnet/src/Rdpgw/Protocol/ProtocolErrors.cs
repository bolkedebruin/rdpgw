namespace Rdpgw.Protocol;

/// <summary>MS-TSGU and Windows status codes returned in gateway response packets.</summary>
public static class ProtocolErrors
{
    /// <summary>Operation completed successfully.</summary>
    public const uint ERROR_SUCCESS = 0x00000000;
    /// <summary>Generic Windows access-denied error.</summary>
    public const uint ERROR_ACCESS_DENIED = 0x00000005;
    /// <summary>RD Gateway internal error HRESULT.</summary>
    public const uint E_PROXY_INTERNALERROR = 0x800759D8;
    /// <summary>Resource Authorization Policy denied the target channel.</summary>
    public const uint E_PROXY_RAP_ACCESSDENIED = 0x800759DA;
    /// <summary>Network Access Protection denied the connection.</summary>
    public const uint E_PROXY_NAP_ACCESSDENIED = 0x800759DB;
    /// <summary>Tunnel or channel was already disconnected.</summary>
    public const uint E_PROXY_ALREADYDISCONNECTED = 0x800759DF;
    /// <summary>Quarantine policy denied access.</summary>
    public const uint E_PROXY_QUARANTINE_ACCESSDENIED = 0x800759ED;
    /// <summary>No certificate was available for gateway authentication.</summary>
    public const uint E_PROXY_NOCERTAVAILABLE = 0x800759EE;
    /// <summary>PAA cookie packet was malformed.</summary>
    public const uint E_PROXY_COOKIE_BADPACKET = 0x800759F7;
    /// <summary>PAA cookie authentication denied access.</summary>
    public const uint E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED = 0x800759F8;
    /// <summary>Client requested an unsupported authentication method.</summary>
    public const uint E_PROXY_UNSUPPORTED_AUTHENTICATION_METHOD = 0x800759F9;
    /// <summary>Client and server capability negotiation failed.</summary>
    public const uint E_PROXY_CAPABILITYMISMATCH = 0x800759E9;
    /// <summary>Gateway failed to connect to the target terminal server.</summary>
    public const uint E_PROXY_TS_CONNECTFAILED = 0x000059DD;
    /// <summary>Gateway maximum connection limit was reached.</summary>
    public const uint E_PROXY_MAXCONNECTIONSREACHED = 0x000059E6;
    /// <summary>Windows status code for a graceful disconnect.</summary>
    public const uint ERROR_GRACEFUL_DISCONNECT = 0x000004CA;
    /// <summary>Requested gateway feature is not supported.</summary>
    public const uint E_PROXY_NOTSUPPORTED = 0x000059E8;
    /// <summary>Security package logon was denied.</summary>
    public const uint SEC_E_LOGON_DENIED = 0x8009030C;
    /// <summary>Gateway session timed out.</summary>
    public const uint E_PROXY_SESSIONTIMEOUT = 0x000059F6;
    /// <summary>Reauthentication failed during authentication.</summary>
    public const uint E_PROXY_REAUTH_AUTHN_FAILED = 0x000059FA;
    /// <summary>Reauthentication failed capability validation.</summary>
    public const uint E_PROXY_REAUTH_CAP_FAILED = 0x000059FB;
    /// <summary>Reauthentication failed Resource Authorization Policy validation.</summary>
    public const uint E_PROXY_REAUTH_RAP_FAILED = 0x000059FC;
    /// <summary>Secure device redirection is not supported by the target server.</summary>
    public const uint E_PROXY_SDR_NOT_SUPPORTED_BY_TS = 0x000059FD;
    /// <summary>Reauthentication failed Network Access Protection validation.</summary>
    public const uint E_PROXY_REAUTH_NAP_FAILED = 0x00005A00;
    /// <summary>Windows status code for an aborted connection.</summary>
    public const uint E_PROXY_CONNECTIONABORTED = 0x000004D4;
}
