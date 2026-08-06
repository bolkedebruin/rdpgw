namespace Rdpgw.Protocol;

public static class ProtocolErrors
{
    public const uint ERROR_SUCCESS = 0x00000000;
    public const uint ERROR_ACCESS_DENIED = 0x00000005;
    public const uint E_PROXY_INTERNALERROR = 0x800759D8;
    public const uint E_PROXY_RAP_ACCESSDENIED = 0x800759DA;
    public const uint E_PROXY_NAP_ACCESSDENIED = 0x800759DB;
    public const uint E_PROXY_ALREADYDISCONNECTED = 0x800759DF;
    public const uint E_PROXY_QUARANTINE_ACCESSDENIED = 0x800759ED;
    public const uint E_PROXY_NOCERTAVAILABLE = 0x800759EE;
    public const uint E_PROXY_COOKIE_BADPACKET = 0x800759F7;
    public const uint E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED = 0x800759F8;
    public const uint E_PROXY_UNSUPPORTED_AUTHENTICATION_METHOD = 0x800759F9;
    public const uint E_PROXY_CAPABILITYMISMATCH = 0x800759E9;
    public const uint E_PROXY_TS_CONNECTFAILED = 0x000059DD;
    public const uint E_PROXY_MAXCONNECTIONSREACHED = 0x000059E6;
    public const uint ERROR_GRACEFUL_DISCONNECT = 0x000004CA;
    public const uint E_PROXY_NOTSUPPORTED = 0x000059E8;
    public const uint SEC_E_LOGON_DENIED = 0x8009030C;
    public const uint E_PROXY_SESSIONTIMEOUT = 0x000059F6;
    public const uint E_PROXY_REAUTH_AUTHN_FAILED = 0x000059FA;
    public const uint E_PROXY_REAUTH_CAP_FAILED = 0x000059FB;
    public const uint E_PROXY_REAUTH_RAP_FAILED = 0x000059FC;
    public const uint E_PROXY_SDR_NOT_SUPPORTED_BY_TS = 0x000059FD;
    public const uint E_PROXY_REAUTH_NAP_FAILED = 0x00005A00;
    public const uint E_PROXY_CONNECTIONABORTED = 0x000004D4;
}
