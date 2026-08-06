namespace Rdpgw.Protocol;

public static class Caps
{
    public const int HTTP_EXTENDED_AUTH_NONE = 0x0;
    public const int HTTP_EXTENDED_AUTH_SC = 0x1;
    public const int HTTP_EXTENDED_AUTH_PAA = 0x02;
    public const int HTTP_EXTENDED_AUTH_SSPI_NTLM = 0x04;
    public const int SERVER_STATE_INITIALIZED = 0x0;
    public const int SERVER_STATE_HANDSHAKE = 0x1;
    public const int SERVER_STATE_TUNNEL_CREATE = 0x2;
    public const int SERVER_STATE_TUNNEL_AUTHORIZE = 0x3;
    public const int SERVER_STATE_CHANNEL_CREATE = 0x4;
    public const int SERVER_STATE_OPENED = 0x5;
    public const int SERVER_STATE_CLOSED = 0x6;
    public const int HTTP_CAPABILITY_TYPE_QUAR_SOH = 0x1;
    public const int HTTP_CAPABILITY_IDLE_TIMEOUT = 0x2;
    public const int HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN = 0x4;
    public const int HTTP_CAPABILITY_MESSAGING_SERVICE_MSG = 0x8;
    public const int HTTP_CAPABILITY_REAUTH = 0x10;
    public const int HTTP_CAPABILITY_UDP_TRANSPORT = 0x20;
}
