namespace Rdpgw.Protocol;

public static class Fields
{
    public const int HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID = 0x01;
    public const int HTTP_TUNNEL_RESPONSE_FIELD_CAPS = 0x02;
    public const int HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ = 0x04;
    public const int HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG = 0x10;
    public const int HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS = 0x01;
    public const int HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT = 0x02;
    public const int HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE = 0x04;
    public const uint HTTP_TUNNEL_REDIR_ENABLE_ALL = 0x80000000;
    public const uint HTTP_TUNNEL_REDIR_DISABLE_ALL = 0x40000000;
    public const int HTTP_TUNNEL_REDIR_DISABLE_DRIVE = 0x01;
    public const int HTTP_TUNNEL_REDIR_DISABLE_PRINTER = 0x02;
    public const int HTTP_TUNNEL_REDIR_DISABLE_PORT = 0x04;
    public const int HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD = 0x08;
    public const int HTTP_TUNNEL_REDIR_DISABLE_PNP = 0x10;
    public const int HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID = 0x01;
    public const int HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE = 0x02;
    public const int HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT = 0x04;
    public const int HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE = 0x1;
}
