namespace Rdpgw.Protocol;

public static class PacketType
{
    public const int PKT_TYPE_HANDSHAKE_REQUEST = 0x1;
    public const int PKT_TYPE_HANDSHAKE_RESPONSE = 0x2;
    public const int PKT_TYPE_EXTENDED_AUTH_MSG = 0x3;
    public const int PKT_TYPE_TUNNEL_CREATE = 0x4;
    public const int PKT_TYPE_TUNNEL_RESPONSE = 0x5;
    public const int PKT_TYPE_TUNNEL_AUTH = 0x6;
    public const int PKT_TYPE_TUNNEL_AUTH_RESPONSE = 0x7;
    public const int PKT_TYPE_CHANNEL_CREATE = 0x8;
    public const int PKT_TYPE_CHANNEL_RESPONSE = 0x9;
    public const int PKT_TYPE_DATA = 0xA;
    public const int PKT_TYPE_SERVICE_MESSAGE = 0xB;
    public const int PKT_TYPE_REAUTH_MESSAGE = 0xC;
    public const int PKT_TYPE_KEEPALIVE = 0xD;
    public const int PKT_TYPE_CLOSE_CHANNEL = 0x10;
    public const int PKT_TYPE_CLOSE_CHANNEL_RESPONSE = 0x11;
}
