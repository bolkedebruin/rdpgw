namespace Rdpgw.Protocol;

/// <summary>
/// MS-TSGU packet type identifiers carried in the 8-byte gateway packet header.
/// </summary>
public static class PacketType
{
    /// <summary>Client-to-server handshake request packet.</summary>
    public const int PKT_TYPE_HANDSHAKE_REQUEST = 0x1;
    /// <summary>Server-to-client handshake response packet.</summary>
    public const int PKT_TYPE_HANDSHAKE_RESPONSE = 0x2;
    /// <summary>Extended authentication continuation packet.</summary>
    public const int PKT_TYPE_EXTENDED_AUTH_MSG = 0x3;
    /// <summary>Client request to create an RD Gateway tunnel.</summary>
    public const int PKT_TYPE_TUNNEL_CREATE = 0x4;
    /// <summary>Server response to a tunnel create request.</summary>
    public const int PKT_TYPE_TUNNEL_RESPONSE = 0x5;
    /// <summary>Client tunnel authorization request packet.</summary>
    public const int PKT_TYPE_TUNNEL_AUTH = 0x6;
    /// <summary>Server response to tunnel authorization.</summary>
    public const int PKT_TYPE_TUNNEL_AUTH_RESPONSE = 0x7;
    /// <summary>Client request to create a target server channel.</summary>
    public const int PKT_TYPE_CHANNEL_CREATE = 0x8;
    /// <summary>Server response to a channel create request.</summary>
    public const int PKT_TYPE_CHANNEL_RESPONSE = 0x9;
    /// <summary>Bidirectional RDP payload data packet.</summary>
    public const int PKT_TYPE_DATA = 0xA;
    /// <summary>Gateway service message packet.</summary>
    public const int PKT_TYPE_SERVICE_MESSAGE = 0xB;
    /// <summary>Gateway reauthentication message packet.</summary>
    public const int PKT_TYPE_REAUTH_MESSAGE = 0xC;
    /// <summary>Keepalive packet used to hold an established tunnel open.</summary>
    public const int PKT_TYPE_KEEPALIVE = 0xD;
    /// <summary>Client request to close the active channel.</summary>
    public const int PKT_TYPE_CLOSE_CHANNEL = 0x10;
    /// <summary>Server acknowledgement for a close-channel request.</summary>
    public const int PKT_TYPE_CLOSE_CHANNEL_RESPONSE = 0x11;
}
