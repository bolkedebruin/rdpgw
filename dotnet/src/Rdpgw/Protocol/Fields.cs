namespace Rdpgw.Protocol;

/// <summary>
/// MS-TSGU response field-mask and redirection flag constants.
/// </summary>
public static class Fields
{
    /// <summary>Tunnel response includes the tunnel identifier field.</summary>
    public const int HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID = 0x01;
    /// <summary>Tunnel response includes the server capability field.</summary>
    public const int HTTP_TUNNEL_RESPONSE_FIELD_CAPS = 0x02;
    /// <summary>Tunnel response includes a statement-of-health request field.</summary>
    public const int HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ = 0x04;
    /// <summary>Tunnel response includes a consent message field.</summary>
    public const int HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG = 0x10;
    /// <summary>Tunnel authorization response includes device redirection flags.</summary>
    public const int HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS = 0x01;
    /// <summary>Tunnel authorization response includes the idle timeout field.</summary>
    public const int HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT = 0x02;
    /// <summary>Tunnel authorization response includes a statement-of-health response field.</summary>
    public const int HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE = 0x04;
    /// <summary>Redirection mask value that enables all client redirection channels.</summary>
    public const uint HTTP_TUNNEL_REDIR_ENABLE_ALL = 0x80000000;
    /// <summary>Redirection mask value that disables all client redirection channels.</summary>
    public const uint HTTP_TUNNEL_REDIR_DISABLE_ALL = 0x40000000;
    /// <summary>Redirection mask bit that disables drive redirection.</summary>
    public const int HTTP_TUNNEL_REDIR_DISABLE_DRIVE = 0x01;
    /// <summary>Redirection mask bit that disables printer redirection.</summary>
    public const int HTTP_TUNNEL_REDIR_DISABLE_PRINTER = 0x02;
    /// <summary>Redirection mask bit that disables port redirection.</summary>
    public const int HTTP_TUNNEL_REDIR_DISABLE_PORT = 0x04;
    /// <summary>Redirection mask bit that disables clipboard redirection.</summary>
    public const int HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD = 0x08;
    /// <summary>Redirection mask bit that disables Plug and Play device redirection.</summary>
    public const int HTTP_TUNNEL_REDIR_DISABLE_PNP = 0x10;
    /// <summary>Channel response includes the channel identifier field.</summary>
    public const int HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID = 0x01;
    /// <summary>Channel response includes an authentication cookie field.</summary>
    public const int HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE = 0x02;
    /// <summary>Channel response includes a UDP port field.</summary>
    public const int HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT = 0x04;
    /// <summary>Tunnel create request includes a PAA cookie field.</summary>
    public const int HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE = 0x1;
}
