namespace Rdpgw.Protocol;

/// <summary>
/// MS-TSGU capability and server-state constants used during gateway negotiation.
/// </summary>
public static class Caps
{
    /// <summary>No extended HTTP authentication capability is requested or offered.</summary>
    public const int HTTP_EXTENDED_AUTH_NONE = 0x0;
    /// <summary>Smart-card extended authentication capability bit.</summary>
    public const int HTTP_EXTENDED_AUTH_SC = 0x1;
    /// <summary>Pluggable Authentication and Authorization (PAA) cookie capability bit.</summary>
    public const int HTTP_EXTENDED_AUTH_PAA = 0x02;
    /// <summary>SSPI NTLM extended authentication capability bit.</summary>
    public const int HTTP_EXTENDED_AUTH_SSPI_NTLM = 0x04;
    /// <summary>Processor state before an MS-TSGU handshake request is accepted.</summary>
    public const int SERVER_STATE_INITIALIZED = 0x0;
    /// <summary>Processor state after sending the handshake response.</summary>
    public const int SERVER_STATE_HANDSHAKE = 0x1;
    /// <summary>Processor state after the tunnel creation packet is accepted.</summary>
    public const int SERVER_STATE_TUNNEL_CREATE = 0x2;
    /// <summary>Processor state after tunnel authorization succeeds.</summary>
    public const int SERVER_STATE_TUNNEL_AUTHORIZE = 0x3;
    /// <summary>Processor state after the target channel is created.</summary>
    public const int SERVER_STATE_CHANNEL_CREATE = 0x4;
    /// <summary>Processor state while RDP payload data is flowing.</summary>
    public const int SERVER_STATE_OPENED = 0x5;
    /// <summary>Processor state after the channel close response is sent.</summary>
    public const int SERVER_STATE_CLOSED = 0x6;
    /// <summary>Server health statement-of-health capability bit.</summary>
    public const int HTTP_CAPABILITY_TYPE_QUAR_SOH = 0x1;
    /// <summary>Server capability bit indicating idle timeout support.</summary>
    public const int HTTP_CAPABILITY_IDLE_TIMEOUT = 0x2;
    /// <summary>Capability bit for signed consent messaging.</summary>
    public const int HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN = 0x4;
    /// <summary>Capability bit for service messages.</summary>
    public const int HTTP_CAPABILITY_MESSAGING_SERVICE_MSG = 0x8;
    /// <summary>Capability bit for reauthentication messages.</summary>
    public const int HTTP_CAPABILITY_REAUTH = 0x10;
    /// <summary>Capability bit for UDP transport support.</summary>
    public const int HTTP_CAPABILITY_UDP_TRANSPORT = 0x20;
}
