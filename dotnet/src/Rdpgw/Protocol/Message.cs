namespace Rdpgw.Protocol;

/// <summary>Represents one decoded MS-TSGU packet body read from a transport.</summary>
public sealed class Message
{
    /// <summary>Packet type from the MS-TSGU packet header.</summary>
    public int PacketType { get; set; }
    /// <summary>Total packet length including the 8-byte packet header.</summary>
    public int Length { get; set; }
    /// <summary>Packet payload after the common header.</summary>
    public byte[] Msg { get; set; } = Array.Empty<byte>();
    /// <summary>Error encountered while framing or decoding the packet, if any.</summary>
    public Exception? Error { get; set; }
}
