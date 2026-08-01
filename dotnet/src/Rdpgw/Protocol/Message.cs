namespace Rdpgw.Protocol;

public sealed class Message
{
    public int PacketType { get; set; }
    public int Length { get; set; }
    public byte[] Msg { get; set; } = Array.Empty<byte>();
    public Exception? Error { get; set; }
}
