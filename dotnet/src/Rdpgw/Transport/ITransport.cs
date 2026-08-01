namespace Rdpgw.Transport;

public interface ITransport
{
    Task<(int Length, byte[] Packet)> ReadPacketAsync(CancellationToken ct = default);
    Task<int> WritePacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct = default);
    Task CloseAsync();
}
