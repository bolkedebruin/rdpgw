namespace Rdpgw.Transport;

/// <summary>Abstracts the packet-oriented transport used by the protocol processor.</summary>
public interface ITransport
{
    /// <summary>Reads the next transport frame containing one or more MS-TSGU packets.</summary>
    /// <param name="ct">Cancellation token for the read operation.</param>
    /// <returns>The frame length and frame bytes.</returns>
    Task<(int Length, byte[] Packet)> ReadPacketAsync(CancellationToken ct = default);
    /// <summary>Writes a complete MS-TSGU packet or transport preface to the peer.</summary>
    /// <param name="packet">Packet bytes to write.</param>
    /// <param name="ct">Cancellation token for the write operation.</param>
    /// <returns>The number of bytes written.</returns>
    Task<int> WritePacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct = default);
    /// <summary>Closes the underlying transport.</summary>
    /// <returns>A task that completes when close handling has finished.</returns>
    Task CloseAsync();
}
