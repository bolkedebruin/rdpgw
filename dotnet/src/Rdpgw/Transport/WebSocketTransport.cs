using System.Net.WebSockets;

namespace Rdpgw.Transport;

/// <summary>Adapts a binary WebSocket to the gateway packet transport abstraction.</summary>
public sealed class WebSocketTransport : ITransport
{
    private readonly WebSocket _webSocket;

    /// <summary>Initializes a transport over an accepted WebSocket.</summary>
    /// <param name="webSocket">Accepted WebSocket carrying binary gateway packets.</param>
    public WebSocketTransport(WebSocket webSocket) => _webSocket = webSocket;

    /// <summary>Reads one complete binary WebSocket message.</summary>
    /// <param name="ct">Cancellation token for the receive operation.</param>
    /// <returns>The message length and bytes.</returns>
    public async Task<(int Length, byte[] Packet)> ReadPacketAsync(CancellationToken ct = default)
    {
        // A single WebSocket message can arrive in multiple frames; coalesce before packet parsing.
        using var ms = new MemoryStream();
        var buffer = new byte[4096];
        WebSocketReceiveResult result;
        do
        {
            result = await _webSocket.ReceiveAsync(buffer, ct).ConfigureAwait(false);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                throw new EndOfStreamException("websocket closed");
            }
            if (result.MessageType != WebSocketMessageType.Binary)
            {
                throw new InvalidDataException("not a binary packet");
            }
            ms.Write(buffer, 0, result.Count);
        } while (!result.EndOfMessage);

        var packet = ms.ToArray();
        return (packet.Length, packet);
    }

    /// <summary>Sends a complete gateway packet as one binary WebSocket message.</summary>
    /// <param name="packet">Packet bytes to send.</param>
    /// <param name="ct">Cancellation token for the send operation.</param>
    /// <returns>The number of bytes sent.</returns>
    public async Task<int> WritePacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct = default)
    {
        await _webSocket.SendAsync(packet, WebSocketMessageType.Binary, true, ct).ConfigureAwait(false);
        return packet.Length;
    }

    /// <summary>Gracefully closes and disposes the WebSocket.</summary>
    public async Task CloseAsync()
    {
        if (_webSocket.State is WebSocketState.Open or WebSocketState.CloseReceived)
        {
            await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "closing", CancellationToken.None).ConfigureAwait(false);
        }
        _webSocket.Dispose();
    }
}
