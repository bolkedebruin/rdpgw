using System.Net.WebSockets;

namespace Rdpgw.Transport;

public sealed class WebSocketTransport : ITransport
{
    private readonly WebSocket _webSocket;

    public WebSocketTransport(WebSocket webSocket) => _webSocket = webSocket;

    public async Task<(int Length, byte[] Packet)> ReadPacketAsync(CancellationToken ct = default)
    {
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

    public async Task<int> WritePacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct = default)
    {
        await _webSocket.SendAsync(packet, WebSocketMessageType.Binary, true, ct).ConfigureAwait(false);
        return packet.Length;
    }

    public async Task CloseAsync()
    {
        if (_webSocket.State is WebSocketState.Open or WebSocketState.CloseReceived)
        {
            await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "closing", CancellationToken.None).ConfigureAwait(false);
        }
        _webSocket.Dispose();
    }
}
