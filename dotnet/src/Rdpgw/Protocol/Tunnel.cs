using System.Net.Sockets;
using Microsoft.AspNetCore.Http;
using Rdpgw.Identity;
using Rdpgw.Transport;

namespace Rdpgw.Protocol;

public sealed class Tunnel
{
    public string Id { get; set; } = string.Empty;
    public string RDGId { get; set; } = string.Empty;
    public string TargetServer { get; set; } = string.Empty;
    public string RemoteAddr { get; set; } = string.Empty;
    public IIdentity User { get; set; } = new User();
    public ITransport? TransportIn { get; internal set; }
    public ITransport? TransportOut { get; internal set; }
    public TcpClient? Rwc { get; set; }
    public HttpContext? Context { get; set; }
    private long _bytesSent;
    private long _bytesReceived;
    public long BytesSent => Interlocked.Read(ref _bytesSent);
    public long BytesReceived => Interlocked.Read(ref _bytesReceived);
    public DateTimeOffset ConnectedOn { get; set; }
    public DateTimeOffset LastSeen { get; set; }

    public async Task WriteAsync(byte[] pkt)
    {
        if (TransportOut is null)
        {
            throw new InvalidOperationException("transportOut is not set");
        }
        var n = await TransportOut.WritePacketAsync(pkt).ConfigureAwait(false);
        Interlocked.Add(ref _bytesSent, n);
    }

    public async Task<List<Message>> ReadAsync() => await ReadAsync(CancellationToken.None).ConfigureAwait(false);

    internal async Task<List<Message>> ReadAsync(CancellationToken ct)
    {
        if (TransportIn is null)
        {
            throw new InvalidOperationException("transportIn is not set");
        }
        var messages = await ProtocolCommon.ReadMessageAsync(TransportIn, ct).ConfigureAwait(false);
        foreach (var message in messages)
        {
            Interlocked.Add(ref _bytesReceived, message.Length);
            LastSeen = DateTimeOffset.UtcNow;
        }
        return messages;
    }
}
