using System.Net.Sockets;
using Microsoft.AspNetCore.Http;
using Rdpgw.Identity;
using Rdpgw.Transport;

namespace Rdpgw.Protocol;

/// <summary>
/// Holds per-connection state for an RD Gateway tunnel, including transports, identity, target channel, and counters.
/// </summary>
public sealed class Tunnel
{
    /// <summary>Server-generated identifier used for active connection tracking.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Client-provided RDG connection identifier used to pair legacy HTTP requests.</summary>
    public string RDGId { get; set; } = string.Empty;
    /// <summary>Target host and port selected by the channel create request.</summary>
    public string TargetServer { get; set; } = string.Empty;
    /// <summary>Remote address recorded for logging and diagnostics.</summary>
    public string RemoteAddr { get; set; } = string.Empty;
    /// <summary>Authenticated user that owns the tunnel.</summary>
    public IIdentity User { get; set; } = new User();
    /// <summary>Transport used for client-to-gateway packets.</summary>
    public ITransport? TransportIn { get; internal set; }
    /// <summary>Transport used for gateway-to-client packets.</summary>
    public ITransport? TransportOut { get; internal set; }
    /// <summary>TCP connection to the requested target server.</summary>
    public TcpClient? Rwc { get; set; }
    /// <summary>HTTP context associated with the tunnel request.</summary>
    public HttpContext? Context { get; set; }
    private long _bytesSent;
    private long _bytesReceived;
    /// <summary>Total bytes written toward the RD Gateway client.</summary>
    public long BytesSent => Interlocked.Read(ref _bytesSent);
    /// <summary>Total bytes read from the RD Gateway client.</summary>
    public long BytesReceived => Interlocked.Read(ref _bytesReceived);
    /// <summary>UTC timestamp when the tunnel was established.</summary>
    public DateTimeOffset ConnectedOn { get; set; }
    /// <summary>UTC timestamp of the most recent packet received from the client.</summary>
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>Writes a complete packet to the outbound transport and updates byte counters.</summary>
    /// <param name="pkt">Packet bytes to send to the client.</param>
    public async Task WriteAsync(byte[] pkt)
    {
        if (TransportOut is null)
        {
            throw new InvalidOperationException("transportOut is not set");
        }
        var n = await TransportOut.WritePacketAsync(pkt).ConfigureAwait(false);
        Interlocked.Add(ref _bytesSent, n);
    }

    /// <summary>Reads all messages currently available from the inbound transport.</summary>
    /// <returns>Decoded gateway messages.</returns>
    public async Task<List<Message>> ReadAsync() => await ReadAsync(CancellationToken.None).ConfigureAwait(false);

    /// <summary>Reads all messages from the inbound transport with cancellation support.</summary>
    /// <param name="ct">Cancellation token for the read.</param>
    /// <returns>Decoded gateway messages.</returns>
    internal async Task<List<Message>> ReadAsync(CancellationToken ct)
    {
        if (TransportIn is null)
        {
            throw new InvalidOperationException("transportIn is not set");
        }
        var messages = await ProtocolCommon.ReadMessageAsync(TransportIn, ct).ConfigureAwait(false);
        // Count the full gateway packet length, not just the payload, for diagnostics.
        foreach (var message in messages)
        {
            Interlocked.Add(ref _bytesReceived, message.Length);
            LastSeen = DateTimeOffset.UtcNow;
        }
        return messages;
    }
}
