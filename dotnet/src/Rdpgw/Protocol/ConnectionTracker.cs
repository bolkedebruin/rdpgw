using System.Collections.Concurrent;

namespace Rdpgw.Protocol;

/// <summary>
/// Tracks active RD Gateway tunnels so administrative code can disconnect them by identifier.
/// </summary>
public static class ConnectionTracker
{
    /// <summary>Active tunnel monitors keyed by the server-generated tunnel identifier.</summary>
    public static ConcurrentDictionary<string, Monitor> Connections { get; } = new();

    /// <summary>References the protocol processor and tunnel for an active connection.</summary>
    public sealed class Monitor
    {
        /// <summary>Processor driving the MS-TSGU state machine for the tunnel.</summary>
        public required Processor Processor { get; init; }
        /// <summary>Tunnel metadata and transports associated with the connection.</summary>
        public required Tunnel Tunnel { get; init; }
    }

    /// <summary>Registers a tunnel when its protocol processor starts.</summary>
    /// <param name="t">Tunnel to expose in the connection cache.</param>
    /// <param name="p">Processor that can be signaled to disconnect the tunnel.</param>
    public static void RegisterTunnel(Tunnel t, Processor p) =>
        Connections[t.Id] = new Monitor { Processor = p, Tunnel = t };

    /// <summary>Removes a tunnel from the active connection cache.</summary>
    /// <param name="t">Tunnel whose identifier should be removed.</param>
    public static void RemoveTunnel(Tunnel t) => Connections.TryRemove(t.Id, out _);

    /// <summary>Signals an active tunnel to disconnect.</summary>
    /// <param name="id">Server-generated tunnel identifier.</param>
    /// <exception cref="KeyNotFoundException">Thrown when no active tunnel exists for <paramref name="id" />.</exception>
    public static void Disconnect(string id)
    {
        if (!Connections.TryGetValue(id, out var monitor))
        {
            throw new KeyNotFoundException($"{id} connection does not exist");
        }
        monitor.Processor.SignalDisconnect();
    }
}
