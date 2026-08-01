using System.Collections.Concurrent;

namespace Rdpgw.Protocol;

public static class ConnectionTracker
{
    public static ConcurrentDictionary<string, Monitor> Connections { get; } = new();

    public sealed class Monitor
    {
        public required Processor Processor { get; init; }
        public required Tunnel Tunnel { get; init; }
    }

    public static void RegisterTunnel(Tunnel t, Processor p) =>
        Connections[t.Id] = new Monitor { Processor = p, Tunnel = t };

    public static void RemoveTunnel(Tunnel t) => Connections.TryRemove(t.Id, out _);

    public static void Disconnect(string id)
    {
        if (!Connections.TryGetValue(id, out var monitor))
        {
            throw new KeyNotFoundException($"{id} connection does not exist");
        }
        monitor.Processor.SignalDisconnect();
    }
}
