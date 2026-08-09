using Prometheus;

namespace Rdpgw.Protocol;

/// <summary>Prometheus metrics emitted by the RD Gateway protocol layer.</summary>
internal static class ProtocolMetrics
{
    /// <summary>Gauge containing the number of cached legacy tunnel records.</summary>
    internal static readonly Gauge ConnectionCache = Metrics.CreateGauge(
        "rdpgw_connection_cache", "The amount of connections in the cache");
    /// <summary>Gauge containing the number of currently active WebSocket tunnels.</summary>
    internal static readonly Gauge WebsocketConnections = Metrics.CreateGauge(
        "rdpgw_websocket_connections", "The count of websocket connections");
    /// <summary>Gauge containing the number of currently active legacy HTTPS tunnel pairs.</summary>
    internal static readonly Gauge LegacyConnections = Metrics.CreateGauge(
        "rdpgw_legacy_connections", "The count of legacy https connections");
}
