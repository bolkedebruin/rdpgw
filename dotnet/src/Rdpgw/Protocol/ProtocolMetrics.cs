using Prometheus;

namespace Rdpgw.Protocol;

internal static class ProtocolMetrics
{
    internal static readonly Gauge ConnectionCache = Metrics.CreateGauge(
        "rdpgw_connection_cache", "The amount of connections in the cache");
    internal static readonly Gauge WebsocketConnections = Metrics.CreateGauge(
        "rdpgw_websocket_connections", "The count of websocket connections");
    internal static readonly Gauge LegacyConnections = Metrics.CreateGauge(
        "rdpgw_legacy_connections", "The count of legacy https connections");
}
