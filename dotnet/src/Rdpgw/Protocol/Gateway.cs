using Microsoft.Extensions.Caching.Memory;
using Rdpgw.Identity;
using Rdpgw.Logging;
using Rdpgw.Transport;

namespace Rdpgw.Protocol;

/// <summary>
/// ASP.NET Core entry point for RD Gateway protocol requests and transport selection.
/// </summary>
/// <remarks>
/// Handles both legacy RDG_IN_DATA/RDG_OUT_DATA HTTP transports and the WebSocket transport before delegating MS-TSGU packet processing to <see cref="Processor" />.
/// </remarks>
public sealed class Gateway
{
    private const string RdgConnectionIdKey = "Rdg-Connection-Id";
    private const string MethodRDGIN = "RDG_IN_DATA";
    private const string MethodRDGOUT = "RDG_OUT_DATA";
    private static readonly MemoryCache Cache = new(new MemoryCacheOptions());
    private readonly ILogger _logger = Log.For<Gateway>();

    /// <summary>Callback used to validate a PAA cookie from the tunnel create request.</summary>
    public Func<HttpContext, string, Task<bool>>? CheckPAACookie { get; set; }
    /// <summary>Callback used to authorize the client computer name in tunnel authorization.</summary>
    public Func<HttpContext, string, Task<bool>>? CheckClientName { get; set; }
    /// <summary>Callback used to authorize the requested target host and port.</summary>
    public Func<HttpContext, string, Task<bool>>? CheckHost { get; set; }
    /// <summary>Device redirection policy advertised in tunnel authorization responses.</summary>
    public RedirectFlags RedirectFlags { get; set; } = new();
    /// <summary>Idle timeout, in milliseconds, sent to clients that support the idle-timeout capability.</summary>
    public int IdleTimeout { get; set; }
    /// <summary>Whether the gateway requires or offers smart-card extended authentication.</summary>
    public bool SmartCardAuth { get; set; }
    /// <summary>Whether the gateway requires or offers PAA token-cookie authentication.</summary>
    public bool TokenAuth { get; set; }
    /// <summary>Optional TCP receive buffer size applied to target server connections.</summary>
    public int ReceiveBuf { get; set; }
    /// <summary>Optional TCP send buffer size applied to target server connections.</summary>
    public int SendBuf { get; set; }

    /// <summary>Handles one HTTP request participating in an RD Gateway connection.</summary>
    /// <param name="context">Current ASP.NET Core request context.</param>
    /// <returns>A task that completes after the request or tunnel processing ends.</returns>
    public async Task HandleGatewayProtocol(HttpContext context)
    {
        ProtocolMetrics.ConnectionCache.Set(Cache.Count);

        // Legacy clients correlate the RDG_OUT_DATA and RDG_IN_DATA requests with this header.
        var id = IdentityContext.FromContext(context) ?? new User();
        var connId = context.Request.Headers[RdgConnectionIdKey].FirstOrDefault() ?? string.Empty;
        if (!Cache.TryGetValue<Tunnel>(connId, out var tunnel) || tunnel is null)
        {
            tunnel = new Tunnel
            {
                RDGId = connId,
                RemoteAddr = Convert.ToString(id.GetAttribute(IdentityContext.AttrRemoteAddr)) ?? string.Empty,
                User = id,
                Context = context,
            };
        }
        else if (!TunnelOwnerMatches(tunnel, id))
        {
            _logger.LogWarning("rejecting reuse of Rdg-Connection-Id {ConnectionId} from a different identity", connId);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Tunnel is owned by a different session", context.RequestAborted).ConfigureAwait(false);
            return;
        }

        // RDG_OUT_DATA carries server-to-client bytes; with WebSockets it becomes the single bidirectional stream.
        if (string.Equals(context.Request.Method, MethodRDGOUT, StringComparison.OrdinalIgnoreCase))
        {
            if (IsWebSocketUpgrade(context))
            {
                if (!context.WebSockets.IsWebSocketRequest)
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("WebSocket upgrade was requested but is not available for this request", context.RequestAborted).ConfigureAwait(false);
                    return;
                }
                using var ws = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
                await HandleWebsocketProtocol(context, ws, tunnel).ConfigureAwait(false);
                return;
            }
            await HandleLegacyProtocol(context, tunnel).ConfigureAwait(false);
        }
        // RDG_IN_DATA carries client-to-server bytes for the legacy two-request transport.
        else if (string.Equals(context.Request.Method, MethodRDGIN, StringComparison.OrdinalIgnoreCase))
        {
            await HandleLegacyProtocol(context, tunnel).ConfigureAwait(false);
        }
        else
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
        }
    }

    private static bool TunnelOwnerMatches(Tunnel? tunnel, IIdentity? id)
    {
        if (tunnel?.User is null || id is null)
        {
            return false;
        }
        if (string.IsNullOrEmpty(tunnel.User.UserName) || tunnel.User.UserName != id.UserName)
        {
            return false;
        }
        // Require the same authenticated username and client IP before reusing a cached legacy tunnel.
        var cachedIp = Convert.ToString(tunnel.User.GetAttribute(IdentityContext.AttrClientIp)) ?? string.Empty;
        var reqIp = Convert.ToString(id.GetAttribute(IdentityContext.AttrClientIp)) ?? string.Empty;
        return cachedIp.Length > 0 && cachedIp == reqIp;
    }

    private static bool HeaderHasToken(IHeaderDictionary headers, string name, string token)
    {
        if (!headers.TryGetValue(name, out var values)) return false;
        foreach (var value in values)
        {
            foreach (var part in (value ?? string.Empty).Split(','))
            {
                if (string.Equals(part.Trim(), token, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private static bool IsWebSocketUpgrade(HttpContext context) =>
        // HTTP header token matching is comma-aware because Connection can contain multiple values.
        HeaderHasToken(context.Request.Headers, "Connection", "upgrade") &&
        HeaderHasToken(context.Request.Headers, "Upgrade", "websocket");

    private async Task HandleWebsocketProtocol(HttpContext context, System.Net.WebSockets.WebSocket socket, Tunnel tunnel)
    {
        ProtocolMetrics.WebsocketConnections.Inc();
        try
        {
            // WebSocket mode maps both MS-TSGU directions onto one binary message transport.
            var inout = new WebSocketTransport(socket);
            tunnel.Id = Guid.NewGuid().ToString();
            tunnel.TransportOut = inout;
            tunnel.TransportIn = inout;
            tunnel.ConnectedOn = DateTimeOffset.UtcNow;

            var processor = new Processor(this, tunnel);
            ConnectionTracker.RegisterTunnel(tunnel, processor);
            try
            {
                await processor.ProcessAsync(context.RequestAborted).ConfigureAwait(false);
            }
            finally
            {
                ConnectionTracker.RemoveTunnel(tunnel);
            }
        }
        finally
        {
            ProtocolMetrics.WebsocketConnections.Dec();
        }
    }

    private async Task HandleLegacyProtocol(HttpContext context, Tunnel tunnel)
    {
        _logger.LogDebug("Session {SessionId}, out: {HasTransportOut}, in: {HasTransportIn}", tunnel.RDGId, tunnel.TransportOut is not null, tunnel.TransportIn is not null);
        var id = IdentityContext.FromContext(context) ?? tunnel.User;
        if (string.Equals(context.Request.Method, MethodRDGOUT, StringComparison.OrdinalIgnoreCase))
        {
            // The first legacy request opens RDG_OUT_DATA and is cached until RDG_IN_DATA arrives.
            var output = await LegacyTransport.CreateAsync(context).ConfigureAwait(false);
            _logger.LogInformation("Opening RDGOUT for client {ClientIp}", id.GetAttribute(IdentityContext.AttrClientIp));
            tunnel.TransportOut = output;
            await output.SendAcceptAsync(true).ConfigureAwait(false);
            Cache.Set(tunnel.RDGId, tunnel, TimeSpan.FromMinutes(5));
            ProtocolMetrics.ConnectionCache.Set(Cache.Count);
            return;
        }

        if (string.Equals(context.Request.Method, MethodRDGIN, StringComparison.OrdinalIgnoreCase))
        {
            ProtocolMetrics.LegacyConnections.Inc();
            try
            {
                var input = await LegacyTransport.CreateAsync(context).ConfigureAwait(false);
                try
                {
                    if (tunnel.TransportIn is null)
                    {
                        tunnel.Id = Guid.NewGuid().ToString();
                        tunnel.TransportIn = input;
                        tunnel.ConnectedOn = DateTimeOffset.UtcNow;
                        Cache.Set(tunnel.RDGId, tunnel, TimeSpan.FromMinutes(5));
                        ProtocolMetrics.ConnectionCache.Set(Cache.Count);

                        _logger.LogInformation("Opening RDGIN for client {ClientIp}", id.GetAttribute(IdentityContext.AttrClientIp));
                        await input.SendAcceptAsync(false).ConfigureAwait(false);
                        // RDG_IN_DATA sends an initial body segment after the HTTP 200; drain it before packet processing.
                        await input.DrainAsync().ConfigureAwait(false);
                        _logger.LogInformation("Legacy handshakeRequest done for client {ClientIp}", id.GetAttribute(IdentityContext.AttrClientIp));

                        var processor = new Processor(this, tunnel);
                        ConnectionTracker.RegisterTunnel(tunnel, processor);
                        try
                        {
                            await processor.ProcessAsync(context.RequestAborted).ConfigureAwait(false);
                        }
                        finally
                        {
                            ConnectionTracker.RemoveTunnel(tunnel);
                        }
                    }
                }
                finally
                {
                    await input.CloseAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                ProtocolMetrics.LegacyConnections.Dec();
            }
        }
    }
}
