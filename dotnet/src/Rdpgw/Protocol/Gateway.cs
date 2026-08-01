using Microsoft.Extensions.Caching.Memory;
using Rdpgw.Identity;
using Rdpgw.Transport;

namespace Rdpgw.Protocol;

public sealed class Gateway
{
    private const string RdgConnectionIdKey = "Rdg-Connection-Id";
    private const string MethodRDGIN = "RDG_IN_DATA";
    private const string MethodRDGOUT = "RDG_OUT_DATA";
    private static readonly MemoryCache Cache = new(new MemoryCacheOptions());

    public Func<string, Task<bool>>? CheckPAACookie { get; set; }
    public Func<string, Task<bool>>? CheckClientName { get; set; }
    public Func<string, Task<bool>>? CheckHost { get; set; }
    public RedirectFlags RedirectFlags { get; set; } = new();
    public int IdleTimeout { get; set; }
    public bool SmartCardAuth { get; set; }
    public bool TokenAuth { get; set; }
    public int ReceiveBuf { get; set; }
    public int SendBuf { get; set; }

    public async Task HandleGatewayProtocol(HttpContext context)
    {
        ProtocolMetrics.ConnectionCache.Set(Cache.Count);

        var id = IdentityContext.FromContext(context) ?? new User();
        var connId = context.Request.Headers[RdgConnectionIdKey].FirstOrDefault() ?? string.Empty;
        if (!Cache.TryGetValue<Tunnel>(connId, out var tunnel) || tunnel is null)
        {
            tunnel = new Tunnel
            {
                RDGId = connId,
                RemoteAddr = Convert.ToString(id.GetAttribute(IdentityContext.AttrRemoteAddr)) ?? string.Empty,
                User = id,
            };
        }
        else if (!TunnelOwnerMatches(tunnel, id))
        {
            Console.WriteLine($"rejecting reuse of Rdg-Connection-Id {connId} from a different identity");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Tunnel is owned by a different session", context.RequestAborted).ConfigureAwait(false);
            return;
        }

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
        HeaderHasToken(context.Request.Headers, "Connection", "upgrade") &&
        HeaderHasToken(context.Request.Headers, "Upgrade", "websocket");

    private async Task HandleWebsocketProtocol(HttpContext context, System.Net.WebSockets.WebSocket socket, Tunnel tunnel)
    {
        ProtocolMetrics.WebsocketConnections.Inc();
        try
        {
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
        Console.WriteLine($"Session {tunnel.RDGId}, {tunnel.TransportOut is not null}, {tunnel.TransportIn is not null}");
        var id = IdentityContext.FromContext(context) ?? tunnel.User;
        if (string.Equals(context.Request.Method, MethodRDGOUT, StringComparison.OrdinalIgnoreCase))
        {
            var output = await LegacyTransport.CreateAsync(context).ConfigureAwait(false);
            Console.WriteLine($"Opening RDGOUT for client {id.GetAttribute(IdentityContext.AttrClientIp)}");
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

                        Console.WriteLine($"Opening RDGIN for client {id.GetAttribute(IdentityContext.AttrClientIp)}");
                        await input.SendAcceptAsync(false).ConfigureAwait(false);
                        await input.DrainAsync().ConfigureAwait(false);
                        Console.WriteLine($"Legacy handshakeRequest done for client {id.GetAttribute(IdentityContext.AttrClientIp)}");

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
