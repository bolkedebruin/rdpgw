using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Rdpgw.Config;
using Rdpgw.Identity;
using Rdpgw.Security;
using Rdpgw.Transport;

namespace Rdpgw.Protocol;

/// <summary>
/// ASP.NET Core entry point for RD Gateway protocol requests and transport selection.
/// </summary>
/// <remarks>
/// Handles both legacy RDG_IN_DATA/RDG_OUT_DATA HTTP transports and the WebSocket transport before delegating MS-TSGU packet processing to <see cref="ProcessorService" />.
/// </remarks>
[ApiController]
[Route("/remoteDesktopGateway")]
public sealed partial class GatewayService(ILogger<GatewayService> logger, IMemoryCache tunnelCache, IOptions<CapsConfig> capsConfig, ITokenService tokenService, ProcessorService processorService)
{
    private const string RdgConnectionIdKey = "Rdg-Connection-Id";
    private const string MethodRDGIN = "RDG_IN_DATA";
    private const string MethodRDGOUT = "RDG_OUT_DATA";

	/*
     * {
    RedirectFlags = new RedirectFlags { Clipboard = configuration.Caps.EnableClipboard, Drive = configuration.Caps.EnableDrive, Printer = configuration.Caps.EnablePrinter, Port = configuration.Caps.EnablePort, Pnp = configuration.Caps.EnablePnp, DisableAll = configuration.Caps.DisableRedirect, EnableAll = configuration.Caps.RedirectAll },
    IdleTimeout = configuration.Caps.IdleTimeout,
    SmartCardAuth = configuration.Caps.SmartCardAuth,
    TokenAuth = configuration.Caps.TokenAuth,
    ReceiveBuf = configuration.Server.ReceiveBuf,
    SendBuf = configuration.Server.SendBuf,
};
if (configuration.Caps.TokenAuth)
{
    gw.CheckHost = Security.CheckSession(Security.CheckHost);
}
else gw.CheckHost = Security.CheckHost;*/

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
    [AcceptVerbs(MethodRDGIN, MethodRDGOUT)]
    public async Task HandleGatewayProtocol(HttpContext context)
    {
        // Legacy clients correlate the RDG_OUT_DATA and RDG_IN_DATA requests with this header.
        var id = IdentityContext.FromContext(context) ?? new User();
        var connId = context.Request.Headers[RdgConnectionIdKey].FirstOrDefault() ?? string.Empty;
        if (!tunnelCache.TryGetValue<Tunnel>(connId, out var tunnel) || tunnel is null)
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
            logger.LogWarning("rejecting reuse of Rdg-Connection-Id {ConnectionId} from a different identity", connId);
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
                using var ws = await context
                    .WebSockets
                    .AcceptWebSocketAsync()
                    .ConfigureAwait(false);
                await HandleWebsocketProtocol(context, ws, tunnel)
                    .ConfigureAwait(false);
                return;
            }

            await HandleLegacyProtocol(context, tunnel)
                .ConfigureAwait(false);
        }
        // RDG_IN_DATA carries client-to-server bytes for the legacy two-request transport.
        else if (string.Equals(context.Request.Method, MethodRDGIN, StringComparison.OrdinalIgnoreCase))
        {
            await HandleLegacyProtocol(context, tunnel)
                .ConfigureAwait(false);
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
        try
        {
            // WebSocket mode maps both MS-TSGU directions onto one binary message transport.
            var inout = new WebSocketTransport(socket);
            tunnel.Id = Guid.NewGuid().ToString();
            tunnel.TransportOut = inout;
            tunnel.TransportIn = inout;
            tunnel.ConnectedOn = DateTimeOffset.UtcNow;

            try
            {
                await ProcessAsync(tunnel, context.RequestAborted);
            }
            finally
            {
                ConnectionTracker.RemoveTunnel(tunnel);
            }
        }
        catch (Exception ex)
        {
			logger.LogError(ex, "WebSocket protocol error for session {SessionId}", tunnel.RDGId);
			context.Response.StatusCode = StatusCodes.Status500InternalServerError;
			await context.Response.WriteAsync("WebSocket protocol error: " + ex.Message, context.RequestAborted).ConfigureAwait(false);
		}
        finally
        {

        }
    }

    private async Task HandleLegacyProtocol(HttpContext context, Tunnel tunnel)
    {
        logger.LogDebug("Session {SessionId}, out: {HasTransportOut}, in: {HasTransportIn}", tunnel.RDGId, tunnel.TransportOut is not null, tunnel.TransportIn is not null);
        var id = IdentityContext.FromContext(context) ?? tunnel.User;
        if (string.Equals(context.Request.Method, MethodRDGOUT, StringComparison.OrdinalIgnoreCase))
        {
            // The first legacy request opens RDG_OUT_DATA and is cached until RDG_IN_DATA arrives.
            var output = await LegacyTransport.CreateAsync(context).ConfigureAwait(false);
            logger.LogInformation("Opening RDGOUT for client {ClientIp}", id.GetAttribute(IdentityContext.AttrClientIp));
            tunnel.TransportOut = output;
            await output.SendAcceptAsync(true).ConfigureAwait(false);
            tunnelCache.Set(tunnel.RDGId, tunnel, TimeSpan.FromMinutes(5));
            return;
        }

        if (string.Equals(context.Request.Method, MethodRDGIN, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var input = await LegacyTransport.CreateAsync(context)
                    .ConfigureAwait(false);
                try
                {
                    if (tunnel.TransportIn is null)
                    {
                        tunnel.Id = Guid.NewGuid().ToString();
                        tunnel.TransportIn = input;
                        tunnel.ConnectedOn = DateTimeOffset.UtcNow;
                        tunnelCache.Set(tunnel.RDGId, tunnel, TimeSpan.FromMinutes(5));

                        logger.LogInformation("Opening RDGIN for client {ClientIp}", id.GetAttribute(IdentityContext.AttrClientIp));
                        await input.SendAcceptAsync(false).ConfigureAwait(false);
                        // RDG_IN_DATA sends an initial body segment after the HTTP 200; drain it before packet processing.
                        await input.DrainAsync().ConfigureAwait(false);
                        logger.LogInformation("Legacy handshakeRequest done for client {ClientIp}", id.GetAttribute(IdentityContext.AttrClientIp));

                        try
                        {
                            await ProcessAsync(tunnel, context.RequestAborted);
                        }
                        finally
                        {
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
            }
        }
    }
}
