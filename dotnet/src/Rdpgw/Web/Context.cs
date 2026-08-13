using System.Net;
using Rdpgw.Identity;

namespace Rdpgw.Web;

/// <summary>
/// Middleware helpers that attach identity and network metadata to each request context.
/// </summary>
public sealed class ContextMiddleware(ILogger<ContextMiddleware> logger)
{
    private static readonly List<IPNetwork> Trusted = [];

    /// <summary>Initializes the CIDR ranges trusted for forwarding client IP headers.</summary>
    /// <param name="cidrs">CIDR strings from configuration.</param>
    public static void InitTrustedProxies(IEnumerable<string> cidrs)
    {
        Trusted.Clear();
        foreach (var raw in cidrs)
        {
            if (!IPNetwork.TryParse(raw, out var net)) throw new InvalidOperationException($"trustedproxies: invalid CIDR {raw}");
            Trusted.Add(net);
        }
    }

    /// <summary>Loads or creates the rdpgw identity and adds client/proxy address attributes before downstream middleware runs.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    /// <param name="next">Next middleware delegate.</param>
    public async Task EnrichContext(HttpContext ctx, Func<Task> next)
    {
        var id = Sessions.GetSessionIdentity(ctx) ?? new User();
        if (IdentityContext.FromContext(ctx) is null) IdentityContext.AddToContext(ctx, id);
        logger.LogDebug("Identity SessionId: {SessionId}, UserName: {UserName}: Authenticated: {Authenticated}", id.SessionId, id.UserName, id.Authenticated);
        var remoteAddr = RemoteAddr(ctx);
        id.SetAttribute(IdentityContext.AttrRemoteAddr, remoteAddr);
        var remoteHost = HostOnly(remoteAddr);
        var clientIp = remoteHost;
        var proxies = new List<string>();
        if (RemoteIsTrustedProxy(remoteAddr) && ctx.Request.Headers.TryGetValue("X-Forwarded-For", out var xff) && !string.IsNullOrWhiteSpace(xff))
        {
            // Only trusted proxies may influence the end-user address; the first XFF value is the original client.
            var ips = xff.ToString().Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();
            if (ips.Count > 0) clientIp = ips[0];
            if (ips.Count > 1) proxies = ips.Skip(1).ToList();
        }
        id.SetAttribute(IdentityContext.AttrClientIp, clientIp);
        id.SetAttribute(IdentityContext.AttrProxies, proxies);
        await next();
    }

    /// <summary>Copies a successful ASP.NET Negotiate authentication result into the rdpgw identity.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    /// <param name="next">Next handler to run after identity transposition.</param>
    public static async Task TransposeSPNEGOContext(HttpContext ctx, Func<Task> next)
    {
        if (ctx.User?.Identity?.IsAuthenticated == true)
        {
            var id = IdentityContext.FromContext(ctx) ?? new User();
            id.UserName = ctx.User.Identity.Name ?? string.Empty;
            id.Authenticated = true;
            id.AuthTime = DateTimeOffset.UtcNow;
            IdentityContext.AddToContext(ctx, id);
        }
        await next();
    }

    /// <summary>Formats Kestrel's remote endpoint as host:port, preserving IPv6 bracket notation.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    /// <returns>The remote endpoint string, or an empty string when unavailable.</returns>
    internal static string RemoteAddr(HttpContext ctx)
    {
        var ip = ctx.Connection.RemoteIpAddress;
        if (ip is null) return string.Empty;
        return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{ip}]:{ctx.Connection.RemotePort}" : $"{ip}:{ctx.Connection.RemotePort}";
    }
    /// <summary>Determines whether a formatted remote endpoint is inside a trusted proxy range.</summary>
    /// <param name="remoteAddr">Remote endpoint in host:port form.</param>
    /// <returns><see langword="true"/> when the endpoint is trusted to supply forwarding headers.</returns>
    internal static bool RemoteIsTrustedProxy(string remoteAddr)
    {
        if (Trusted.Count == 0) return false;
        if (!IPAddress.TryParse(HostOnly(remoteAddr), out var ip)) return false;
        return Trusted.Any(n => n.Contains(ip));
    }
    /// <summary>Extracts the host portion from a host:port or bracketed IPv6 endpoint.</summary>
    /// <param name="hostPort">Endpoint string to parse.</param>
    /// <returns>The host/IP portion when parsing succeeds, otherwise the text before the first colon.</returns>
    internal static string HostOnly(string hostPort) => IPEndPoint.TryParse(hostPort, out var ep) ? ep.Address.ToString() : hostPort.Split(':')[0];
}
