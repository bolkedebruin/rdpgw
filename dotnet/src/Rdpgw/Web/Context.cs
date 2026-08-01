using System.Net;
using Microsoft.AspNetCore.Http;
using Rdpgw.Identity;

namespace Rdpgw.Web;

public static class ContextMiddleware
{
    private static readonly List<IPNetwork> Trusted = [];

    public static void InitTrustedProxies(IEnumerable<string> cidrs)
    {
        Trusted.Clear();
        foreach (var raw in cidrs)
        {
            if (!IPNetwork.TryParse(raw, out var net)) throw new InvalidOperationException($"trustedproxies: invalid CIDR {raw}");
            Trusted.Add(net);
        }
    }

    public static async Task EnrichContext(HttpContext ctx, Func<Task> next)
    {
        var id = Sessions.GetSessionIdentity(ctx) ?? new User();
        if (IdentityContext.FromContext(ctx) is null) IdentityContext.AddToContext(ctx, id);
        Console.WriteLine($"Identity SessionId: {id.SessionId}, UserName: {id.UserName}: Authenticated: {id.Authenticated}");
        var remoteAddr = RemoteAddr(ctx);
        id.SetAttribute(IdentityContext.AttrRemoteAddr, remoteAddr);
        var remoteHost = HostOnly(remoteAddr);
        var clientIp = remoteHost;
        var proxies = new List<string>();
        if (RemoteIsTrustedProxy(remoteAddr) && ctx.Request.Headers.TryGetValue("X-Forwarded-For", out var xff) && !string.IsNullOrWhiteSpace(xff))
        {
            var ips = xff.ToString().Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();
            if (ips.Count > 0) clientIp = ips[0];
            if (ips.Count > 1) proxies = ips.Skip(1).ToList();
        }
        id.SetAttribute(IdentityContext.AttrClientIp, clientIp);
        id.SetAttribute(IdentityContext.AttrProxies, proxies);
        await next();
    }

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

    internal static string RemoteAddr(HttpContext ctx) => ctx.Connection.RemoteIpAddress is null ? string.Empty : $"{ctx.Connection.RemoteIpAddress}:{ctx.Connection.RemotePort}";
    internal static bool RemoteIsTrustedProxy(string remoteAddr)
    {
        if (Trusted.Count == 0) return false;
        if (!IPAddress.TryParse(HostOnly(remoteAddr), out var ip)) return false;
        return Trusted.Any(n => n.Contains(ip));
    }
    internal static string HostOnly(string hostPort) => IPEndPoint.TryParse(hostPort, out var ep) ? ep.Address.ToString() : hostPort.Split(':')[0];
}
