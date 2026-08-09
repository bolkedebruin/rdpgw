using System.Net;
using Microsoft.AspNetCore.Http;
using Rdpgw.Identity;
using Rdpgw.Logging;

namespace Rdpgw.Web;

public sealed class HeaderAuthConfig
{
    public string UserHeader { get; set; } = string.Empty;
    public string UserIdHeader { get; set; } = string.Empty;
    public string EmailHeader { get; set; } = string.Empty;
    public string DisplayNameHeader { get; set; } = string.Empty;
    public List<string> TrustedProxies { get; set; } = [];
    public HeaderAuth New() => new(this);
}

public sealed class HeaderAuth
{
    private readonly HeaderAuthConfig _c;
    private readonly List<IPNetwork> _trusted = [];
    private readonly ILogger _logger = Log.For<HeaderAuth>();
    public HeaderAuth(HeaderAuthConfig c)
    {
        _c = c;
        foreach (var raw in c.TrustedProxies)
            if (!IPNetwork.TryParse(raw, out var n)) throw new InvalidOperationException($"header auth: invalid TrustedProxies entry {raw}"); else _trusted.Add(n);
        if (_trusted.Count == 0) _logger.LogWarning("header auth: no TrustedProxies configured; every request will be refused");
    }
    public async Task Authenticated(HttpContext ctx, Func<Task> next)
    {
        var id = IdentityContext.FromContext(ctx) ?? new User();
        if (id.Authenticated) { await next(); return; }
        if (!RemoteTrusted(ContextMiddleware.RemoteAddr(ctx))) { _logger.LogWarning("header auth: rejecting request from untrusted remote {RemoteAddr}", ContextMiddleware.RemoteAddr(ctx)); ctx.Response.StatusCode = 401; await ctx.Response.WriteAsync("Untrusted upstream"); return; }
        var user = ctx.Request.Headers[_c.UserHeader].FirstOrDefault();
        if (string.IsNullOrEmpty(user)) { ctx.Response.StatusCode = 401; await ctx.Response.WriteAsync("No authenticated user from proxy"); return; }
        id.UserName = user; id.Authenticated = true; id.AuthTime = DateTimeOffset.UtcNow;
        if (!string.IsNullOrEmpty(_c.UserIdHeader) && ctx.Request.Headers.TryGetValue(_c.UserIdHeader, out var uid)) id.SetAttribute("user_id", uid.ToString());
        if (!string.IsNullOrEmpty(_c.EmailHeader)) id.Email = ctx.Request.Headers[_c.EmailHeader].FirstOrDefault() ?? id.Email;
        if (!string.IsNullOrEmpty(_c.DisplayNameHeader)) id.DisplayName = ctx.Request.Headers[_c.DisplayNameHeader].FirstOrDefault() ?? id.DisplayName;
        IdentityContext.AddToContext(ctx, id); Sessions.SaveSessionIdentity(ctx, id);
        await next();
    }
    private bool RemoteTrusted(string remoteAddr) => _trusted.Count != 0 && IPAddress.TryParse(ContextMiddleware.HostOnly(remoteAddr), out var ip) && _trusted.Any(n => n.Contains(ip));
}
