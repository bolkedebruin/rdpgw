using System.Net;
using Microsoft.AspNetCore.Http;
using Rdpgw.Identity;
using Rdpgw.Logging;

namespace Rdpgw.Web;

/// <summary>
/// Configuration for trusted reverse-proxy header authentication.
/// </summary>
public sealed class HeaderAuthConfig
{
    /// <summary>Gets or sets the required header containing the authenticated username.</summary>
    public string UserHeader { get; set; } = string.Empty;
    /// <summary>Gets or sets the optional header containing a stable user identifier.</summary>
    public string UserIdHeader { get; set; } = string.Empty;
    /// <summary>Gets or sets the optional header containing the user's email address.</summary>
    public string EmailHeader { get; set; } = string.Empty;
    /// <summary>Gets or sets the optional header containing the user's display name.</summary>
    public string DisplayNameHeader { get; set; } = string.Empty;
    /// <summary>Gets or sets CIDR ranges trusted to assert the configured identity headers.</summary>
    public List<string> TrustedProxies { get; set; } = [];
    /// <summary>Creates a header-authentication middleware helper from this configuration.</summary>
    /// <returns>A configured <see cref="HeaderAuth"/> instance.</returns>
    public HeaderAuth New() => new(this);
}

/// <summary>
/// Authenticates requests by accepting identity headers only from explicitly trusted upstream proxies.
/// </summary>
public sealed class HeaderAuth
{
    private readonly HeaderAuthConfig _c;
    private readonly List<IPNetwork> _trusted = [];
    private readonly ILogger _logger = Log.For<HeaderAuth>();
    /// <summary>Initializes header authentication and parses trusted proxy CIDR ranges.</summary>
    /// <param name="c">Header authentication configuration.</param>
    public HeaderAuth(HeaderAuthConfig c)
    {
        _c = c;
        foreach (var raw in c.TrustedProxies)
            if (!IPNetwork.TryParse(raw, out var n)) throw new InvalidOperationException($"header auth: invalid TrustedProxies entry {raw}"); else _trusted.Add(n);
        if (_trusted.Count == 0) _logger.LogWarning("header auth: no TrustedProxies configured; every request will be refused");
    }
    /// <summary>Ensures the current request has an authenticated identity, deriving it from trusted proxy headers when needed.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    /// <param name="next">Next handler to run after authentication.</param>
    public async Task Authenticated(HttpContext ctx, Func<Task> next)
    {
        var id = IdentityContext.FromContext(ctx) ?? new User();
        if (id.Authenticated) { await next(); return; }
        // Header identity is only safe when the direct peer is a configured trusted proxy.
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
