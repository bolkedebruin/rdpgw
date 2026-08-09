using Microsoft.AspNetCore.Http;

namespace Rdpgw.Identity;

/// <summary>
/// Provides helpers and well-known attribute keys for attaching rdpgw identities to the current ASP.NET request.
/// </summary>
public static class IdentityContext
{
    /// <summary>Key used in <see cref="HttpContext.Items"/> to store the current <see cref="IIdentity"/>.</summary>
    public const string CtxKey = "rdpgw/identity";
    /// <summary>Identity attribute containing the TCP peer address seen by Kestrel.</summary>
    public const string AttrRemoteAddr = "remoteAddr";
    /// <summary>Identity attribute containing the resolved end-user client IP address.</summary>
    public const string AttrClientIp = "clientIp";
    /// <summary>Identity attribute containing proxy IP addresses from trusted forwarding headers.</summary>
    public const string AttrProxies = "proxyAddresses";
    /// <summary>Identity attribute containing the OIDC access token when the provider returns one.</summary>
    public const string AttrAccessToken = "accessToken";

    /// <summary>Stores an identity on the current request context.</summary>
    /// <param name="ctx">HTTP context to enrich.</param>
    /// <param name="id">Identity to make available to downstream handlers.</param>
    public static void AddToContext(HttpContext ctx, IIdentity id) => ctx.Items[CtxKey] = id;

    /// <summary>Retrieves the rdpgw identity previously attached to the request.</summary>
    /// <param name="ctx">HTTP context to read.</param>
    /// <returns>The current identity, or <see langword="null"/> when none has been attached.</returns>
    public static IIdentity? FromContext(HttpContext ctx) =>
        ctx.Items.TryGetValue(CtxKey, out var value) ? value as IIdentity : null;
}
