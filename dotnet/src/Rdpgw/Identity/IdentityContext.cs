using Microsoft.AspNetCore.Http;

namespace Rdpgw.Identity;

public static class IdentityContext
{
    public const string CtxKey = "rdpgw/identity";
    public const string AttrRemoteAddr = "remoteAddr";
    public const string AttrClientIp = "clientIp";
    public const string AttrProxies = "proxyAddresses";
    public const string AttrAccessToken = "accessToken";

    public static void AddToContext(HttpContext ctx, IIdentity id) => ctx.Items[CtxKey] = id;

    public static IIdentity? FromContext(HttpContext ctx) =>
        ctx.Items.TryGetValue(CtxKey, out var value) ? value as IIdentity : null;
}
