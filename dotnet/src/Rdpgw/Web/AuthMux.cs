using Microsoft.AspNetCore.Http;

namespace Rdpgw.Web;

public sealed class AuthMux
{
    private readonly List<(string Header, Func<HttpContext, bool>? Condition)> _headers = [];
    public void Register(IEnumerable<string> headers, Func<HttpContext, bool>? condition) { foreach (var h in headers) _headers.Add((h, condition)); }
    public async Task SetAuthenticate(HttpContext ctx)
    {
        foreach (var h in _headers.Where(h => h.Condition is null || h.Condition(ctx))) ctx.Response.Headers.Append("WWW-Authenticate", h.Header);
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await ctx.Response.WriteAsync("Unauthorized");
    }
    public static bool NoAuthz(HttpContext ctx) => string.IsNullOrEmpty(ctx.Request.Headers.Authorization);
}
