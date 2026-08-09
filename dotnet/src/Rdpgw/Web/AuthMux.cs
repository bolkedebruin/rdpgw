using Microsoft.AspNetCore.Http;

namespace Rdpgw.Web;

/// <summary>
/// Collects authentication challenges from enabled gateway authentication mechanisms and writes a combined 401 response.
/// </summary>
public sealed class AuthMux
{
    private readonly List<(string Header, Func<HttpContext, bool>? Condition)> _headers = [];
    /// <summary>Registers one or more WWW-Authenticate header values.</summary>
    /// <param name="headers">Challenge header values to offer.</param>
    /// <param name="condition">Optional request predicate controlling whether the headers apply.</param>
    public void Register(IEnumerable<string> headers, Func<HttpContext, bool>? condition) { foreach (var h in headers) _headers.Add((h, condition)); }
    /// <summary>Writes all applicable authentication challenges and a standard unauthorized body.</summary>
    /// <param name="ctx">Request context receiving the 401 response.</param>
    public async Task SetAuthenticate(HttpContext ctx)
    {
        // Multiple challenges let RDP clients choose between Basic, NTLM, and SPNEGO as configured.
        foreach (var h in _headers.Where(h => h.Condition is null || h.Condition(ctx))) ctx.Response.Headers.Append("WWW-Authenticate", h.Header);
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await ctx.Response.WriteAsync("Unauthorized");
    }
    /// <summary>Returns whether the request lacks an Authorization header.</summary>
    /// <param name="ctx">Request context to inspect.</param>
    /// <returns><see langword="true"/> when no authorization header is present.</returns>
    public static bool NoAuthz(HttpContext ctx) => string.IsNullOrEmpty(ctx.Request.Headers.Authorization);
}
