using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Rdpgw.Logging;
using Rdpgw.Security;

namespace Rdpgw.Web;

/// <summary>
/// Implements the token introspection-style endpoint for rdpgw encrypted user tokens.
/// </summary>
public static class TokenInfoEndpoint
{
    /// <summary>Validates the access_token query parameter and returns its claims as JSON.</summary>
    /// <param name="ctx">HTTP request context for the tokeninfo request.</param>
    public static async Task TokenInfo(HttpContext ctx)
    {
        if (!HttpMethods.IsGet(ctx.Request.Method)) { ctx.Response.StatusCode = 405; await ctx.Response.WriteAsync("Invalid request"); return; }
        var token = ctx.Request.Query["access_token"].FirstOrDefault();
        if (string.IsNullOrEmpty(token)) { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("access_token missing in request"); return; }
        try
        {
            // UserInfo performs JWT decryption, optional signature validation, issuer checks, and lifetime checks.
            var info = await Security.Security.UserInfo(ctx, token);
            ctx.Response.ContentType = "application/json; charset=UTF-8";
            await JsonSerializer.SerializeAsync(ctx.Response.Body, info);
        }
        catch (Exception ex) { Log.For(typeof(TokenInfoEndpoint)).LogWarning(ex, "Token validation failed"); ctx.Response.StatusCode = 403; await ctx.Response.WriteAsync($"token validation failed due to {ex.Message}"); }
    }
}
