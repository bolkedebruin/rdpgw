using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Rdpgw.Security;

namespace Rdpgw.Web;

public static class TokenInfoEndpoint
{
    public static async Task TokenInfo(HttpContext ctx)
    {
        if (!HttpMethods.IsGet(ctx.Request.Method)) { ctx.Response.StatusCode = 405; await ctx.Response.WriteAsync("Invalid request"); return; }
        var token = ctx.Request.Query["access_token"].FirstOrDefault();
        if (string.IsNullOrEmpty(token)) { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("access_token missing in request"); return; }
        try
        {
            var info = await Security.Security.UserInfo(ctx, token);
            ctx.Response.ContentType = "application/json; charset=UTF-8";
            await JsonSerializer.SerializeAsync(ctx.Response.Body, info);
        }
        catch (Exception ex) { Console.WriteLine($"Token validation failed due to {ex}"); ctx.Response.StatusCode = 403; await ctx.Response.WriteAsync($"token validation failed due to {ex.Message}"); }
    }
}
