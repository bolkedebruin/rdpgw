using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Rdpgw.Logging;
using Rdpgw.Security;

namespace Rdpgw.Web;

/// <summary>
/// Gateway federation: allows subservient gateways to validate PAA tokens against
/// the primary gateway. The endpoint is secured with a shared key that every bona
/// fide gateway must present as a bearer token.
/// </summary>
public static class GatewayFederation
{
    public const string ValidateEndpoint = "/api/v1/gateway/validate";

    private sealed record ValidateRequest(string? Token);
    private sealed record ValidateResponse(bool Valid, string? Username, string? RemoteServer, string? ClientIp, string? Error);

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true };

    /// <summary>
    /// Endpoint handler run on the primary gateway. Validates the shared key in the
    /// Authorization header (constant-time comparison) and then the submitted PAA token.
    /// </summary>
    public static async Task HandleValidate(HttpContext ctx, byte[] sharedKey)
    {
        if (!IsAuthorized(ctx, sharedKey))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsync("Unauthorized");
            return;
        }
        ValidateRequest? request = null;
        try { request = await JsonSerializer.DeserializeAsync<ValidateRequest>(ctx.Request.Body, JsonOptions); }
        catch (JsonException) { }
        if (string.IsNullOrEmpty(request?.Token))
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsync("missing token");
            return;
        }
        ctx.Response.ContentType = "application/json";
        try
        {
            var info = await Tokens.ValidatePAAToken(request.Token);
            await JsonSerializer.SerializeAsync(ctx.Response.Body, new ValidateResponse(true, info.Username, info.RemoteServer, info.ClientIp, null), JsonOptions);
        }
        catch (Exception ex)
        {
            Log.For(typeof(GatewayFederation)).LogWarning(ex, "gateway federation: token validation failed");
            await JsonSerializer.SerializeAsync(ctx.Response.Body, new ValidateResponse(false, null, null, null, "token validation failed"), JsonOptions);
        }
    }

    private static bool IsAuthorized(HttpContext ctx, byte[] sharedKey)
    {
        var auth = ctx.Request.Headers.Authorization.ToString();
        const string prefix = "Bearer ";
        if (sharedKey.Length == 0 || !auth.StartsWith(prefix, StringComparison.Ordinal)) return false;
        var presented = Encoding.UTF8.GetBytes(auth[prefix.Length..]);
        return CryptographicOperations.FixedTimeEquals(presented, sharedKey);
    }

    /// <summary>
    /// Client used by subservient gateways: validates the PAA token received from an
    /// RDP client by asking the primary gateway, and applies the returned claims to
    /// the connection context on success.
    /// </summary>
    public sealed class RemoteTokenValidator
    {
        private readonly HttpClient _http;
        private readonly Uri _validateUri;
        private readonly ILogger _logger = Log.For<RemoteTokenValidator>();

        public RemoteTokenValidator(Uri primaryGateway, string sharedKey)
        {
            _validateUri = new Uri(primaryGateway, ValidateEndpoint);
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            _http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", sharedKey);
        }

        public async Task<bool> CheckPAACookie(HttpContext context, string tokenString)
        {
            if (string.IsNullOrEmpty(tokenString)) throw new InvalidOperationException("no token to parse");
            using var content = new StringContent(JsonSerializer.Serialize(new ValidateRequest(tokenString), JsonOptions), Encoding.UTF8, "application/json");
            using var response = await _http.PostAsync(_validateUri, content);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("gateway federation: primary gateway returned {StatusCode} for token validation", (int)response.StatusCode);
                return false;
            }
            var result = await JsonSerializer.DeserializeAsync<ValidateResponse>(await response.Content.ReadAsStreamAsync(), JsonOptions);
            if (result is not { Valid: true }) return false;
            Tokens.ApplyPaaTokenInfo(context, new Tokens.PaaTokenInfo(result.Username ?? string.Empty, result.RemoteServer ?? string.Empty, result.ClientIp ?? string.Empty));
            return true;
        }
    }
}
