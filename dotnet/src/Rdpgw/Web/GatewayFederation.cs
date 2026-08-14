using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Rdpgw.Security;

namespace Rdpgw.Web;

/// <summary>
/// Gateway federation: allows subservient gateways to validate PAA tokens against
/// the primary gateway. The endpoint is secured with a shared key that every bona
/// fide gateway must present as a bearer token.
/// </summary>
public sealed class GatewayFederation(ILogger<GatewayFederation> logger, ITokenService tokenService)
{
    /// <summary>HTTP endpoint path exposed by a primary gateway for remote PAA token validation.</summary>
    public const string ValidateEndpoint = "/api/v1/gateway/validate";

    /// <summary>Request body sent by a subservient gateway to validate a PAA token.</summary>
    /// <param name="Token">PAA token received from the RDP client.</param>
    private sealed record ValidateRequest(string? Token);
    /// <summary>Response body returned by the primary gateway after PAA token validation.</summary>
    /// <param name="Valid">Indicates whether the token was valid.</param>
    /// <param name="Username">Authenticated username from the token.</param>
    /// <param name="RemoteServer">Authorized target server from the token.</param>
    /// <param name="ClientIp">Client IP bound into the token.</param>
    /// <param name="Error">Validation error description safe for the caller.</param>
    private sealed record ValidateResponse(bool Valid, string? Username, string? RemoteServer, string? ClientIp, string? Error);

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true };

    /// <summary>
    /// Endpoint handler run on the primary gateway. Validates the shared key in the
    /// Authorization header (constant-time comparison) and then the submitted PAA token.
    /// </summary>
    /// <param name="ctx">HTTP request context for the validation request.</param>
    /// <param name="sharedKey">UTF-8 bytes of the shared bearer key configured on all gateways.</param>
    public async Task HandleValidate(HttpContext ctx, byte[] sharedKey)
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
            // The primary owns token validation because it minted the PAA signing key in federation mode.
            var info = await tokenService.ValidatePAAToken(request.Token);
            await JsonSerializer.SerializeAsync(ctx.Response.Body, new ValidateResponse(true, info.Username, info.RemoteServer, info.ClientIp, null), JsonOptions);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "gateway federation: token validation failed");
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
        private readonly ILogger<RemoteTokenValidator> _logger;
        private readonly ITokenService _tokenService;

        /// <summary>Initializes a validator that calls the configured primary gateway.</summary>
        /// <param name="primaryGateway">Base URL of the primary gateway.</param>
        /// <param name="sharedKey">Shared bearer key used to authenticate federation calls.</param>
        /// <param name="logger">Logger instance.</param>
        /// <param name="tokenService">Token service used to apply validated PAA claims to the request context.</param>
        public RemoteTokenValidator(Uri primaryGateway, string sharedKey, ILogger<RemoteTokenValidator> logger, ITokenService tokenService)
        {
            _validateUri = new Uri(primaryGateway, ValidateEndpoint);
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            _http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", sharedKey);
            _logger = logger;
            _tokenService = tokenService;
        }

        /// <summary>Validates a PAA token remotely and applies returned claims to the request context.</summary>
        /// <param name="context">Gateway request context to update.</param>
        /// <param name="tokenString">PAA token received from the client cookie.</param>
        /// <returns><see langword="true"/> when the primary gateway accepts the token.</returns>
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
            _tokenService.ApplyPaaTokenInfo(context, new TokenService.PaaTokenInfo(result.Username ?? string.Empty, result.RemoteServer ?? string.Empty, result.ClientIp ?? string.Empty));
            return true;
        }
    }
}
