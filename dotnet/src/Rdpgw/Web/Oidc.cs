using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Rdpgw.Identity;
using Rdpgw.Logging;

namespace Rdpgw.Web;

/// <summary>
/// Configuration needed to create an OpenID Connect authentication helper.
/// </summary>
public sealed class OidcConfig
{
    /// <summary>Gets or sets the provider base URL used for discovery.</summary>
    public string ProviderUrl { get; set; } = string.Empty;
    /// <summary>Gets or sets the registered OIDC client identifier.</summary>
    public string ClientId { get; set; } = string.Empty;
    /// <summary>Gets or sets the registered OIDC client secret.</summary>
    public string ClientSecret { get; set; } = string.Empty;
    /// <summary>Gets or sets the redirect URI registered with the provider.</summary>
    public string RedirectUrl { get; set; } = string.Empty;
    /// <summary>Creates an <see cref="OIDC"/> instance by synchronously completing discovery.</summary>
    /// <returns>A configured OIDC helper.</returns>
    public OIDC New() => OIDC.CreateAsync(this).GetAwaiter().GetResult();
}

/// <summary>
/// Implements the browser OpenID Connect authorization-code flow for the rdpgw web UI.
/// </summary>
public sealed class OIDC
{
    private const string OidcStateKey = "OIDCSTATE";
    private readonly OidcConfig _config;
    private readonly string _authorizationEndpoint;
    private readonly string _tokenEndpoint;
    private readonly string _issuer;
    private readonly ICollection<SecurityKey> _signingKeys;
    private static readonly HttpClient Http = new();
    private readonly ILogger _logger = Log.For<OIDC>();

    private OIDC(OidcConfig config, string authorizationEndpoint, string tokenEndpoint, string issuer, ICollection<SecurityKey> keys)
    { _config = config; _authorizationEndpoint = authorizationEndpoint; _tokenEndpoint = tokenEndpoint; _issuer = issuer; _signingKeys = keys; }

    /// <summary>Discovers provider endpoints and signing keys, then creates an OIDC helper.</summary>
    /// <param name="c">OIDC configuration.</param>
    /// <returns>A configured OIDC helper.</returns>
    public static async Task<OIDC> CreateAsync(OidcConfig c)
    {
        var baseUrl = c.ProviderUrl.TrimEnd('/');
        var doc = await JsonDocument.ParseAsync(await Http.GetStreamAsync(baseUrl + "/.well-known/openid-configuration"));
        var root = doc.RootElement;
        var jwksUri = root.GetProperty("jwks_uri").GetString()!;
        var jwksJson = await Http.GetStringAsync(jwksUri);
        var keys = new JsonWebKeySet(jwksJson).Keys.Cast<SecurityKey>().ToList();
        return new OIDC(c, root.GetProperty("authorization_endpoint").GetString()!, root.GetProperty("token_endpoint").GetString()!, root.GetProperty("issuer").GetString()!, keys);
    }

    /// <summary>Handles the provider redirect, exchanges the authorization code, validates the ID token, and saves the session identity.</summary>
    /// <param name="ctx">Callback request context.</param>
    public async Task HandleCallback(HttpContext ctx)
    {
        var state = ctx.Request.Query["state"].FirstOrDefault() ?? string.Empty;
        if (!GetOidcState(ctx, state, out var redirect)) { _logger.LogWarning("OIDC HandleCallback: unknown state '{State}'", state); ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("unknown state"); return; }
        var code = ctx.Request.Query["code"].FirstOrDefault() ?? string.Empty;
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = _config.RedirectUrl,
            ["client_id"] = _config.ClientId, ["client_secret"] = _config.ClientSecret,
        };
        var response = await Http.PostAsync(_tokenEndpoint, new FormUrlEncodedContent(form));
        if (!response.IsSuccessStatusCode) { ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("Failed to exchange token: " + await response.Content.ReadAsStringAsync()); return; }
        var tokenJson = await response.Content.ReadAsStringAsync();
        using var tokenDoc = JsonDocument.Parse(tokenJson);
        var rawIdToken = tokenDoc.RootElement.TryGetProperty("id_token", out var idp) ? idp.GetString() : null;
        if (string.IsNullOrEmpty(rawIdToken)) { ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("No id_token field in oauth2 token."); return; }
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true, ValidIssuer = _issuer, ValidateAudience = true, ValidAudience = _config.ClientId,
            ValidateLifetime = true, ValidateIssuerSigningKey = true, IssuerSigningKeys = _signingKeys, ClockSkew = TimeSpan.FromMinutes(5)
        };
        // ID token validation pins issuer, audience, lifetime, and the signing key set from discovery.
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(rawIdToken, parameters);
        if (!result.IsValid) { ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("Failed to verify ID Token: " + result.Exception?.Message); return; }
        var claims = result.ClaimsIdentity.Claims.ToDictionary(c => c.Type, c => c.Value);
        var username = FindUsernameInClaims(claims);
        if (string.IsNullOrEmpty(username)) { ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("no oidc claim for username found"); return; }
        var id = IdentityContext.FromContext(ctx) ?? new User();
        id.UserName = username; id.Authenticated = true; id.AuthTime = DateTimeOffset.UtcNow;
        if (tokenDoc.RootElement.TryGetProperty("access_token", out var at)) id.SetAttribute(IdentityContext.AttrAccessToken, at.GetString());
        IdentityContext.AddToContext(ctx, id); Sessions.SaveSessionIdentity(ctx, id);
        if (!redirect.StartsWith("/", StringComparison.Ordinal) || redirect.StartsWith("//", StringComparison.Ordinal))
        {
            // Only local redirects are allowed so a forged state cannot become an open redirect.
            redirect = "/";
        }
        ctx.Response.Redirect(redirect);
    }

    /// <summary>Ensures a web request has an authenticated OIDC session, redirecting to the provider when needed.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    /// <param name="next">Next handler to execute when authenticated.</param>
    public async Task Authenticated(HttpContext ctx, Func<Task> next)
    {
        var id = IdentityContext.FromContext(ctx) ?? new User();
        if (!id.Authenticated)
        {
            var state = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            _logger.LogDebug("OIDC Authenticated: storing state '{State}' for redirect to '{Redirect}'", state, ctx.Request.Path + ctx.Request.QueryString);
            // The state cookie entry pairs CSRF protection with the local URL to resume after callback.
            Sessions.SetValue(ctx, OidcStateKey, state + "|" + ctx.Request.Path + ctx.Request.QueryString, TimeSpan.FromMinutes(2));
            var url = _authorizationEndpoint + "?" + QueryString.Create(new Dictionary<string, string?>
            {
                ["client_id"] = _config.ClientId, ["redirect_uri"] = _config.RedirectUrl, ["response_type"] = "code",
                ["scope"] = "openid profile email", ["state"] = state,
            }).Value!.TrimStart('?');
            ctx.Response.Redirect(url); return;
        }
        await next();
    }

    private static bool GetOidcState(HttpContext ctx, string state, out string redirect)
    {
        redirect = string.Empty;
        if (!Sessions.TryGetValue(ctx, OidcStateKey, out var value)) return false;
        var prefix = state + "|";
        if (!value.StartsWith(prefix, StringComparison.Ordinal)) return false;
        redirect = value[prefix.Length..]; return true;
    }
    private static string FindUsernameInClaims(Dictionary<string, string> data) => new[] { "preferred_username", "unique_name", "upn", "username" }.Select(c => data.TryGetValue(c, out var v) ? v : string.Empty).FirstOrDefault(v => !string.IsNullOrEmpty(v)) ?? string.Empty;
}
