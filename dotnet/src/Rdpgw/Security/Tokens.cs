using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Rdpgw.Identity;

namespace Rdpgw.Security;

/// <summary>
/// Describes the normalized claims returned after validating an rdpgw JWT.
/// </summary>
/// <param name="Subject">Token subject, usually a username or selected host.</param>
/// <param name="Issuer">Issuer that signed or encrypted the token.</param>
/// <param name="ExpiresAt">Expiration time parsed from the token, when present.</param>
/// <param name="Claims">All claims keyed by claim type.</param>
public sealed record TokenClaims(string Subject, string Issuer, DateTimeOffset? ExpiresAt, IReadOnlyDictionary<string, object?> Claims);

/// <summary>
/// Creates and validates rdpgw JWTs used for gateway access, user tokens, and signed host-selection queries.
/// </summary>
public static class Tokens
{
    private const string PaaAudience = "rdpgw-paa";

    /// <summary>
    /// Generates a signed Protected Application Access token for an RDP gateway connection.
    /// </summary>
    /// <param name="context">HTTP request context that may contain client IP metadata.</param>
    /// <param name="username">Authenticated username to place in the subject claim.</param>
    /// <param name="server">Target RDP server authorized by the token.</param>
    /// <returns>A signed compact JWT.</returns>
    public static Task<string> GeneratePAAToken(HttpContext context, string username, string server)
    {
        if (SecurityOptions.SigningKey.Length < 32) throw new InvalidOperationException("token signing key not long enough or not specified");
        var identity = IdentityContext.FromContext(context);
        var clientIp = identity?.GetAttribute(IdentityContext.AttrClientIp)?.ToString() ?? string.Empty;
        // PAA tokens authorize exactly one tunnel target and optionally bind it to the observed client IP.
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Iss] = "rdpgw",
            [JwtRegisteredClaimNames.Sub] = username,
            [JwtRegisteredClaimNames.Aud] = PaaAudience,
            ["remoteServer"] = server,
            ["clientIp"] = clientIp,
        };
        return Task.FromResult(CreateSignedToken(claims, SecurityOptions.SigningKey, SecurityOptions.ExpiryTime));
    }

    /// <summary>
    /// Generates a signed Protected Application Access token without request-specific client IP binding.
    /// </summary>
    /// <param name="username">Authenticated username to place in the subject claim.</param>
    /// <param name="server">Target RDP server authorized by the token.</param>
    /// <returns>A signed compact JWT.</returns>
    public static Task<string> GeneratePAAToken(string username, string server)
    {
        if (SecurityOptions.SigningKey.Length < 32) throw new InvalidOperationException("token signing key not long enough or not specified");
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Iss] = "rdpgw",
            [JwtRegisteredClaimNames.Sub] = username,
            [JwtRegisteredClaimNames.Aud] = PaaAudience,
            ["remoteServer"] = server,
            ["clientIp"] = string.Empty,
        };
        return Task.FromResult(CreateSignedToken(claims, SecurityOptions.SigningKey, SecurityOptions.ExpiryTime));
    }

    /// <summary>
    /// Generates an encrypted user token for embedding in a generated RDP username template.
    /// </summary>
    /// <param name="context">HTTP request context; currently unused but kept for delegate compatibility.</param>
    /// <param name="userName">Username to place in the token subject.</param>
    /// <returns>An encrypted compact JWT.</returns>
    public static Task<string> GenerateUserToken(HttpContext context, string userName) => GenerateUserToken(userName);

    /// <summary>
    /// Generates an encrypted user token for embedding in a generated RDP username template.
    /// </summary>
    /// <param name="userName">Username to place in the token subject.</param>
    /// <returns>An encrypted compact JWT.</returns>
    public static Task<string> GenerateUserToken(string userName)
    {
        if (SecurityOptions.UserEncryptionKey.Length < 32) throw new InvalidOperationException("user token encryption key not long enough or not specified");
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Sub, userName)]),
            Issuer = "rdpgw",
            Expires = DateTime.UtcNow.Add(SecurityOptions.ExpiryTime),
            EncryptingCredentials = EncryptingCredentials(SecurityOptions.UserEncryptionKey),
        };
        if (SecurityOptions.UserSigningKey.Length > 0)
        {
            descriptor.SigningCredentials = SigningCredentials(SecurityOptions.UserSigningKey);
        }
        var token = new JsonWebTokenHandler().CreateToken(descriptor);
        // Windows username fields are small; warn when a tokenized username may exceed RDP client limits.
        if (token.Length > 511) Rdpgw.Logging.Log.For(typeof(Tokens)).LogWarning("token too long: len {Length} > 511", token.Length);
        return Task.FromResult(token);
    }

    /// <summary>
    /// Validates a user token and returns normalized claims.
    /// </summary>
    /// <param name="context">HTTP request context; currently unused but kept for delegate compatibility.</param>
    /// <param name="token">Encrypted user token.</param>
    /// <returns>Validated token claims.</returns>
    public static Task<TokenClaims> UserInfo(HttpContext context, string token) => UserInfo(token);

    /// <summary>
    /// Validates a user token and returns normalized claims.
    /// </summary>
    /// <param name="token">Encrypted user token.</param>
    /// <returns>Validated token claims.</returns>
    /// <exception cref="SecurityTokenException">Thrown when token validation fails.</exception>
    public static Task<TokenClaims> UserInfo(string token)
    {
        var parameters = ValidationParameters(SecurityOptions.UserSigningKey.Length > 0 ? SecurityOptions.UserSigningKey : null, SecurityOptions.UserEncryptionKey, "rdpgw", null);
        var result = new JsonWebTokenHandler().ValidateTokenAsync(token, parameters).GetAwaiter().GetResult();
        if (!result.IsValid) throw new SecurityTokenException($"token validation failed due to {result.Exception?.Message}", result.Exception);
        return Task.FromResult(ToTokenClaims(result.ClaimsIdentity.Claims));
    }

    /// <summary>
    /// Claims extracted from a validated Protected Application Access token.
    /// </summary>
    /// <param name="Username">Authenticated username from the token subject.</param>
    /// <param name="RemoteServer">Target server authorized by the token.</param>
    /// <param name="ClientIp">Client IP bound into the token, or an empty string.</param>
    public sealed record PaaTokenInfo(string Username, string RemoteServer, string ClientIp);

    /// <summary>
    /// Validates a PAA token and returns its claims. Shared by the local gateway
    /// cookie check and the gateway federation validation endpoint.
    /// </summary>
    /// <param name="tokenString">Signed PAA token string.</param>
    /// <returns>The token claims required by the gateway protocol checks.</returns>
    /// <exception cref="SecurityTokenException">Thrown when token validation fails.</exception>
    public static async Task<PaaTokenInfo> ValidatePAAToken(string tokenString)
    {
        if (string.IsNullOrEmpty(tokenString)) throw new InvalidOperationException("no token to parse");
        var parameters = ValidationParameters(SecurityOptions.SigningKey, null, "rdpgw", PaaAudience);
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(tokenString, parameters);
        if (!result.IsValid) throw new SecurityTokenException($"token validation failed due to {result.Exception?.Message}", result.Exception);
        var claims = result.ClaimsIdentity.Claims.ToDictionary(c => c.Type, c => c.Value);
        // Different token handlers may expose JWT registered names or claim-type URIs; accept both forms.
        return new PaaTokenInfo(Claim(claims, JwtRegisteredClaimNames.Sub, ClaimTypes.NameIdentifier, "sub"), Claim(claims, "remoteServer"), Claim(claims, "clientIp"));
    }

    /// <summary>
    /// Validates a PAA cookie value and stores its authorization claims on the current request.
    /// </summary>
    /// <param name="context">Gateway request context.</param>
    /// <param name="tokenString">PAA token string from the gateway cookie.</param>
    /// <returns><see langword="true"/> when validation succeeds.</returns>
    public static async Task<bool> CheckPAACookie(HttpContext context, string tokenString)
    {
        var info = await ValidatePAAToken(tokenString);
        ApplyPaaTokenInfo(context, info);
        return true;
    }

    /// <summary>
    /// Stores the validated token claims in the request context so that the tunnel
    /// can later verify the target host and client IP.
    /// </summary>
    /// <param name="context">Request context to update.</param>
    /// <param name="info">Validated PAA token claims.</param>
    public static void ApplyPaaTokenInfo(HttpContext context, PaaTokenInfo info)
    {
        context.Items[SecurityOptions.TunnelTargetServerKey] = info.RemoteServer;
        context.Items[SecurityOptions.TunnelRemoteAddrKey] = info.ClientIp;
        var id = IdentityContext.FromContext(context);
        if (id is not null) id.UserName = info.Username;
    }

    /// <summary>
    /// Composes host authorization with PAA tunnel-target and optional client-IP verification.
    /// </summary>
    /// <param name="next">Host checker to invoke after session-token claims are verified.</param>
    /// <returns>A host checker that rejects mismatched token targets or client IPs.</returns>
    public static Func<HttpContext, string, Task<bool>> CheckSession(Func<HttpContext, string, Task<bool>> next) => async (context, host) =>
    {
        var tokenHost = context.Items[SecurityOptions.TunnelTargetServerKey]?.ToString();
        if (string.IsNullOrEmpty(tokenHost)) throw new InvalidOperationException("no valid session info found in context");
        if (tokenHost != host) return false;
        var id = IdentityContext.FromContext(context);
        if (SecurityOptions.VerifyClientIP && id is not null)
        {
            var current = id.GetAttribute(IdentityContext.AttrClientIp)?.ToString();
            var tokenIp = context.Items[SecurityOptions.TunnelRemoteAddrKey]?.ToString();
            // Binding the PAA token to the client IP makes stolen gateway cookies less useful.
            if (current != tokenIp) return false;
        }
        return await next(context, host);
    };

    /// <summary>
    /// Checks whether the selected host is allowed by the configured host-selection mode.
    /// </summary>
    /// <param name="context">Request context containing the current identity.</param>
    /// <param name="host">Requested RDP destination host.</param>
    /// <returns><see langword="true"/> when the host is permitted.</returns>
    public static Task<bool> CheckHost(HttpContext context, string host)
    {
        switch (SecurityOptions.HostSelection)
        {
            case "any": return Task.FromResult(true);
            case "signed": throw new InvalidOperationException("cannot verify host in 'signed' mode as token data is missing");
            case "roundrobin":
            case "unsigned":
                var user = IdentityContext.FromContext(context)?.UserName ?? string.Empty;
                if (string.IsNullOrEmpty(user)) throw new InvalidOperationException("no valid session info or username found in context");
                return Task.FromResult(SecurityOptions.HostsProvider(user).Any(h => h.Replace("{{ preferred_username }}", user, StringComparison.Ordinal) == host));
            default:
                throw new InvalidOperationException("unrecognized host selection criteria");
        }
    }

    /// <summary>
    /// Validates a signed query token and returns the subject claim.
    /// </summary>
    /// <param name="context">HTTP request context; currently unused but kept for delegate compatibility.</param>
    /// <param name="tokenString">Signed query token.</param>
    /// <param name="issuer">Expected issuer.</param>
    /// <returns>The query token subject.</returns>
    public static Task<string> QueryInfo(HttpContext context, string tokenString, string issuer) => QueryInfo(tokenString, issuer);

    /// <summary>
    /// Validates a signed query token and returns the subject claim.
    /// </summary>
    /// <param name="tokenString">Signed query token.</param>
    /// <param name="issuer">Expected issuer.</param>
    /// <returns>The query token subject.</returns>
    public static Task<string> QueryInfo(string tokenString, string issuer)
    {
        var parameters = ValidationParameters(SecurityOptions.QuerySigningKey, null, issuer, null);
        var result = new JsonWebTokenHandler().ValidateTokenAsync(tokenString, parameters).GetAwaiter().GetResult();
        if (!result.IsValid) throw new SecurityTokenException($"token validation failed due to {result.Exception?.Message}", result.Exception);
        return Task.FromResult(result.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? result.ClaimsIdentity.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty);
    }

    /// <summary>
    /// Generates a signed query token used by signed host-selection links.
    /// </summary>
    /// <param name="query">Value to place in the subject claim.</param>
    /// <param name="issuer">Issuer to place in the token.</param>
    /// <returns>A signed compact JWT.</returns>
    public static Task<string> GenerateQueryToken(string query, string issuer)
    {
        if (SecurityOptions.QuerySigningKey.Length < 32) throw new InvalidOperationException("query token encryption key not long enough or not specified");
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Iss] = issuer,
            [JwtRegisteredClaimNames.Sub] = query,
        };
        return Task.FromResult(CreateSignedToken(claims, SecurityOptions.QuerySigningKey, SecurityOptions.ExpiryTime));
    }

    private static string CreateSignedToken(Dictionary<string, object> claims, byte[] key, TimeSpan lifetime)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            Expires = DateTime.UtcNow.Add(lifetime),
            SigningCredentials = SigningCredentials(key),
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static SigningCredentials SigningCredentials(byte[] key) => new(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
    private static EncryptingCredentials EncryptingCredentials(byte[] key) => new(new SymmetricSecurityKey(key), "dir", SecurityAlgorithms.Aes128CbcHmacSha256);

    private static TokenValidationParameters ValidationParameters(byte[]? signingKey, byte[]? encryptionKey, string issuer, string? audience)
    {
        var p = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = audience is not null,
            ValidAudience = audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = signingKey is not null,
            RequireSignedTokens = signingKey is not null,
            ClockSkew = TimeSpan.Zero,
            ValidAlgorithms = signingKey is null ? null : [SecurityAlgorithms.HmacSha256],
        };
        if (signingKey is not null) p.IssuerSigningKey = new SymmetricSecurityKey(signingKey);
        if (encryptionKey is not null) p.TokenDecryptionKey = new SymmetricSecurityKey(encryptionKey);
        return p;
    }

    private static TokenClaims ToTokenClaims(IEnumerable<Claim> claims)
    {
        var dict = claims.GroupBy(c => c.Type).ToDictionary(g => g.Key, g => (object?)g.Last().Value);
        var sub = Claim(dict, JwtRegisteredClaimNames.Sub, ClaimTypes.NameIdentifier, "sub");
        var iss = Claim(dict, JwtRegisteredClaimNames.Iss, "iss");
        DateTimeOffset? exp = null;
        if (long.TryParse(Claim(dict, JwtRegisteredClaimNames.Exp, "exp"), out var seconds)) exp = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return new TokenClaims(sub, iss, exp, dict);
    }

    private static string Claim(IReadOnlyDictionary<string, string> claims, params string[] names) => names.Select(n => claims.TryGetValue(n, out var v) ? v : null).FirstOrDefault(v => v is not null) ?? string.Empty;
    private static string Claim(IReadOnlyDictionary<string, object?> claims, params string[] names) => names.Select(n => claims.TryGetValue(n, out var v) ? v?.ToString() : null).FirstOrDefault(v => v is not null) ?? string.Empty;
}
