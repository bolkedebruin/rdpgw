using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Rdpgw.Identity;

namespace Rdpgw.Security;

public sealed record TokenClaims(string Subject, string Issuer, DateTimeOffset? ExpiresAt, IReadOnlyDictionary<string, object?> Claims);

public static class Tokens
{
    private const string PaaAudience = "rdpgw-paa";

    public static Task<string> GeneratePAAToken(HttpContext context, string username, string server)
    {
        if (SecurityOptions.SigningKey.Length < 32) throw new InvalidOperationException("token signing key not long enough or not specified");
        var identity = IdentityContext.FromContext(context);
        var clientIp = identity?.GetAttribute(IdentityContext.AttrClientIp)?.ToString() ?? string.Empty;
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

    public static Task<string> GenerateUserToken(HttpContext context, string userName) => GenerateUserToken(userName);

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
        if (token.Length > 511) Console.Error.WriteLine($"WARNING: token too long: len {token.Length} > 511");
        return Task.FromResult(token);
    }

    public static Task<TokenClaims> UserInfo(HttpContext context, string token) => UserInfo(token);

    public static Task<TokenClaims> UserInfo(string token)
    {
        var parameters = ValidationParameters(SecurityOptions.UserSigningKey.Length > 0 ? SecurityOptions.UserSigningKey : null, SecurityOptions.UserEncryptionKey, "rdpgw", null);
        var result = new JsonWebTokenHandler().ValidateTokenAsync(token, parameters).GetAwaiter().GetResult();
        if (!result.IsValid) throw new SecurityTokenException($"token validation failed due to {result.Exception?.Message}", result.Exception);
        return Task.FromResult(ToTokenClaims(result.ClaimsIdentity.Claims));
    }

    public static async Task<bool> CheckPAACookie(HttpContext context, string tokenString)
    {
        if (string.IsNullOrEmpty(tokenString)) throw new InvalidOperationException("no token to parse");
        var parameters = ValidationParameters(SecurityOptions.SigningKey, null, "rdpgw", PaaAudience);
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(tokenString, parameters);
        if (!result.IsValid) throw new SecurityTokenException($"token validation failed due to {result.Exception?.Message}", result.Exception);
        var claims = result.ClaimsIdentity.Claims.ToDictionary(c => c.Type, c => c.Value);
        context.Items[SecurityOptions.TunnelTargetServerKey] = Claim(claims, "remoteServer");
        context.Items[SecurityOptions.TunnelRemoteAddrKey] = Claim(claims, "clientIp");
        var id = IdentityContext.FromContext(context);
        if (id is not null) id.UserName = Claim(claims, JwtRegisteredClaimNames.Sub, ClaimTypes.NameIdentifier, "sub");
        return true;
    }

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
            if (current != tokenIp) return false;
        }
        return await next(context, host);
    };

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
                return Task.FromResult(SecurityOptions.HostsProvider().Any(h => h.Replace("{{ preferred_username }}", user, StringComparison.Ordinal) == host));
            default:
                throw new InvalidOperationException("unrecognized host selection criteria");
        }
    }

    public static Task<string> QueryInfo(HttpContext context, string tokenString, string issuer) => QueryInfo(tokenString, issuer);

    public static Task<string> QueryInfo(string tokenString, string issuer)
    {
        var parameters = ValidationParameters(SecurityOptions.QuerySigningKey, null, issuer, null);
        var result = new JsonWebTokenHandler().ValidateTokenAsync(tokenString, parameters).GetAwaiter().GetResult();
        if (!result.IsValid) throw new SecurityTokenException($"token validation failed due to {result.Exception?.Message}", result.Exception);
        return Task.FromResult(result.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? result.ClaimsIdentity.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty);
    }

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
