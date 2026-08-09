using Microsoft.AspNetCore.Http;

namespace Rdpgw.Security;

/// <summary>
/// Compatibility facade that exposes rdpgw security operations while delegating implementation to <see cref="Tokens"/>.
/// </summary>
public static class Security
{
    /// <summary>Generates a PAA token for a username and target server, binding client metadata from the current context.</summary>
    /// <param name="context">Current request context.</param>
    /// <param name="username">Authenticated username.</param>
    /// <param name="server">Target RDP server.</param>
    /// <returns>A signed PAA token.</returns>
    public static Task<string> GeneratePAAToken(HttpContext context, string username, string server) => Tokens.GeneratePAAToken(context, username, server);
    /// <summary>Generates a PAA token without request-specific client metadata.</summary>
    /// <param name="username">Authenticated username.</param>
    /// <param name="server">Target RDP server.</param>
    /// <returns>A signed PAA token.</returns>
    public static Task<string> GeneratePAAToken(string username, string server) => Tokens.GeneratePAAToken(username, server);
    /// <summary>Generates an encrypted user token for use inside an RDP username template.</summary>
    /// <param name="context">Current request context.</param>
    /// <param name="userName">Authenticated username.</param>
    /// <returns>An encrypted user token.</returns>
    public static Task<string> GenerateUserToken(HttpContext context, string userName) => Tokens.GenerateUserToken(context, userName);
    /// <summary>Generates an encrypted user token without request-specific metadata.</summary>
    /// <param name="userName">Authenticated username.</param>
    /// <returns>An encrypted user token.</returns>
    public static Task<string> GenerateUserToken(string userName) => Tokens.GenerateUserToken(userName);
    /// <summary>Validates a PAA cookie token and stores its claims on the request context.</summary>
    /// <param name="context">Current gateway request context.</param>
    /// <param name="tokenString">PAA token string from the gateway cookie.</param>
    /// <returns><see langword="true"/> when validation succeeds.</returns>
    public static Task<bool> CheckPAACookie(HttpContext context, string tokenString) => Tokens.CheckPAACookie(context, tokenString);
    /// <summary>Wraps a host checker with token target and optional client-IP validation.</summary>
    /// <param name="next">Checker to run after session-token claims are verified.</param>
    /// <returns>A composed host checker.</returns>
    public static Func<HttpContext, string, Task<bool>> CheckSession(Func<HttpContext, string, Task<bool>> next) => Tokens.CheckSession(next);
    /// <summary>Checks whether a host is permitted for the authenticated user and configured host-selection mode.</summary>
    /// <param name="context">Current request context.</param>
    /// <param name="host">Requested host address.</param>
    /// <returns><see langword="true"/> when the host is permitted.</returns>
    public static Task<bool> CheckHost(HttpContext context, string host) => Tokens.CheckHost(context, host);
    /// <summary>Validates a user token and returns its claims.</summary>
    /// <param name="context">Current request context.</param>
    /// <param name="token">Encrypted user token.</param>
    /// <returns>Validated token claims.</returns>
    public static Task<TokenClaims> UserInfo(HttpContext context, string token) => Tokens.UserInfo(context, token);
    /// <summary>Validates a user token and returns its claims.</summary>
    /// <param name="token">Encrypted user token.</param>
    /// <returns>Validated token claims.</returns>
    public static Task<TokenClaims> UserInfo(string token) => Tokens.UserInfo(token);
    /// <summary>Validates a signed host-selection query token and returns its subject.</summary>
    /// <param name="context">Current request context.</param>
    /// <param name="tokenString">Signed query token.</param>
    /// <param name="issuer">Expected token issuer.</param>
    /// <returns>The host/query subject from the token.</returns>
    public static Task<string> QueryInfo(HttpContext context, string tokenString, string issuer) => Tokens.QueryInfo(context, tokenString, issuer);
    /// <summary>Validates a signed host-selection query token and returns its subject.</summary>
    /// <param name="tokenString">Signed query token.</param>
    /// <param name="issuer">Expected token issuer.</param>
    /// <returns>The host/query subject from the token.</returns>
    public static Task<string> QueryInfo(string tokenString, string issuer) => Tokens.QueryInfo(tokenString, issuer);
    /// <summary>Generates a signed host-selection query token.</summary>
    /// <param name="query">Host or query value to place in the subject claim.</param>
    /// <param name="issuer">Issuer claim to embed.</param>
    /// <returns>A signed query token.</returns>
    public static Task<string> GenerateQueryToken(string query, string issuer) => Tokens.GenerateQueryToken(query, issuer);
}
