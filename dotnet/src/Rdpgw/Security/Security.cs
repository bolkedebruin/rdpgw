using Microsoft.AspNetCore.Http;

namespace Rdpgw.Security;

public static class Security
{
    public static Task<string> GeneratePAAToken(HttpContext context, string username, string server) => Tokens.GeneratePAAToken(context, username, server);
    public static Task<string> GeneratePAAToken(string username, string server) => Tokens.GeneratePAAToken(username, server);
    public static Task<string> GenerateUserToken(HttpContext context, string userName) => Tokens.GenerateUserToken(context, userName);
    public static Task<string> GenerateUserToken(string userName) => Tokens.GenerateUserToken(userName);
    public static Task<bool> CheckPAACookie(HttpContext context, string tokenString) => Tokens.CheckPAACookie(context, tokenString);
    public static Func<HttpContext, string, Task<bool>> CheckSession(Func<HttpContext, string, Task<bool>> next) => Tokens.CheckSession(next);
    public static Task<bool> CheckHost(HttpContext context, string host) => Tokens.CheckHost(context, host);
    public static Task<TokenClaims> UserInfo(HttpContext context, string token) => Tokens.UserInfo(context, token);
    public static Task<TokenClaims> UserInfo(string token) => Tokens.UserInfo(token);
    public static Task<string> QueryInfo(HttpContext context, string tokenString, string issuer) => Tokens.QueryInfo(context, tokenString, issuer);
    public static Task<string> QueryInfo(string tokenString, string issuer) => Tokens.QueryInfo(tokenString, issuer);
    public static Task<string> GenerateQueryToken(string query, string issuer) => Tokens.GenerateQueryToken(query, issuer);
}
