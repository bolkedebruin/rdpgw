namespace Rdpgw.Security;

public interface ITokenService
{
	void ApplyPaaTokenInfo(HttpContext context, TokenService.PaaTokenInfo info);
	Task<bool> CheckPAACookie(HttpContext context, string tokenString);
	Func<HttpContext, string, Task<bool>> CheckSession(Func<HttpContext, string, Task<bool>> next);
	Task<string> GeneratePAAToken(string clientIp, string username, string server);
	Task<string> GeneratePAAToken(string username, string server);
	Task<string> GenerateQueryToken(string query, string issuer);
	Task<string> QueryInfo(HttpContext context, string tokenString, string issuer);
	Task<string> QueryInfo(string tokenString, string issuer);
	Task<TokenClaims> UserInfo(HttpContext context, string token);
	Task<TokenClaims> UserInfo(string token);
	Task<TokenService.PaaTokenInfo> ValidatePAAToken(string tokenString);
}