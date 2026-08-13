using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Rdpgw.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Encodings.Web;

namespace Rdpgw.Security.GatewayToken;

public sealed class GatewayTokenAuthenticationHandler(
	ILogger<GatewayTokenAuthenticationHandler> logger,
	IOptionsMonitor<AuthenticationSchemeOptions> options,
	ILoggerFactory loggerFactory,
	UrlEncoder encoder,
	RdpgwDbContext dbContext) : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
	protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
	{
		// 1. Get the Authorization header.
		if (!Request.Headers.TryGetValue("Authorization", out var authorization))
		{
			logger.LogError("Missing Authorization header.");
			return AuthenticateResult.NoResult();
		}

		var authorizationValue = authorization.ToString();
		if (!authorizationValue.StartsWith(
				"Bearer ",
				StringComparison.OrdinalIgnoreCase))
		{
			logger.LogError("Authorization header does not start with 'Bearer '.");
			return AuthenticateResult.NoResult();
		}

		var token = authorizationValue["Bearer ".Length..].Trim();

		if (string.IsNullOrWhiteSpace(token))
		{
			logger.LogError("Missing bearer token.");
			return AuthenticateResult.Fail("Missing bearer token.");
		}

		// 2. Parse the JWT WITHOUT validating it.
		//
		// At this point the token is completely untrusted.
		// We are only using the claims to determine which key
		// we should try.
		JwtSecurityToken untrustedToken;
		try
		{
			var handler = new JwtSecurityTokenHandler();
			untrustedToken = handler.ReadJwtToken(token);
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "Unable to parse bearer token.");
			return AuthenticateResult.Fail("Invalid bearer token.");
		}

		// 3. Extract the host identifier.
		var gatewayName = untrustedToken.Claims
			.FirstOrDefault(c => c.Type == "gatewayHostName")
			?.Value;

		if (string.IsNullOrWhiteSpace(gatewayName))
		{
			logger.LogError("Bearer token does not contain a gatewayHostName claim.");
			return AuthenticateResult.Fail(
				"Bearer token does not contain a gatewayHostName claim.");
		}

		// 4. Look up the host and its signing key.
		var host = await dbContext.Gateways
			.AsNoTracking()
			.SingleOrDefaultAsync(
				x => x.Name == gatewayName,
				Context.RequestAborted);

		if (host is null)
		{
			logger.LogError("Bearer token references unknown gateway {GatewayName}.", gatewayName);
			return AuthenticateResult.Fail("Unknown gateway.");
		}

		// 5. Construct the signing key.
		//
		// This example assumes the key is stored as a Base64 string.
		var keyBytes = Convert.FromBase64String(host.GatewaySigningKey);

		var signingKey = new SymmetricSecurityKey(keyBytes);

		// 6. NOW perform actual cryptographic validation.
		var tokenHandler = new JwtSecurityTokenHandler();

		var validationParameters = new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = signingKey,

			ValidateIssuer = true,
			ValidIssuer = gatewayName,

			ValidateAudience = true,
			ValidAudience = "rdpgw",

			ValidateLifetime = true,

			ClockSkew = TimeSpan.FromMinutes(1)
		};

		try
		{
			var principal = tokenHandler.ValidateToken(
				token,
				validationParameters,
				out var validatedToken);

			// Optional: explicitly ensure we're using the algorithm
			// you expect rather than allowing arbitrary algorithms.
			if (validatedToken is not JwtSecurityToken jwt ||
				!string.Equals(
					jwt.Header.Alg,
					SecurityAlgorithms.HmacSha256,
					StringComparison.Ordinal))
			{
				logger.LogError(
					"Invalid token signing algorithm for gateway {GatewayName}.",
					gatewayName);
				return AuthenticateResult.Fail(
					"Invalid token signing algorithm.");
			}

			// 7. The token is now cryptographically authenticated.
			return AuthenticateResult.Success(
				new AuthenticationTicket(principal, Scheme.Name));
		}
		catch (SecurityTokenException ex)
		{
			logger.LogWarning(ex, "JWT validation failed for gateway {GatewayName}.", gatewayName);
			return AuthenticateResult.Fail("Invalid bearer token.");
		}
	}
}