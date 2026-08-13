using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Rdpgw.Config;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Encodings.Web;

namespace Rdpgw.Security.GatewayToken;

/// <summary>
/// Authenticates gateways that have not yet registered. Their public key is unknown to
/// the orchestrator, so registration tokens are signed with a pre-shared symmetric key
/// instead. Attempts are rate limited per source address and replay protected.
/// </summary>
public sealed class GatewayRegistrationAuthenticationHandler(
	ILogger<GatewayRegistrationAuthenticationHandler> logger,
	IOptionsMonitor<AuthenticationSchemeOptions> options,
	ILoggerFactory loggerFactory,
	UrlEncoder encoder,
	GatewayTokenReplayValidator replayValidator,
	GatewayRegistrationRateLimiter rateLimiter,
	SecurityConfigProvider securityConfig)
	: AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
	/// <summary>Name of the authentication scheme registered for gateway registration.</summary>
	public const string SchemeName = "GatewayRegistration";

	/// <summary>Claim carrying the gateway name, surfaced as the identity name.</summary>
	private const string GatewayNameClaim = "gatewayName";

	/// <summary>Audience registration tokens must be issued for.</summary>
	private const string RegistrationAudience = "rdpgw-registration";

	protected override Task<AuthenticateResult> HandleAuthenticateAsync()
	{
		// 1. Throttle first so unauthenticated callers cannot force signature validation work.
		if (!rateLimiter.TryAcquire(Context.Connection.RemoteIpAddress))
		{
			return Task.FromResult(AuthenticateResult.Fail("Too many registration attempts."));
		}

		// 2. Get the bearer token from the Authorization header.
		if (!Request.Headers.TryGetValue("Authorization", out var authorization))
		{
			logger.LogError("Missing Authorization header on gateway registration request.");
			return Task.FromResult(AuthenticateResult.NoResult());
		}

		var authorizationValue = authorization.ToString();
		if (!authorizationValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
		{
			logger.LogError("Registration Authorization header does not start with 'Bearer '.");
			return Task.FromResult(AuthenticateResult.NoResult());
		}

		var token = authorizationValue["Bearer ".Length..].Trim();

		if (string.IsNullOrWhiteSpace(token))
		{
			logger.LogError("Missing bearer token on gateway registration request.");
			return Task.FromResult(AuthenticateResult.Fail("Missing bearer token."));
		}

		// 3. Validate the token against the pre-shared registration key. No database
		//    lookup happens here because the gateway is not known to us yet.
		var tokenHandler = new JwtSecurityTokenHandler();

		var validationParameters = new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = new SymmetricSecurityKey(securityConfig.GatewayRegistrationKey),

			// The gateway names itself, so the issuer cannot be pinned to a known value.
			ValidateIssuer = false,

			ValidateAudience = true,
			ValidAudience = RegistrationAudience,

			ValidateLifetime = true,

			ClockSkew = GatewayTokenReplayValidator.ClockSkew,

			// Surface the gateway name as User.Identity.Name for downstream controllers.
			NameClaimType = GatewayNameClaim
		};

		try
		{
			var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

			// Pin the algorithm rather than allowing whatever the token declares.
			if (validatedToken is not JwtSecurityToken jwt ||
				!string.Equals(jwt.Header.Alg, SecurityAlgorithms.HmacSha256, StringComparison.Ordinal))
			{
				logger.LogError("Invalid registration token signing algorithm.");
				return Task.FromResult(AuthenticateResult.Fail("Invalid token signing algorithm."));
			}

			var gatewayName = principal.Identity?.Name;
			if (string.IsNullOrWhiteSpace(gatewayName))
			{
				logger.LogError("Registration token is missing a {Claim} claim.", GatewayNameClaim);
				return Task.FromResult(AuthenticateResult.Fail("Registration token is missing a gateway name."));
			}

			// 4. The token is authenticated, so reject stale or already-seen tokens.
			if (!replayValidator.TryValidate(jwt, gatewayName, out var replayFailure))
			{
				return Task.FromResult(AuthenticateResult.Fail(replayFailure));
			}

			logger.LogInformation("Authenticated registration request for gateway {GatewayName}.", gatewayName);

			return Task.FromResult(AuthenticateResult.Success(
				new AuthenticationTicket(principal, Scheme.Name)));
		}
		catch (SecurityTokenException ex)
		{
			logger.LogWarning(ex, "Registration token validation failed.");
			return Task.FromResult(AuthenticateResult.Fail("Invalid bearer token."));
		}
	}
}
