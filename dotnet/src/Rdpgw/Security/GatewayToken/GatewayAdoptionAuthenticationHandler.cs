using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Rdpgw.Config;
using Rdpgw.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Encodings.Web;

namespace Rdpgw.Security.GatewayToken;

/// <summary>
/// Authenticates the orchestrator's "you have been adopted" notification, received by a
/// gateway running in <see cref="ServerMode.Gateway"/>. The first time a notification is
/// successfully validated, the orchestrator's message-signing key is pinned in
/// <see cref="OrchestratorTrustEntry"/>; subsequent requests are validated against that
/// pinned key rather than a freshly-fetched JWKS document, so a later compromise of the
/// orchestrator's JWKS endpoint cannot silently substitute a new signing key. Before a
/// pin exists, the gateway has no other trust anchor, so it falls back to fetching the
/// orchestrator's own JWKS document (via <see cref="OrchestratorConfig.OrchestratorAddress"/>).
/// </summary>
public sealed class GatewayAdoptionAuthenticationHandler(
	ILogger<GatewayAdoptionAuthenticationHandler> logger,
	IOptionsMonitor<AuthenticationSchemeOptions> options,
	ILoggerFactory loggerFactory,
	UrlEncoder encoder,
	GatewayTokenReplayValidator replayValidator,
	JwksClient jwksClient,
	IOptions<OrchestratorConfig> orchestratorConfig,
	IDbContextFactory<RdpgwDbContext> dbContextFactory)
	: AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
	/// <summary>Name of the authentication scheme registered for gateway adoption notifications.</summary>
	public const string SchemeName = "GatewayAdoption";

	/// <summary>Claim carrying the gateway name the notification is addressed to.</summary>
	private const string GatewayNameClaim = "gatewayName";

	/// <summary>Audience adoption notification tokens must be issued for.</summary>
	private const string AdoptionAudience = "rdpgw-adoption";

	/// <summary>Key id of the orchestrator's message signing key in its JWKS document.</summary>
	private const string MessageKeyId = "message";

	protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
	{
		// 1. Get the bearer token from the Authorization header.
		if (!Request.Headers.TryGetValue("Authorization", out var authorization))
		{
			logger.LogError("Missing Authorization header on adoption notification request.");
			return AuthenticateResult.NoResult();
		}

		var authorizationValue = authorization.ToString();
		if (!authorizationValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
		{
			logger.LogError("Adoption notification Authorization header does not start with 'Bearer '.");
			return AuthenticateResult.NoResult();
		}

		var token = authorizationValue["Bearer ".Length..].Trim();

		if (string.IsNullOrWhiteSpace(token))
		{
			logger.LogError("Missing bearer token on adoption notification request.");
			return AuthenticateResult.Fail("Missing bearer token.");
		}

		// 2. Use the pinned orchestrator key if one has already been established; otherwise
		//    fall back to fetching the orchestrator's current JWKS document. The pin is
		//    established below, after the first successful validation.
		var orchestratorAddress = orchestratorConfig.Value.OrchestratorAddress;

		await using var dbContext = await dbContextFactory.CreateDbContextAsync(Context.RequestAborted);
		var pin = await dbContext.OrchestratorTrust.SingleOrDefaultAsync(
			t => t.OrchestratorAddress == orchestratorAddress, Context.RequestAborted);

		RsaSecurityKey signingKey;
		if (pin is not null)
		{
			try
			{
				var rsa = RSA.Create();
				rsa.ImportFromPem(pin.PublicKeyPem);
				signingKey = new RsaSecurityKey(rsa);
			}
			catch (Exception ex)
			{
				logger.LogError(ex, "Unable to load pinned orchestrator signing key.");
				return AuthenticateResult.Fail("Invalid pinned orchestrator signing key.");
			}
		}
		else
		{
			var key = await jwksClient.GetKeyAsync(orchestratorAddress, MessageKeyId, Context.RequestAborted);
			if (key is null)
			{
				logger.LogError("Unable to fetch orchestrator message signing key from {OrchestratorAddress}.", orchestratorAddress);
				return AuthenticateResult.Fail("Unable to fetch orchestrator signing key.");
			}

			try
			{
				signingKey = new RsaSecurityKey(JwkRsaConverter.ToRsaPublicKey(key));
			}
			catch (Exception ex)
			{
				logger.LogError(ex, "Unable to build orchestrator signing key from JWKS.");
				return AuthenticateResult.Fail("Invalid orchestrator signing key.");
			}
		}

		// 3. Validate the token signature and standard claims.
		var tokenHandler = new JwtSecurityTokenHandler();

		var validationParameters = new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = signingKey,

			// The orchestrator's issuer identity is not stored locally; the JWKS fetch
			// itself is the trust anchor.
			ValidateIssuer = false,

			ValidateAudience = true,
			ValidAudience = AdoptionAudience,

			ValidateLifetime = true,

			ClockSkew = GatewayTokenReplayValidator.ClockSkew,

			// Surface the gateway name as User.Identity.Name for downstream controllers.
			NameClaimType = GatewayNameClaim
		};

		try
		{
			var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

			if (validatedToken is not JwtSecurityToken jwt ||
				!string.Equals(jwt.Header.Alg, SecurityAlgorithms.RsaSha256, StringComparison.Ordinal))
			{
				logger.LogError("Invalid adoption notification token signing algorithm.");
				return AuthenticateResult.Fail("Invalid token signing algorithm.");
			}

			// 4. The token is authenticated, so reject stale or already-seen tokens.
			if (!replayValidator.TryValidate(jwt, "orchestrator", out var replayFailure))
			{
				return AuthenticateResult.Fail(replayFailure);
			}

			// 5. If this is the first successful validation, pin the key we just trusted so
			//    future requests no longer need to (and cannot be tricked into) re-fetching
			//    the JWKS document.
			if (pin is null)
			{
				dbContext.OrchestratorTrust.Add(new OrchestratorTrustEntry
				{
					OrchestratorAddress = orchestratorAddress,
					PublicKeyPem = signingKey.Rsa!.ExportSubjectPublicKeyInfoPem(),
					PinnedAt = DateTimeOffset.UtcNow,
				});

				try
				{
					await dbContext.SaveChangesAsync(Context.RequestAborted);
					logger.LogInformation("Pinned orchestrator message signing key from {OrchestratorAddress}.", orchestratorAddress);
				}
				catch (DbUpdateException ex)
				{
					// Another concurrent request may have pinned it first; that's fine.
					logger.LogWarning(ex, "Failed to pin orchestrator signing key from {OrchestratorAddress}; it may already be pinned.", orchestratorAddress);
				}
			}

			logger.LogInformation("Authenticated adoption notification from orchestrator {OrchestratorAddress}.", orchestratorAddress);

			return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
		}
		catch (SecurityTokenException ex)
		{
			logger.LogWarning(ex, "Adoption notification token validation failed.");
			return AuthenticateResult.Fail("Invalid bearer token.");
		}
	}
}
