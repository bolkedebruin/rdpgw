using Microsoft.Extensions.Caching.Memory;
using System.IdentityModel.Tokens.Jwt;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;

namespace Rdpgw.Security.GatewayToken;

/// <summary>
/// Shared replay protection for gateway tokens. Rejects tokens whose issued-at
/// claim is too old and tokens whose jti has already been presented.
/// </summary>
public sealed class GatewayTokenReplayValidator(ILogger<GatewayTokenReplayValidator> logger, IMemoryCache replayCache)
{
	/// <summary>Maximum age of a token's issued-at claim before it is rejected.</summary>
	public static readonly TimeSpan MaxTokenAge = TimeSpan.FromMinutes(5);

	/// <summary>Tolerance applied to token lifetime and issued-at validation.</summary>
	public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(1);

	private const string ReplayCacheKeyPrefix = "GatewayToken:jti:";

	/// <summary>Guards the check-then-set of a jti so concurrent replays cannot both succeed.</summary>
	private static readonly object ReplayCacheLock = new();

	/// <summary>
	/// Validates the token's iat claim and consumes its jti. Must only be called
	/// after the token signature has been cryptographically verified, otherwise an
	/// attacker could poison the replay cache with forged jti values.
	/// </summary>
	/// <param name="jwt">The verified token.</param>
	/// <param name="gatewayName">Gateway name used for logging.</param>
	/// <param name="failure">Failure reason when validation does not succeed.</param>
	/// <returns><see langword="true"/> when the token is fresh and unused.</returns>
	public bool TryValidate(JwtSecurityToken jwt, string gatewayName, out string failure)
		=> TryValidateIssuedAt(jwt, gatewayName, out failure) && TryConsumeTokenId(jwt, gatewayName, out failure);

	private bool TryValidateIssuedAt(JwtSecurityToken jwt, string gatewayName, out string failure)
	{
		var issuedAtClaim = jwt.Claims
			.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iat)
			?.Value;

		if (string.IsNullOrWhiteSpace(issuedAtClaim) ||
			!long.TryParse(issuedAtClaim, out var issuedAtSeconds))
		{
			logger.LogError("Token for gateway {GatewayName} is missing a valid iat claim.", gatewayName);
			failure = "Token is missing a valid iat claim.";
			return false;
		}

		var issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAtSeconds);
		var age = DateTimeOffset.UtcNow - issuedAt;

		if (age > MaxTokenAge)
		{
			logger.LogWarning(
				"Token for gateway {GatewayName} was issued {Age} ago, which exceeds the maximum age of {MaxTokenAge}.",
				gatewayName,
				age,
				MaxTokenAge);
			failure = "Token is too old.";
			return false;
		}

		// Allow the same clock skew the signature validation uses for tokens issued slightly ahead.
		if (age < -ClockSkew)
		{
			logger.LogWarning("Token for gateway {GatewayName} has an iat claim in the future.", gatewayName);
			failure = "Token iat claim is in the future.";
			return false;
		}

		failure = string.Empty;
		return true;
	}

	private bool TryConsumeTokenId(JwtSecurityToken jwt, string gatewayName, out string failure)
	{
		var tokenId = jwt.Claims
			.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)
			?.Value;

		if (string.IsNullOrWhiteSpace(tokenId) || !Guid.TryParse(tokenId, out var tokenGuid))
		{
			logger.LogError("Token for gateway {GatewayName} is missing a valid jti claim.", gatewayName);
			failure = "Token is missing a valid jti claim.";
			return false;
		}

		var cacheKey = ReplayCacheKeyPrefix + tokenGuid.ToString("N");

		lock (ReplayCacheLock)
		{
			if (replayCache.TryGetValue(cacheKey, out _))
			{
				logger.LogWarning(
					"Token for gateway {GatewayName} reuses jti {TokenId}; possible replay attack.",
					gatewayName,
					tokenGuid);
				failure = "Token has already been used.";
				return false;
			}

			replayCache.Set(cacheKey, true, new MemoryCacheEntryOptions
			{
				AbsoluteExpirationRelativeToNow = MaxTokenAge
			});
		}

		failure = string.Empty;
		return true;
	}
}
