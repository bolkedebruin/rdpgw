using Microsoft.Extensions.Caching.Memory;
using System.Net;

namespace Rdpgw.Security.GatewayToken;

/// <summary>
/// Fixed-window, per-IP rate limiter for gateway registration attempts. Registration
/// can only be authenticated with a pre-shared key, so attempts are throttled before
/// any cryptographic work is done to limit denial-of-service exposure.
/// </summary>
public sealed class GatewayRegistrationRateLimiter(ILogger<GatewayRegistrationRateLimiter> logger, IMemoryCache cache)
{
	/// <summary>Length of the fixed counting window.</summary>
	public static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

	/// <summary>Maximum registration attempts allowed per address within a window.</summary>
	public const int MaxAttemptsPerWindow = 5;

	private const string CacheKeyPrefix = "GatewayRegistration:ip:";

	private static readonly object CounterLock = new();

	/// <summary>Tracks how many attempts an address has made in the current window.</summary>
	private sealed class Counter
	{
		public int Attempts;
	}

	/// <summary>
	/// Records an attempt from the given address and reports whether it is allowed.
	/// </summary>
	/// <param name="remoteAddress">Remote address of the caller, or <see langword="null"/> when unknown.</param>
	/// <returns><see langword="true"/> when the caller is still within its quota.</returns>
	public bool TryAcquire(IPAddress? remoteAddress)
	{
		// Requests without a resolvable remote address cannot be throttled fairly, so reject them.
		if (remoteAddress is null)
		{
			logger.LogWarning("Rejecting gateway registration attempt with no remote address.");
			return false;
		}

		var cacheKey = CacheKeyPrefix + remoteAddress;

		lock (CounterLock)
		{
			// The entry keeps its original expiry, so a burst cannot extend the window.
			if (!cache.TryGetValue<Counter>(cacheKey, out var counter) || counter is null)
			{
				counter = new Counter();
				cache.Set(cacheKey, counter, Window);
			}

			if (counter.Attempts >= MaxAttemptsPerWindow)
			{
				logger.LogWarning(
					"Gateway registration attempts from {RemoteAddress} exceeded {MaxAttempts} per {Window}.",
					remoteAddress,
					MaxAttemptsPerWindow,
					Window);
				return false;
			}

			counter.Attempts++;
		}

		return true;
	}
}
