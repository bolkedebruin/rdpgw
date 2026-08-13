using System.Text.Json;

namespace Rdpgw.Security;

/// <summary>
/// Fetches and parses remote JWKS documents so this instance can validate tokens
/// signed by another rdpgw node (orchestrator or gateway) without a pre-shared key.
/// </summary>
public sealed class JwksClient(HttpClient httpClient, ILogger<JwksClient> logger)
{
	private static readonly JsonSerializerOptions JsonOptions = new()
	{
		PropertyNameCaseInsensitive = true,
	};

	/// <summary>
	/// Fetches the JWKS document from <paramref name="baseAddress"/> and returns the
	/// public key with the given <paramref name="kid"/>, or <see langword="null"/> when
	/// it cannot be retrieved or is not present.
	/// </summary>
	/// <param name="baseAddress">Base address of the node whose JWKS should be fetched.</param>
	/// <param name="kid">Key identifier to look up (e.g. <c>"message"</c>).</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	public async Task<JwkKey?> GetKeyAsync(string baseAddress, string kid, CancellationToken cancellationToken = default)
	{
		var jwksUri = new Uri(new Uri(baseAddress), "/.well-known/jwks.json");

		try
		{
			using var response = await httpClient.GetAsync(jwksUri, cancellationToken);
			if (!response.IsSuccessStatusCode)
			{
				logger.LogError("failed to fetch JWKS from {JwksUri}: {StatusCode}", jwksUri, (int)response.StatusCode);
				return null;
			}

			var document = await JsonSerializer.DeserializeAsync<JwksDocument>(
				await response.Content.ReadAsStreamAsync(cancellationToken), JsonOptions, cancellationToken);

			var key = document?.Keys.FirstOrDefault(k => k.Kid == kid);
			if (key is null)
			{
				logger.LogError("JWKS from {JwksUri} does not contain a key with kid '{Kid}'", jwksUri, kid);
			}

			return key;
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "error fetching or parsing JWKS from {JwksUri}", jwksUri);
			return null;
		}
	}
}
