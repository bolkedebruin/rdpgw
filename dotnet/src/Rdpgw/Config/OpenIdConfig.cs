using Microsoft.Extensions.Options;

namespace Rdpgw.Config;

/// <summary>
/// OpenID Connect provider and client settings.
/// </summary>
public sealed class OpenIdConfig
{
	/// <summary>Gets or sets the issuer/provider base URL.</summary>
	public string ProviderUrl { get; set; } = string.Empty;
	/// <summary>Gets or sets the OIDC client identifier.</summary>
	public string ClientId { get; set; } = string.Empty;
	/// <summary>Gets or sets the OIDC client secret.</summary>
	public string ClientSecret { get; set; } = string.Empty;

	public bool Validate()
	{
		if (string.IsNullOrWhiteSpace(ProviderUrl))
		{
			throw new InvalidOperationException("OpenID Connect provider URL is not configured.");
		}
		if (string.IsNullOrWhiteSpace(ClientId))
		{
			throw new InvalidOperationException("OpenID Connect client ID is not configured.");
		}
		if (string.IsNullOrWhiteSpace(ClientSecret))
		{
			throw new InvalidOperationException("OpenID Connect client secret is not configured.");
		}
		return true;
	}
}
