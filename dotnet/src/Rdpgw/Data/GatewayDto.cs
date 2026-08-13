namespace Rdpgw.Data;

public class GatewayDto : IDto
{
	/// <summary>Gets or sets the operator-friendly gateway name displayed in the UI.</summary>
	public string Name { get; set; } = string.Empty;

	/// <summary>Gets or sets the gateway host name or host:port written into RDP files.</summary>
	public string Address { get; set; } = string.Empty;

	/// <summary>Gets or sets optional explanatory text shown to administrators.</summary>
	public string Description { get; set; } = string.Empty;

	/// <summary>
	/// Gets or sets the key used for signing messages from the gateway.
	/// </summary>
	public string GatewaySigningKey { get; set; } = string.Empty;

	public bool IsDefault { get; set; } = false;

	public void Validate()
	{
		var validationErrors = new List<string>();
		if (string.IsNullOrWhiteSpace(Name))
		{
			validationErrors.Add("Gateway name is required.");
		}
		if (string.IsNullOrWhiteSpace(Address))
		{
			validationErrors.Add("Gateway address is required.");
		}
		if (!Uri.TryCreate(Address, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
		{
			validationErrors.Add("Gateway address must be a valid HTTPS URL.");
		}
		if (string.IsNullOrWhiteSpace(GatewaySigningKey) || GatewaySigningKey.Length < 32)
		{
			validationErrors.Add("Gateway signing key is required and must be at least 32 characters long.");
		}

		if (validationErrors.Count != 0)
		{
			throw new ValidationException(validationErrors);
		}
	}
}
