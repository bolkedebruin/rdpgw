namespace Rdpgw.Data;

/// <summary>
/// Data transfer object describing the registration status of a gateway.
/// </summary>
public sealed class GatewayRegistrationDto : IDto
{
	/// <summary>
	/// Gets or sets the registration status of the gateway.
	/// 0 = not registered, 1 = registration pending, 2 = registration complete.
	/// </summary>
	public int RegistrationStatus { get; set; }

	public void Validate()
	{
		var validationErrors = new List<string>();

		if (RegistrationStatus is < 0 or > 2)
		{
			validationErrors.Add("Registration status must be 0 (not registered), 1 (pending), or 2 (complete).");
		}

		if (validationErrors.Count != 0)
		{
			throw new ValidationException(validationErrors);
		}
	}
}
