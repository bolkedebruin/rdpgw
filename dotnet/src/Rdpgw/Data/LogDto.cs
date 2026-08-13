namespace Rdpgw.Data;

/// <summary>
/// Data transfer object for gateway log entries.
/// </summary>
public sealed class LogDto : IDto
{
	/// <summary>Gets or sets the timestamp when the log entry was created.</summary>
	public DateTime Timestamp { get; set; }

	/// <summary>Gets or sets the log message content.</summary>
	public string LogMessage { get; set; } = string.Empty;

	public void Validate()
	{
		var validationErrors = new List<string>();

		if (Timestamp == default)
		{
			validationErrors.Add("Timestamp is required.");
		}

		if (string.IsNullOrWhiteSpace(LogMessage))
		{
			validationErrors.Add("Log message is required.");
		}

		if (validationErrors.Count != 0)
		{
			throw new ValidationException(validationErrors);
		}
	}
}
