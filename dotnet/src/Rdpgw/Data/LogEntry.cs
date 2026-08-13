using System.ComponentModel.DataAnnotations;

namespace Rdpgw.Data;

/// <summary>
/// Represents a log entry recorded by a gateway.
/// </summary>
public sealed class LogEntry
{
	/// <summary>Gets or sets the database identifier for the log entry.</summary>
	public int Id { get; set; }

	/// <summary>Gets or sets the identifier of the gateway that created this log entry.</summary>
	[Required]
	public int GatewayId { get; set; }

	/// <summary>Gets or sets the timestamp when the log entry was created.</summary>
	[Required]
	public DateTime Timestamp { get; set; }

	/// <summary>Gets or sets the log message content.</summary>
	[Required]
	public string LogMessage { get; set; } = string.Empty;

	/// <summary>Gets or sets the navigation property to the gateway that created this log.</summary>
	public GatewayEntry? Gateway { get; set; }
}
