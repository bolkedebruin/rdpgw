using System.ComponentModel.DataAnnotations;

namespace Rdpgw.Data;

/// <summary>
/// A gateway's pinned copy of the orchestrator's message-signing public key,
/// captured the first time an adoption notification is successfully validated.
/// Once pinned, subsequent adoption notifications are validated against this
/// stored key instead of a freshly-fetched JWKS document, so a later compromise
/// of the orchestrator's JWKS endpoint cannot silently substitute a new key.
/// There is at most one row: the pin is keyed by the orchestrator address it was
/// captured from.
/// </summary>
public sealed class OrchestratorTrustEntry
{
	/// <summary>Gets or sets the database identifier for the pinned trust row.</summary>
	public int Id { get; set; }

	/// <summary>Gets or sets the orchestrator address (as configured) the key was pinned from.</summary>
	[Required]
	public string OrchestratorAddress { get; set; } = string.Empty;

	/// <summary>Gets or sets the pinned orchestrator message-signing public key, PEM-encoded.</summary>
	[Required]
	public string PublicKeyPem { get; set; } = string.Empty;

	/// <summary>Gets or sets when this pin was first established.</summary>
	public DateTimeOffset PinnedAt { get; set; }
}
