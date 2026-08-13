using System.ComponentModel.DataAnnotations;

namespace Rdpgw.Data;

/// <summary>
/// A gateway that has requested registration with the orchestrator but has not
/// yet been approved by an administrator. Approved entries are promoted into
/// <see cref="GatewayEntry"/>.
/// </summary>
public sealed class PendingGatewayEntry
{
	/// <summary>Gets or sets the database identifier for the pending registration row.</summary>
	public int Id { get; set; }

	/// <summary>
	/// Gets or sets the gateway name presented by the registering gateway. This is also
	/// its reachable host (without a URI scheme), used to fetch its JWKS document (public
	/// signing key) when adopting the gateway: the value comes from the gateway's own
	/// signed registration token, so it is inherently tied to the identity being trusted
	/// rather than a separately-supplied, unverified field. A gateway that misconfigures
	/// its own address will simply fail to be adopted.
	/// </summary>
	[Required]
	public string Name { get; set; } = string.Empty;
}
