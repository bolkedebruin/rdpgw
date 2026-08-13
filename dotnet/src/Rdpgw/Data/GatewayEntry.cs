using System.ComponentModel.DataAnnotations;

namespace Rdpgw.Data;

/// <summary>
/// A remote desktop gateway that RDP clients can be directed to. Hosts may be
/// associated with a gateway; the generated RDP file then points at that
/// gateway's address instead of this server's own address.
/// </summary>
public sealed class GatewayEntry
{
    /// <summary>Gets or sets the database identifier for the gateway row.</summary>
    public int Id { get; set; }

    /// <summary>Gets or sets the operator-friendly gateway name displayed in the UI.</summary>
    [Required]
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the gateway host name or host:port written into RDP files.</summary>
    [Required]
    public string Address { get; set; } = string.Empty;

    /// <summary>Gets or sets optional explanatory text shown to administrators.</summary>
    public string Description { get; set; } = string.Empty;

    [Required]
    public string GatewaySigningKey { get; set; } = string.Empty;

	public bool IsDefault { get; set; } = false;
}
