using System.ComponentModel.DataAnnotations;

namespace Rdpgw.Data;

/// <summary>
/// Represents a destination host that an authenticated user can select for an RDP connection.
/// </summary>
public sealed class HostEntry
{
    /// <summary>Gets or sets the database identifier for the host row.</summary>
    public int Id { get; set; }

    /// <summary>Gets or sets the display name shown in the host picker.</summary>
    [Required]
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the RDP target address, optionally containing supported username templates.</summary>
    [Required]
    public string Address { get; set; } = string.Empty;

    /// <summary>Gets or sets descriptive text shown alongside the host.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Unique identifier of the user that owns this host (the authenticated username).
    /// An empty owner marks a shared host seeded from the legacy `server.hosts` configuration.
    /// </summary>
    public string Owner { get; set; } = string.Empty;

    /// <summary>
    /// Optional gateway this host is reached through. When unset, the RDP file
    /// uses the server's own configured gateway address.
    /// </summary>
    public int? GatewayId { get; set; }

    /// <summary>Gets or sets the optional gateway navigation property loaded by EF Core.</summary>
    public GatewayEntry? Gateway { get; set; }

    /// <summary>Gets or sets a value indicating whether this host is the user's default selection.</summary>
    public bool IsDefault { get; set; }
}
