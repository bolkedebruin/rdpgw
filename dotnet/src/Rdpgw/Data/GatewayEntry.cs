using System.ComponentModel.DataAnnotations;

namespace Rdpgw.Data;

/// <summary>
/// A remote desktop gateway that RDP clients can be directed to. Hosts may be
/// associated with a gateway; the generated RDP file then points at that
/// gateway's address instead of this server's own address.
/// </summary>
public sealed class GatewayEntry
{
    public int Id { get; set; }

    [Required]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string Address { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;
}
