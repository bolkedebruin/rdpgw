using System.ComponentModel.DataAnnotations;

namespace Rdpgw.Data;

public sealed class HostEntry
{
    public int Id { get; set; }

    [Required]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string Address { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Unique identifier of the user that owns this host (the authenticated username).
    /// An empty owner marks a shared host seeded from the legacy `server.hosts` configuration.
    /// </summary>
    public string Owner { get; set; } = string.Empty;

    public bool IsDefault { get; set; }
}
