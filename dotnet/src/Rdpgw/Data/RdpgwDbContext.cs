using Microsoft.EntityFrameworkCore;

namespace Rdpgw.Data;

/// <summary>
/// EF Core database context for rdpgw host and gateway metadata stored in SQLite.
/// </summary>
/// <param name="options">Database options configured by startup.</param>
public sealed class RdpgwDbContext(DbContextOptions<RdpgwDbContext> options) : DbContext(options)
{
    /// <summary>Gets the host destination table.</summary>
    public DbSet<HostEntry> Hosts => Set<HostEntry>();
    /// <summary>Gets the gateway table used for per-host gateway routing.</summary>
    public DbSet<GatewayEntry> Gateways => Set<GatewayEntry>();
    /// <summary>Gets the log entries table for gateway logs.</summary>
    public DbSet<LogEntry> Logs => Set<LogEntry>();

    /// <summary>Configures required columns, uniqueness, and gateway relationship behavior.</summary>
    /// <param name="modelBuilder">EF Core model builder for this context.</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<HostEntry>(entity =>
        {
            entity.Property(h => h.Name).IsRequired();
            entity.Property(h => h.Address).IsRequired();
            entity.Property(h => h.Owner).IsRequired().HasDefaultValue(string.Empty);
            entity.HasIndex(h => new { h.Owner, h.Address }).IsUnique();
            // Deleting a gateway should not delete hosts; they fall back to this server's gateway address.
            entity.HasOne(h => h.Gateway).WithMany().HasForeignKey(h => h.GatewayId).OnDelete(DeleteBehavior.SetNull);
        });
        modelBuilder.Entity<GatewayEntry>(entity =>
        {
            entity.Property(g => g.Name).IsRequired();
            entity.Property(g => g.Address).IsRequired();
            entity.HasIndex(g => g.Address).IsUnique();
        });
        modelBuilder.Entity<LogEntry>(entity =>
        {
            entity.Property(l => l.GatewayId).IsRequired();
            entity.Property(l => l.Timestamp).IsRequired();
            entity.Property(l => l.LogMessage).IsRequired();
            entity.HasOne(l => l.Gateway).WithMany().HasForeignKey(l => l.GatewayId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
