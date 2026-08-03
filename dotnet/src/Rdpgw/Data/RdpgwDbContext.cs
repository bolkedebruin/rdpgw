using Microsoft.EntityFrameworkCore;

namespace Rdpgw.Data;

public sealed class RdpgwDbContext(DbContextOptions<RdpgwDbContext> options) : DbContext(options)
{
    public DbSet<HostEntry> Hosts => Set<HostEntry>();
    public DbSet<GatewayEntry> Gateways => Set<GatewayEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<HostEntry>(entity =>
        {
            entity.Property(h => h.Name).IsRequired();
            entity.Property(h => h.Address).IsRequired();
            entity.Property(h => h.Owner).IsRequired().HasDefaultValue(string.Empty);
            entity.HasIndex(h => new { h.Owner, h.Address }).IsUnique();
            entity.HasOne(h => h.Gateway).WithMany().HasForeignKey(h => h.GatewayId).OnDelete(DeleteBehavior.SetNull);
        });
        modelBuilder.Entity<GatewayEntry>(entity =>
        {
            entity.Property(g => g.Name).IsRequired();
            entity.Property(g => g.Address).IsRequired();
            entity.HasIndex(g => g.Address).IsUnique();
        });
    }
}
