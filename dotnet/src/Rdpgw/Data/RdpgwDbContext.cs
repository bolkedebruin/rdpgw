using Microsoft.EntityFrameworkCore;

namespace Rdpgw.Data;

public sealed class RdpgwDbContext(DbContextOptions<RdpgwDbContext> options) : DbContext(options)
{
    public DbSet<HostEntry> Hosts => Set<HostEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<HostEntry>(entity =>
        {
            entity.Property(h => h.Name).IsRequired();
            entity.Property(h => h.Address).IsRequired();
            entity.HasIndex(h => h.Address).IsUnique();
        });
    }
}
