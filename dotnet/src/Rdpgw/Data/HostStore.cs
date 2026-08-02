using Microsoft.EntityFrameworkCore;

namespace Rdpgw.Data;

/// <summary>
/// EF Core (SQLite) backed store for the hosts that the gateway allows connections to.
/// Replaces the static `server.hosts` list from the configuration file.
/// </summary>
public sealed class HostStore(IDbContextFactory<RdpgwDbContext> contextFactory)
{
    /// <summary>
    /// Creates the database schema if needed and seeds it with any hosts from the
    /// legacy `server.hosts` configuration key when the table is still empty.
    /// </summary>
    public async Task InitializeAsync(IEnumerable<string> seedHosts)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        await db.Database.EnsureCreatedAsync();
        if (await db.Hosts.AnyAsync()) return;
        var first = true;
        foreach (var host in seedHosts.Where(h => !string.IsNullOrWhiteSpace(h)).Distinct())
        {
            db.Hosts.Add(new HostEntry { Name = host, Address = host, Description = $"Connect to {host}", IsDefault = first });
            first = false;
        }
        await db.SaveChangesAsync();
    }

    public async Task<List<HostEntry>> GetAllAsync()
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        return await db.Hosts.AsNoTracking().OrderBy(h => h.Name).ToListAsync();
    }

    public List<HostEntry> GetAll()
    {
        using var db = contextFactory.CreateDbContext();
        return db.Hosts.AsNoTracking().OrderBy(h => h.Name).ToList();
    }

    public IReadOnlyList<string> GetHostAddresses()
    {
        using var db = contextFactory.CreateDbContext();
        return db.Hosts.AsNoTracking().OrderBy(h => h.Id).Select(h => h.Address).ToList();
    }

    public async Task AddAsync(HostEntry host)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        if (host.IsDefault) await ClearDefaultAsync(db);
        db.Hosts.Add(host);
        await db.SaveChangesAsync();
    }

    public async Task UpdateAsync(HostEntry host)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        var existing = await db.Hosts.FindAsync(host.Id) ?? throw new InvalidOperationException($"host with id {host.Id} not found");
        if (host.IsDefault && !existing.IsDefault) await ClearDefaultAsync(db);
        existing.Name = host.Name;
        existing.Address = host.Address;
        existing.Description = host.Description;
        existing.IsDefault = host.IsDefault;
        await db.SaveChangesAsync();
    }

    public async Task DeleteAsync(int id)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        var existing = await db.Hosts.FindAsync(id);
        if (existing is null) return;
        db.Hosts.Remove(existing);
        await db.SaveChangesAsync();
    }

    private static async Task ClearDefaultAsync(RdpgwDbContext db)
    {
        await foreach (var h in db.Hosts.Where(h => h.IsDefault).AsAsyncEnumerable()) h.IsDefault = false;
    }
}
