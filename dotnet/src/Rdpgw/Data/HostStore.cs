using Microsoft.EntityFrameworkCore;

namespace Rdpgw.Data;

/// <summary>
/// EF Core (SQLite) backed store for the hosts that the gateway allows connections to.
/// Replaces the static `server.hosts` list from the configuration file.
/// Hosts are associated with the user that created them; hosts seeded from the legacy
/// configuration have an empty owner and are shared with (visible to) every user.
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
        await MigrateOwnerColumnAsync(db);
        if (await db.Hosts.AnyAsync()) return;
        var first = true;
        foreach (var host in seedHosts.Where(h => !string.IsNullOrWhiteSpace(h)).Distinct())
        {
            db.Hosts.Add(new HostEntry { Name = host, Address = host, Description = $"Connect to {host}", IsDefault = first, Owner = string.Empty });
            first = false;
        }
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Returns the hosts owned by the given user. Used by the host management page.
    /// </summary>
    public async Task<List<HostEntry>> GetOwnedAsync(string owner)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        return await db.Hosts.AsNoTracking().Where(h => h.Owner == owner).OrderBy(h => h.Name).ToListAsync();
    }

    /// <summary>
    /// Returns the hosts visible to the given user: their own hosts plus shared
    /// (configuration-seeded) hosts that have no owner.
    /// </summary>
    public List<HostEntry> GetVisible(string owner)
    {
        using var db = contextFactory.CreateDbContext();
        return db.Hosts.AsNoTracking().Where(h => h.Owner == owner || h.Owner == "").OrderBy(h => h.Name).ToList();
    }

    /// <summary>
    /// Returns the addresses of the hosts visible to the given user.
    /// </summary>
    public IReadOnlyList<string> GetHostAddresses(string owner)
    {
        using var db = contextFactory.CreateDbContext();
        return db.Hosts.AsNoTracking().Where(h => h.Owner == owner || h.Owner == "").OrderBy(h => h.Id).Select(h => h.Address).ToList();
    }

    public async Task AddAsync(HostEntry host, string owner)
    {
        if (string.IsNullOrEmpty(owner)) throw new InvalidOperationException("cannot add a host without an authenticated user");
        await using var db = await contextFactory.CreateDbContextAsync();
        host.Owner = owner;
        if (host.IsDefault) await ClearDefaultAsync(db, owner);
        db.Hosts.Add(host);
        await db.SaveChangesAsync();
    }

    public async Task UpdateAsync(HostEntry host, string owner)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        var existing = await db.Hosts.FindAsync(host.Id);
        if (existing is null || existing.Owner != owner) throw new InvalidOperationException($"host with id {host.Id} not found for the current user");
        if (host.IsDefault && !existing.IsDefault) await ClearDefaultAsync(db, owner);
        existing.Name = host.Name;
        existing.Address = host.Address;
        existing.Description = host.Description;
        existing.IsDefault = host.IsDefault;
        await db.SaveChangesAsync();
    }

    public async Task DeleteAsync(int id, string owner)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        var existing = await db.Hosts.FindAsync(id);
        if (existing is null || existing.Owner != owner) return;
        db.Hosts.Remove(existing);
        await db.SaveChangesAsync();
    }

    private static async Task ClearDefaultAsync(RdpgwDbContext db, string owner)
    {
        await foreach (var h in db.Hosts.Where(h => h.IsDefault && h.Owner == owner).AsAsyncEnumerable()) h.IsDefault = false;
    }

    /// <summary>
    /// Adds the Owner column to databases created before hosts were associated with users.
    /// EnsureCreated does not alter existing tables, so this is done with a lightweight check.
    /// </summary>
    private static async Task MigrateOwnerColumnAsync(RdpgwDbContext db)
    {
        var connection = db.Database.GetDbConnection();
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM pragma_table_info('Hosts') WHERE name = 'Owner'";
            var hasOwner = Convert.ToInt64(await cmd.ExecuteScalarAsync()) > 0;
            if (!hasOwner)
            {
                cmd.CommandText = "ALTER TABLE Hosts ADD COLUMN Owner TEXT NOT NULL DEFAULT ''";
                await cmd.ExecuteNonQueryAsync();
            }
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }
}
