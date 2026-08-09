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
    /// <param name="seedHosts">Legacy configured host addresses to import into an empty database.</param>
    public async Task InitializeAsync(IEnumerable<string> seedHosts)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        await db.Database.EnsureCreatedAsync();
        await MigrateOwnerColumnAsync(db);
        // The import is intentionally one-shot so later configuration edits do not overwrite user-managed rows.
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
    /// <param name="owner">Authenticated username that owns the requested hosts.</param>
    /// <returns>The user's private hosts ordered by name.</returns>
    public async Task<List<HostEntry>> GetOwnedAsync(string owner)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        return await db.Hosts.AsNoTracking().Where(h => h.Owner == owner).OrderBy(h => h.Name).ToListAsync();
    }

    /// <summary>
    /// Returns the hosts visible to the given user: their own hosts plus shared
    /// (configuration-seeded) hosts that have no owner.
    /// </summary>
    /// <param name="owner">Authenticated username whose visible host list is requested.</param>
    /// <returns>Private and shared hosts ordered by name.</returns>
    public List<HostEntry> GetVisible(string owner)
    {
        using var db = contextFactory.CreateDbContext();
        return db.Hosts.AsNoTracking().Where(h => h.Owner == owner || h.Owner == "").OrderBy(h => h.Name).ToList();
    }

    /// <summary>
    /// Returns the addresses of the hosts visible to the given user.
    /// </summary>
    /// <param name="owner">Authenticated username whose visible host addresses are requested.</param>
    /// <returns>Host addresses ordered by database identifier.</returns>
    public IReadOnlyList<string> GetHostAddresses(string owner)
    {
        using var db = contextFactory.CreateDbContext();
        return db.Hosts.AsNoTracking().Where(h => h.Owner == owner || h.Owner == "").OrderBy(h => h.Id).Select(h => h.Address).ToList();
    }

    /// <summary>
    /// Returns the address of the gateway associated with the given (already
    /// template-substituted) host address visible to the user, or null when the
    /// host has no gateway assigned and the server's own address should be used.
    /// </summary>
    /// <param name="userName">Authenticated username used to resolve host ownership and templates.</param>
    /// <param name="hostAddress">Final host address selected for the RDP file.</param>
    /// <returns>The assigned gateway address, or <see langword="null"/> to use the server default.</returns>
    public string? GetGatewayAddressForHost(string userName, string hostAddress)
    {
        using var db = contextFactory.CreateDbContext();
        var host = db.Hosts.AsNoTracking().Include(h => h.Gateway)
            .Where(h => h.Owner == userName || h.Owner == "")
            .AsEnumerable()
            // Template expansion is performed in memory because it depends on the authenticated username.
            .FirstOrDefault(h => h.Address.Replace("{{ preferred_username }}", userName) == hostAddress);
        return host?.Gateway?.Address;
    }

    /// <summary>
    /// Adds a host owned by the authenticated user.
    /// </summary>
    /// <param name="host">Host values to store.</param>
    /// <param name="owner">Authenticated username that will own the host.</param>
    /// <exception cref="InvalidOperationException">Thrown when no owner is supplied.</exception>
    public async Task AddAsync(HostEntry host, string owner)
    {
        if (string.IsNullOrEmpty(owner)) throw new InvalidOperationException("cannot add a host without an authenticated user");
        await using var db = await contextFactory.CreateDbContextAsync();
        host.Owner = owner;
        if (host.IsDefault) await ClearDefaultAsync(db, owner);
        db.Hosts.Add(host);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Updates a host owned by the authenticated user.
    /// </summary>
    /// <param name="host">Host values, including the existing database identifier, to persist.</param>
    /// <param name="owner">Authenticated username that must own the host.</param>
    /// <exception cref="InvalidOperationException">Thrown when the host is absent or belongs to another user.</exception>
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
        existing.GatewayId = host.GatewayId;
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Deletes a host if it belongs to the authenticated user.
    /// </summary>
    /// <param name="id">Database identifier of the host to delete.</param>
    /// <param name="owner">Authenticated username that must own the host.</param>
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
