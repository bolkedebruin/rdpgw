using Microsoft.EntityFrameworkCore;

namespace Rdpgw.Data;

/// <summary>
/// EF Core (SQLite) backed store for the hosts that the gateway allows connections to.
/// Replaces the static `server.hosts` list from the configuration file.
/// Hosts are associated with the user that created them; hosts seeded from the legacy
/// configuration have an empty owner and are shared with (visible to) every user.
/// </summary>
public sealed partial class HostStore(ILogger<HostStore> logger, IDbContextFactory<RdpgwDbContext> contextFactory)
{
    /// <summary>
    /// Returns the hosts owned by the given user. Used by the host management page.
    /// </summary>
    /// <param name="owner">Authenticated username that owns the requested hosts.</param>
    /// <returns>The user's private hosts ordered by name.</returns>
    public async Task<List<HostEntry>> GetOwnedAsync(string owner, CancellationToken cancellationToken = default)
    {
        logger.LogTrace("Retrieving hosts owned by {Owner}", owner);
		await using var dbContext = await contextFactory.CreateDbContextAsync(cancellationToken);
        return await dbContext.Hosts
            .AsNoTracking()
            .Where(h => h.Owner == owner)
            .OrderBy(h => h.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Adds a host owned by the authenticated user.
    /// </summary>
    /// <param name="host">Host values to store.</param>
    /// <param name="owner">Authenticated username that will own the host.</param>
    /// <exception cref="InvalidOperationException">Thrown when no owner is supplied.</exception>
    public async Task AddAsync(string name, string address, string description, bool isDefault, int? gatewayId, string owner, CancellationToken cancellationToken = default)
    {        
        logger.LogInformation("Adding host: Host = {Name}:{Address}, Owner = {Owner}", name, address, owner);

		await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);
        var host = new HostEntry
        {
            Name = name,
            Address = address,
            Description = description,
            IsDefault = isDefault,
            GatewayId = gatewayId,
            Owner = owner
        };

		// If the new host is marked as default, clear the default flag from any other hosts owned by the same user.
		if (host.IsDefault)
        {
            await foreach (var currentHost in db
                .Hosts
                .Where(h => h.IsDefault && h.Owner == owner)
                .AsAsyncEnumerable())
            {
                currentHost.IsDefault = false;
            }
		}

        db.Hosts.Add(host);
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Updates a host owned by the authenticated user.
    /// </summary>
    /// <param name="host">Host values, including the existing database identifier, to persist.</param>
    /// <param name="owner">Authenticated username that must own the host.</param>
    /// <exception cref="InvalidOperationException">Thrown when the host is absent or belongs to another user.</exception>
    public async Task UpdateAsync(int id, string name, string address, string description, bool isDefault, int? gatewayId, string owner)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        var existing = await db.Hosts.FindAsync(id);

		if (existing is null)
		{
			logger.LogError("Attempted to delete host with id {Id}, but it does not exist", id);
			throw new InvalidOperationException($"Host with id {id} not found");
		}

#warning clear defaults if this is set to default
        existing.Name = name;
        existing.Address = address;
        existing.Description = description;
        existing.IsDefault = isDefault;
        existing.GatewayId = gatewayId;
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Returns the hosts visible to the given user: their own hosts plus any legacy hosts
    /// (empty owner) shared with every user. Used by the web UI host picker.
    /// </summary>
    /// <param name="owner">Authenticated username requesting the host list.</param>
    /// <returns>The user's visible hosts ordered by name.</returns>
    public async Task<List<HostEntry>> GetVisible(string owner, CancellationToken cancellationToken = default)
    {
        logger.LogTrace("Retrieving hosts visible to {Owner}", owner);
        await using var dbContext = await contextFactory.CreateDbContextAsync(cancellationToken);
        return await dbContext.Hosts
            .AsNoTracking()
            .Where(h => h.Owner == owner || h.Owner == string.Empty)
            .OrderBy(h => h.Name)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Returns the RDP destination addresses of the hosts visible to the given user.
    /// Used to validate that a requested host is one the user is allowed to connect to.
    /// </summary>
    /// <param name="owner">Authenticated username requesting the host list.</param>
    /// <returns>The set of addresses visible to the user.</returns>
    public async Task<HashSet<string>> GetHostAddresses(string owner, CancellationToken cancellationToken = default)
    {
        var entries = await GetVisible(owner, cancellationToken);
        return [.. entries.Select(h => h.Address)];
    }

    /// <summary>Finds a host entry by its RDP destination address.</summary>
    /// <param name="address">Address to look up.</param>
    /// <returns>The matching host entry, or <see langword="null"/> if none exists.</returns>
    public async Task<HostEntry?> FindByAddressAsync(string address, CancellationToken cancellationToken = default)
    {
        await using var dbContext = await contextFactory.CreateDbContextAsync(cancellationToken);
        return await dbContext.Hosts.AsNoTracking().FirstOrDefaultAsync(h => h.Address == address, cancellationToken);
    }

    public async Task DeleteAsync(int id)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        var existing = await db.Hosts.FindAsync(id);
        
        if (existing is null)
        {
            logger.LogError("Attempted to delete host with id {Id}, but it does not exist", id);
            throw new InvalidOperationException($"Host with id {id} not found");
		}

        db.Hosts.Remove(existing);
        await db.SaveChangesAsync();
    }
}
