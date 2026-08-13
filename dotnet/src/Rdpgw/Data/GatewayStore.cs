using Microsoft.EntityFrameworkCore;

namespace Rdpgw.Data;

/// <summary>
/// EF Core (SQLite) backed store for the gateways that RDP files can point clients to.
/// Gateways are shared infrastructure and are not scoped per user.
/// </summary>
public sealed partial class GatewayStore(ILogger<HostStore> logger, RdpgwDbContext dbContext)
{
    /// <summary>
    /// Returns all known gateways ordered by display name.
    /// </summary>
    /// <returns>A list of gateway entries suitable for management UI display.</returns>
    public Task<List<GatewayEntry>> GetAllAsync(CancellationToken cancellationToken = default) => dbContext
        .Gateways
        .AsNoTracking()
        .OrderBy(g => g.Name)
        .ToListAsync(cancellationToken);

    /// <summary>
    /// Adds a new gateway.
    /// </summary>
    /// <param name="gateway">Gateway entry supplied by the caller.</param>
    public async Task AddAsync(string name, string address, string gatewayKey, string? description = default, CancellationToken cancellationToken = default)
    {
        var gateway = new GatewayEntry
        {
            Name = name,
            Address = address,
            GatewaySigningKey = gatewayKey,
            Description = description ?? string.Empty
        };

#warning if default, clear default flag on others

		dbContext.Gateways.Add(gateway);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Updates an existing gateway row.
    /// </summary>
    /// <param name="id">Database identifier of the gateway to update.</param>
    /// <param name="name">New name of the gateway.</param>
    /// <param name="address">New address of the gateway.</param>
    /// <param name="description">New description of the gateway.</param>
    /// <param name="gatewayKey">New gateway signing key.</param>
    /// <param name="isDefault">Whether the gateway is the default.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">Thrown when the gateway no longer exists.</exception>
    public Task UpdateAsync(int id, string name, string address, string? description, string gatewayKey, bool isDefault, CancellationToken cancellationToken = default)
    {
        var existing = dbContext.Gateways.Find(id);
            
        if (existing is null)
        { 
            logger.LogError("Attempted to update gateway with id {Id}, but it does not exist", id);
            throw new InvalidOperationException($"Gateway with id {id} not found");
        }

        existing.Name = name;
        existing.Address = address;
        existing.Description = description ?? string.Empty;
        existing.GatewaySigningKey = gatewayKey;
        existing.IsDefault = isDefault;

#warning if default, clear default flag on others

        return dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Deletes a gateway and clears any host assignments that referenced it.
    /// </summary>
    /// <param name="id">Database identifier of the gateway to delete.</param>
    public Task DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        var existing = dbContext.Gateways.Find(id);
        if (existing is null)
        {
            logger.LogWarning("Gateway with id {Id} not found for deletion", id);
			return Task.CompletedTask;
        }

        if (existing.IsDefault)
		{
            logger.LogWarning("Attempted to delete the default gateway with id {Id}", id);
			throw new InvalidOperationException("Cannot delete the default gateway");
		}

		// Hosts should remain connectable by falling back to the server's default gateway.
		foreach (var h in dbContext
            .Hosts
            .Where(h => h.GatewayId == id))
        {
			h.GatewayId = null;
        }

        dbContext.Gateways.Remove(existing);
        return dbContext.SaveChangesAsync(cancellationToken);
    }
}
