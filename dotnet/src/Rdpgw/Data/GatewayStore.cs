using Microsoft.EntityFrameworkCore;
using System.Net.Http.Headers;
using Rdpgw.Security;

namespace Rdpgw.Data;

/// <summary>
/// EF Core (SQLite) backed store for the gateways that RDP files can point clients to.
/// Gateways are shared infrastructure and are not scoped per user.
/// </summary>
public sealed partial class GatewayStore(
    ILogger<HostStore> logger,
    RdpgwDbContext dbContext,
    HttpClient httpClient,
    JwksClient jwksClient,
    ITokenService tokenService)
{
    /// <summary>Key id of a node's message signing key in its JWKS document.</summary>
    private const string MessageKeyId = "message";

    /// <summary>
    /// Builds the HTTPS base address to reach a gateway by its self-declared name/host,
    /// e.g. <c>gw1.example.com</c> becomes <c>https://gw1.example.com</c>.
    /// </summary>
    private static string GatewayAddress(string name) => $"https://{name}";

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
    /// Returns all gateways that have initiated registration but have not yet been adopted.
    /// </summary>
    /// <returns>A list of pending gateway entries suitable for management UI display.</returns>
    public Task<List<PendingGatewayEntry>> GetPendingAsync(CancellationToken cancellationToken = default) => dbContext
        .PendingGateways
        .AsNoTracking()
        .OrderBy(g => g.Name)
        .ToListAsync(cancellationToken);

    /// <summary>
    /// Adopts a pending gateway: fetches its message signing key from its JWKS document,
    /// moves it from the pending set into the accepted <see cref="GatewayEntry"/> set, and
    /// notifies the gateway of its adoption by posting a signed message token to its
    /// registration endpoint.
    /// </summary>
    /// <param name="pendingId">Database identifier of the pending gateway to adopt.</param>
    /// <exception cref="InvalidOperationException">Thrown when the pending gateway no longer exists or its public key cannot be retrieved.</exception>
    public async Task AdoptAsync(int pendingId, CancellationToken cancellationToken = default)
    {
        var pending = await dbContext.PendingGateways.FindAsync([pendingId], cancellationToken);
        if (pending is null)
        {
            logger.LogError("Attempted to adopt pending gateway with id {Id}, but it does not exist", pendingId);
            throw new InvalidOperationException($"Pending gateway with id {pendingId} not found");
        }

        var address = GatewayAddress(pending.Name);
        var key = await jwksClient.GetKeyAsync(address, MessageKeyId, cancellationToken);
        if (key is null)
        {
            logger.LogError("Unable to fetch message signing key from gateway '{Name}' at {Address}", pending.Name, address);
            throw new InvalidOperationException($"Unable to fetch signing key for gateway '{pending.Name}'");
        }

        string pem;
        try
        {
            pem = JwkRsaConverter.ToPem(key);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unable to convert JWKS key for gateway '{Name}' to PEM", pending.Name);
            throw new InvalidOperationException($"Invalid signing key returned by gateway '{pending.Name}'", ex);
        }

        dbContext.Gateways.Add(new GatewayEntry
        {
            Name = pending.Name,
            Address = pending.Name,
            GatewaySigningKey = pem,
        });
        dbContext.PendingGateways.Remove(pending);
        await dbContext.SaveChangesAsync(cancellationToken);

        await NotifyAdoptedAsync(pending, cancellationToken);
    }

    private async Task NotifyAdoptedAsync(PendingGatewayEntry pending, CancellationToken cancellationToken)
    {
        var registerUri = new Uri(new Uri(GatewayAddress(pending.Name)), "api/gateway/register");
        var token = await tokenService.GenerateAdoptionNotificationToken(pending.Name);

        using var request = new HttpRequestMessage(HttpMethod.Post, registerUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            // The gateway's DB record has already been created, so this is a notification
            // delivery failure, not an adoption failure; the gateway can discover its
            // adopted status the next time it checks in.
            logger.LogError("gateway '{Name}' returned {StatusCode} for adoption notification", pending.Name, (int)response.StatusCode);
        }
    }

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
