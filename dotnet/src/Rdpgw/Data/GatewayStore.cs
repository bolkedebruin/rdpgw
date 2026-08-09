using Microsoft.EntityFrameworkCore;

namespace Rdpgw.Data;

/// <summary>
/// EF Core (SQLite) backed store for the gateways that RDP files can point clients to.
/// Gateways are shared infrastructure and are not scoped per user.
/// </summary>
public sealed class GatewayStore(IDbContextFactory<RdpgwDbContext> contextFactory)
{
    /// <summary>
    /// Creates the Gateways table on databases created before multi-gateway support
    /// and seeds it with this server's own configured gateway address when empty.
    /// </summary>
    /// <param name="ownGatewayAddress">Gateway address configured for this server; used to seed the initial primary gateway.</param>
    public async Task InitializeAsync(string ownGatewayAddress)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        await db.Database.EnsureCreatedAsync();
        await MigrateSchemaAsync(db);
        // Only seed an empty table so operator-managed gateway rows are never overwritten at startup.
        if (string.IsNullOrWhiteSpace(ownGatewayAddress) || await db.Gateways.AnyAsync()) return;
        var address = NormalizeAddress(ownGatewayAddress);
        db.Gateways.Add(new GatewayEntry { Name = "Primary", Address = address, Description = "This gateway" });
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Returns all known gateways ordered by display name.
    /// </summary>
    /// <returns>A list of gateway entries suitable for management UI display.</returns>
    public async Task<List<GatewayEntry>> GetAllAsync()
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        return await db.Gateways.AsNoTracking().OrderBy(g => g.Name).ToListAsync();
    }

    /// <summary>
    /// Adds a new gateway after normalizing its address to the RDP host[:port] form.
    /// </summary>
    /// <param name="gateway">Gateway entry supplied by the caller.</param>
    public async Task AddAsync(GatewayEntry gateway)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        gateway.Address = NormalizeAddress(gateway.Address);
        db.Gateways.Add(gateway);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Updates an existing gateway row.
    /// </summary>
    /// <param name="gateway">Gateway values, including the existing database identifier, to persist.</param>
    /// <exception cref="InvalidOperationException">Thrown when the gateway no longer exists.</exception>
    public async Task UpdateAsync(GatewayEntry gateway)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        var existing = await db.Gateways.FindAsync(gateway.Id) ?? throw new InvalidOperationException($"gateway with id {gateway.Id} not found");
        existing.Name = gateway.Name;
        existing.Address = NormalizeAddress(gateway.Address);
        existing.Description = gateway.Description;
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Deletes a gateway and clears any host assignments that referenced it.
    /// </summary>
    /// <param name="id">Database identifier of the gateway to delete.</param>
    public async Task DeleteAsync(int id)
    {
        await using var db = await contextFactory.CreateDbContextAsync();
        var existing = await db.Gateways.FindAsync(id);
        if (existing is null) return;
        // Hosts should remain connectable by falling back to the server's default gateway.
        await foreach (var h in db.Hosts.Where(h => h.GatewayId == id).AsAsyncEnumerable()) h.GatewayId = null;
        db.Gateways.Remove(existing);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Reduces a gateway address to the host[:port] form used in RDP files,
    /// stripping any scheme or path the operator may have entered.
    /// </summary>
    /// <param name="address">Operator-supplied gateway address.</param>
    /// <returns>The trimmed host or host:port value written into RDP files.</returns>
    public static string NormalizeAddress(string address)
    {
        address = address.Trim();
        if (address.Contains("://", StringComparison.Ordinal) && Uri.TryCreate(address, UriKind.Absolute, out var uri))
            return uri.IsDefaultPort ? uri.Host : uri.Authority;
        return address;
    }

    /// <summary>
    /// Adds the Gateways table and the Hosts.GatewayId column to databases created
    /// before multi-gateway support. EnsureCreated does not alter existing tables.
    /// </summary>
    private static async Task MigrateSchemaAsync(RdpgwDbContext db)
    {
        var connection = db.Database.GetDbConnection();
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var cmd = connection.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS "Gateways" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_Gateways" PRIMARY KEY AUTOINCREMENT,
                    "Name" TEXT NOT NULL,
                    "Address" TEXT NOT NULL,
                    "Description" TEXT NOT NULL
                )
                """;
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "CREATE UNIQUE INDEX IF NOT EXISTS \"IX_Gateways_Address\" ON \"Gateways\" (\"Address\")";
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "SELECT COUNT(*) FROM pragma_table_info('Hosts') WHERE name = 'GatewayId'";
            var hasColumn = Convert.ToInt64(await cmd.ExecuteScalarAsync()) > 0;
            if (!hasColumn)
            {
                cmd.CommandText = "ALTER TABLE Hosts ADD COLUMN GatewayId INTEGER NULL REFERENCES Gateways(Id) ON DELETE SET NULL";
                await cmd.ExecuteNonQueryAsync();
            }
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }
}
