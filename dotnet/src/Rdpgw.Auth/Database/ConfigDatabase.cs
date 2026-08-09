using Rdpgw.Auth.Config;

namespace Rdpgw.Auth.Database;

/// <summary>
/// In-memory user database backed by the YAML user configuration.
/// </summary>
public sealed class ConfigDatabase : IUserDatabase
{
    private readonly IReadOnlyDictionary<string, UserConfig> users;

    /// <summary>
    /// Initializes a new instance of the <see cref="ConfigDatabase"/> class.
    /// </summary>
    /// <param name="users">Configured users to index by username.</param>
    public ConfigDatabase(IEnumerable<UserConfig> users)
    {
        this.users = users.ToDictionary(u => u.Username, StringComparer.Ordinal);
    }

    /// <summary>
    /// Gets the configured password for a username.
    /// </summary>
    /// <param name="username">Username to look up.</param>
    /// <returns>The configured password, or an empty string when the user is not configured.</returns>
    public string GetPassword(string username) => users.TryGetValue(username, out var user) ? user.Password : string.Empty;
}
