using Rdpgw.Auth.Config;

namespace Rdpgw.Auth.Database;

public sealed class ConfigDatabase : IUserDatabase
{
    private readonly IReadOnlyDictionary<string, UserConfig> users;

    public ConfigDatabase(IEnumerable<UserConfig> users)
    {
        this.users = users.ToDictionary(u => u.Username, StringComparer.Ordinal);
    }

    public string GetPassword(string username) => users.TryGetValue(username, out var user) ? user.Password : string.Empty;
}
