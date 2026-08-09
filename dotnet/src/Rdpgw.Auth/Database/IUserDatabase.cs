namespace Rdpgw.Auth.Database;

/// <summary>
/// Provides password lookup for authentication mechanisms that use configured local users.
/// </summary>
public interface IUserDatabase
{
    /// <summary>
    /// Gets the password associated with a username.
    /// </summary>
    /// <param name="username">Username to look up.</param>
    /// <returns>The password for the user, or an empty string when no user exists.</returns>
    string GetPassword(string username);
}
