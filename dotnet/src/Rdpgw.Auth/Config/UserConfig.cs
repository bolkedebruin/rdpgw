namespace Rdpgw.Auth.Config;

/// <summary>
/// Configured local user credentials for password and NTLM authentication.
/// </summary>
public sealed class UserConfig
{
    /// <summary>
    /// Gets or sets the username as it appears in the rdpgw auth configuration.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the plaintext password used by local fallback and NTLMv2 verification.
    /// </summary>
    public string Password { get; set; } = string.Empty;
}
