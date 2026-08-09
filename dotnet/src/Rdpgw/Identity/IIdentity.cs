using System.Text.Json;

namespace Rdpgw.Identity;

/// <summary>
/// Represents the authenticated rdpgw user and the per-session attributes shared by authentication middleware, web handlers, and gateway protocol checks.
/// </summary>
public interface IIdentity
{
    /// <summary>Gets or sets the canonical username used for authorization and host templating.</summary>
    string UserName { get; set; }
    /// <summary>Gets or sets the friendly display name shown in the web UI.</summary>
    string DisplayName { get; set; }
    /// <summary>Gets or sets the user's authentication domain when one is available.</summary>
    string Domain { get; set; }
    /// <summary>Gets or sets a value indicating whether the identity has completed an authentication flow.</summary>
    bool Authenticated { get; set; }
    /// <summary>Gets or sets the time at which authentication was established.</summary>
    DateTimeOffset AuthTime { get; set; }
    /// <summary>Gets the stable session identifier serialized into the rdpgw session cookie.</summary>
    string SessionId { get; }
    /// <summary>Gets or sets the user's email address when supplied by the identity provider.</summary>
    string Email { get; set; }
    /// <summary>Gets or sets the identity expiry time used by session-aware callers.</summary>
    DateTimeOffset Expiry { get; set; }
    /// <summary>Gets the arbitrary per-session attributes used to carry request metadata such as client IP and access tokens.</summary>
    IDictionary<string, object?> Attributes { get; }
    /// <summary>Returns a stored attribute value.</summary>
    /// <param name="key">Attribute key to look up.</param>
    /// <returns>The stored value, or <see langword="null"/> when the key is absent.</returns>
    object? GetAttribute(string key);
    /// <summary>Stores or replaces an attribute value.</summary>
    /// <param name="key">Attribute key to update.</param>
    /// <param name="value">Value to store; may be <see langword="null"/>.</param>
    void SetAttribute(string key, object? value);
    /// <summary>Removes an attribute from the identity.</summary>
    /// <param name="key">Attribute key to remove.</param>
    void DelAttribute(string key);
    /// <summary>Serializes the identity for encrypted session-cookie storage.</summary>
    /// <returns>UTF-8 JSON bytes containing the identity state.</returns>
    byte[] Marshal();
    /// <summary>Restores identity state from data previously produced by <see cref="Marshal"/>.</summary>
    /// <param name="data">Serialized identity bytes.</param>
    void Unmarshal(byte[] data);
}
