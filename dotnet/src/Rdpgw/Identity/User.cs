using System.Text.Json;

namespace Rdpgw.Identity;

/// <summary>
/// Default mutable implementation of <see cref="IIdentity"/> serialized into the rdpgw session cookie.
/// </summary>
public sealed class User : IIdentity
{
    private string _displayName = string.Empty;
    private string _sessionId = Guid.NewGuid().ToString();
    private IDictionary<string, object?> _attributes = new Dictionary<string, object?>();
    private IDictionary<string, bool> _groupMembership = new Dictionary<string, bool>();

    /// <summary>Gets or sets the canonical username used by authorization and host templating.</summary>
    public string UserName { get; set; } = string.Empty;

    /// <summary>Gets or sets the display name, falling back to <see cref="UserName"/> when unset.</summary>
    public string DisplayName
    {
        get => string.IsNullOrEmpty(_displayName) ? UserName : _displayName;
        set => _displayName = value;
    }

    /// <summary>Gets or sets the optional authentication domain.</summary>
    public string Domain { get; set; } = string.Empty;
    /// <summary>Gets or sets whether this user has been authenticated.</summary>
    public bool Authenticated { get; set; }
    /// <summary>Gets or sets the time authentication completed.</summary>
    public DateTimeOffset AuthTime { get; set; }
    /// <summary>Gets the stable per-session identifier.</summary>
    public string SessionId => _sessionId;
    /// <summary>Gets or sets the user's email address.</summary>
    public string Email { get; set; } = string.Empty;
    /// <summary>Gets or sets the identity expiry time.</summary>
    public DateTimeOffset Expiry { get; set; }
    /// <summary>Gets the arbitrary attribute dictionary used by middleware.</summary>
    public IDictionary<string, object?> Attributes => _attributes;
    /// <summary>Gets group membership flags restored from the serialized session.</summary>
    public IDictionary<string, bool> GroupMembership => _groupMembership;

    /// <summary>Returns an attribute value by key.</summary>
    /// <param name="key">Attribute key.</param>
    /// <returns>The stored value, or <see langword="null"/> when absent.</returns>
    public object? GetAttribute(string key) => _attributes.TryGetValue(key, out var value) ? value : null;

    /// <summary>Stores or replaces an attribute value.</summary>
    /// <param name="key">Attribute key.</param>
    /// <param name="value">Attribute value.</param>
    public void SetAttribute(string key, object? value) => _attributes[key] = value;

    /// <summary>Deletes an attribute value.</summary>
    /// <param name="key">Attribute key.</param>
    public void DelAttribute(string key) => _attributes.Remove(key);

    /// <summary>Serializes this user into UTF-8 JSON bytes for session storage.</summary>
    /// <returns>Serialized user DTO bytes.</returns>
    public byte[] Marshal() => JsonSerializer.SerializeToUtf8Bytes(ToDto());

    /// <summary>Restores this user from UTF-8 JSON bytes produced by <see cref="Marshal"/>.</summary>
    /// <param name="data">Serialized user DTO bytes.</param>
    public void Unmarshal(byte[] data)
    {
        var dto = JsonSerializer.Deserialize<UserDto>(data) ?? throw new JsonException("Empty user payload");
        Authenticated = dto.Authenticated;
        UserName = dto.UserName ?? string.Empty;
        Domain = dto.Domain ?? string.Empty;
        _displayName = dto.DisplayName ?? string.Empty;
        Email = dto.Email ?? string.Empty;
        AuthTime = dto.AuthTime;
        _sessionId = string.IsNullOrEmpty(dto.SessionId) ? Guid.NewGuid().ToString() : dto.SessionId!;
        Expiry = dto.Expiry;
        _attributes = dto.Attributes ?? new Dictionary<string, object?>();
        _groupMembership = dto.GroupMembership ?? new Dictionary<string, bool>();
    }

    private UserDto ToDto() => new()
    {
        Authenticated = Authenticated,
        UserName = UserName,
        Domain = Domain,
        DisplayName = _displayName,
        Email = Email,
        AuthTime = AuthTime,
        SessionId = _sessionId,
        Expiry = Expiry,
        Attributes = _attributes,
        GroupMembership = _groupMembership,
    };

    private sealed class UserDto
    {
        /// <summary>Gets or sets whether the serialized user was authenticated.</summary>
        public bool Authenticated { get; set; }
        /// <summary>Gets or sets the serialized username.</summary>
        public string? UserName { get; set; }
        /// <summary>Gets or sets the serialized domain.</summary>
        public string? Domain { get; set; }
        /// <summary>Gets or sets the serialized display name.</summary>
        public string? DisplayName { get; set; }
        /// <summary>Gets or sets the serialized email address.</summary>
        public string? Email { get; set; }
        /// <summary>Gets or sets the serialized authentication time.</summary>
        public DateTimeOffset AuthTime { get; set; }
        /// <summary>Gets or sets the serialized session identifier.</summary>
        public string? SessionId { get; set; }
        /// <summary>Gets or sets the serialized expiry time.</summary>
        public DateTimeOffset Expiry { get; set; }
        /// <summary>Gets or sets serialized arbitrary identity attributes.</summary>
        public IDictionary<string, object?>? Attributes { get; set; }
        /// <summary>Gets or sets serialized group membership flags.</summary>
        public IDictionary<string, bool>? GroupMembership { get; set; }
    }
}
