using System.Text.Json;

namespace Rdpgw.Identity;

public sealed class User : IIdentity
{
    private string _displayName = string.Empty;
    private string _sessionId = Guid.NewGuid().ToString();
    private IDictionary<string, object?> _attributes = new Dictionary<string, object?>();
    private IDictionary<string, bool> _groupMembership = new Dictionary<string, bool>();

    public string UserName { get; set; } = string.Empty;

    public string DisplayName
    {
        get => string.IsNullOrEmpty(_displayName) ? UserName : _displayName;
        set => _displayName = value;
    }

    public string Domain { get; set; } = string.Empty;
    public bool Authenticated { get; set; }
    public DateTimeOffset AuthTime { get; set; }
    public string SessionId => _sessionId;
    public string Email { get; set; } = string.Empty;
    public DateTimeOffset Expiry { get; set; }
    public IDictionary<string, object?> Attributes => _attributes;
    public IDictionary<string, bool> GroupMembership => _groupMembership;

    public object? GetAttribute(string key) => _attributes.TryGetValue(key, out var value) ? value : null;

    public void SetAttribute(string key, object? value) => _attributes[key] = value;

    public void DelAttribute(string key) => _attributes.Remove(key);

    public byte[] Marshal() => JsonSerializer.SerializeToUtf8Bytes(ToDto());

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
        public bool Authenticated { get; set; }
        public string? UserName { get; set; }
        public string? Domain { get; set; }
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public DateTimeOffset AuthTime { get; set; }
        public string? SessionId { get; set; }
        public DateTimeOffset Expiry { get; set; }
        public IDictionary<string, object?>? Attributes { get; set; }
        public IDictionary<string, bool>? GroupMembership { get; set; }
    }
}
