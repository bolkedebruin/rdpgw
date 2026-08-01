using System.Text.Json;

namespace Rdpgw.Identity;

public interface IIdentity
{
    string UserName { get; set; }
    string DisplayName { get; set; }
    string Domain { get; set; }
    bool Authenticated { get; set; }
    DateTimeOffset AuthTime { get; set; }
    string SessionId { get; }
    string Email { get; set; }
    DateTimeOffset Expiry { get; set; }
    IDictionary<string, object?> Attributes { get; }
    object? GetAttribute(string key);
    void SetAttribute(string key, object? value);
    void DelAttribute(string key);
    byte[] Marshal();
    void Unmarshal(byte[] data);
}
