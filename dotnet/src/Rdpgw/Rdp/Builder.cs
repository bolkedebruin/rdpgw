using System.Reflection;
using System.Text;

namespace Rdpgw.Rdp;

public sealed class Builder
{
    public const string CRLF = "\r\n";
    private readonly HashSet<string> _setFromTemplate = [];
    private readonly HashSet<string> _forced = [];
    public RdpSettings Settings { get; } = new();

    public Builder() => InitDefaults();

    public static Builder NewBuilder() => new();

    public static Builder NewBuilderFromFile(string filename)
    {
        var builder = new Builder();
        var values = RdpParser.ParseFile(filename);
        builder.ApplyParsed(values);
        return builder;
    }

    public override string ToString()
    {
        var sb = new StringBuilder();
        foreach (var prop in Properties())
        {
            var key = prop.GetCustomAttribute<RdpKeyAttribute>()!.Key;
            if (IsZero(prop) && !_setFromTemplate.Contains(prop.Name) && !_forced.Contains(prop.Name)) continue;
            sb.Append(key).Append(':');
            var value = prop.GetValue(Settings);
            if (prop.PropertyType == typeof(string)) sb.Append("s:").Append(SanitizeRdpValue(prop.Name, (string?)value ?? string.Empty));
            else if (prop.PropertyType == typeof(int)) sb.Append("i:").Append(value);
            else if (prop.PropertyType == typeof(bool)) sb.Append("i:").Append((bool)value! ? '1' : '0');
            sb.Append(CRLF);
        }
        return sb.ToString();
    }

    public static string NormalizeRdpKey(string s) => s.Trim().ToLowerInvariant().Replace(" ", string.Empty);

    public void ApplyOverrides(IEnumerable<KeyValuePair<string, string?>> values, IEnumerable<string> allowed)
    {
        var allow = allowed.Select(NormalizeRdpKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var byKey = Properties().ToDictionary(p => NormalizeRdpKey(p.GetCustomAttribute<RdpKeyAttribute>()!.Key), StringComparer.OrdinalIgnoreCase);
        foreach (var pair in values)
        {
            var normalized = NormalizeRdpKey(pair.Key);
            if (!byKey.TryGetValue(normalized, out var prop)) continue;
            if (!allow.Contains(normalized)) throw new InvalidOperationException($"rdp option {pair.Key} is not allowed to be overridden");
            var value = pair.Value?.Trim();
            if (string.IsNullOrEmpty(value)) throw new InvalidOperationException($"rdp option {pair.Key} has empty value");
            SetValue(prop, value);
            _forced.Add(prop.Name);
        }
    }

    public void ApplyOverrides(IQueryCollection query, IEnumerable<string> allowed) => ApplyOverrides(query.Select(q => KeyValuePair.Create(q.Key, q.Value.FirstOrDefault())), allowed);

    public static byte[] Sign(string rdpContent, string certificatePath, string privateKeyPath)
    {
        // TODO: rdpsign-compatible RDP signature generation requires the exact mstsc signature envelope.
        throw new NotSupportedException("RDP file signing is not implemented in the .NET port yet");
    }

    private void ApplyParsed(Dictionary<string, object> values)
    {
        var byKey = Properties().ToDictionary(p => p.GetCustomAttribute<RdpKeyAttribute>()!.Key, StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in values)
        {
            if (!byKey.TryGetValue(key, out var prop)) continue;
            SetValue(prop, value.ToString() ?? string.Empty);
            _setFromTemplate.Add(prop.Name);
        }
    }

    private void InitDefaults()
    {
        foreach (var prop in Properties())
        {
            var def = prop.GetCustomAttribute<RdpDefaultAttribute>()?.Value;
            if (def is not null) SetValue(prop, def);
        }
    }

    private static IEnumerable<PropertyInfo> Properties() => typeof(RdpSettings).GetProperties().Where(p => p.GetCustomAttribute<RdpKeyAttribute>() is not null);

    private bool IsZero(PropertyInfo prop)
    {
        var value = prop.GetValue(Settings);
        var def = prop.GetCustomAttribute<RdpDefaultAttribute>()?.Value;
        if (def is not null) return ValueEquals(prop, value, def);
        return prop.PropertyType == typeof(string) ? string.IsNullOrEmpty((string?)value) : Equals(value, Activator.CreateInstance(prop.PropertyType));
    }

    private static bool ValueEquals(PropertyInfo prop, object? value, string expected) => prop.PropertyType == typeof(string)
        ? (string?)value == expected
        : prop.PropertyType == typeof(int)
            ? (int)(value ?? 0) == int.Parse(expected)
            : prop.PropertyType == typeof(bool) && (bool)(value ?? false) == (expected is "true" or "1");

    private void SetValue(PropertyInfo prop, string value)
    {
        if (prop.PropertyType == typeof(string)) prop.SetValue(Settings, value);
        else if (prop.PropertyType == typeof(int)) prop.SetValue(Settings, int.Parse(value));
        else if (prop.PropertyType == typeof(bool))
        {
            prop.SetValue(Settings, value.ToLowerInvariant() switch
            {
                "1" or "true" => true,
                "0" or "false" => false,
                _ => throw new FormatException($"expected 0/1 or true/false, got {value}")
            });
        }
    }

    private static string SanitizeRdpValue(string field, string value)
    {
        if (value.All(c => c >= 0x20 && c != 0x7f)) return value;
        Console.Error.WriteLine($"rdp: stripped control bytes from field {field}");
        return new string(value.Where(c => c >= 0x20 && c != 0x7f).ToArray());
    }
}
