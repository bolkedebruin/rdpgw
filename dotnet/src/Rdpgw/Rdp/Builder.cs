using System.Reflection;
using System.Text;

namespace Rdpgw.Rdp;

/// <summary>Builds .rdp file content from defaults, templates, and validated overrides.</summary>
public sealed class Builder
{
    /// <summary>Line ending required by RDP file format entries.</summary>
    public const string CRLF = "\r\n";
    private readonly HashSet<string> _setFromTemplate = [];
    private readonly HashSet<string> _forced = [];
    /// <summary>Mutable RDP settings used when rendering the file.</summary>
    public RdpSettings Settings { get; } = new();

    /// <summary>Initializes a builder and applies default RDP settings.</summary>
    public Builder() => InitDefaults();

    /// <summary>Creates a new builder with default settings.</summary>
    /// <returns>A default-initialized builder.</returns>
    public static Builder NewBuilder() => new();

    /// <summary>Creates a builder initialized from an existing .rdp template file.</summary>
    /// <param name="filename">Path to the template .rdp file.</param>
    /// <returns>A builder containing parsed template values.</returns>
    public static Builder NewBuilderFromFile(string filename)
    {
        var builder = new Builder();
        var values = RdpParser.ParseFile(filename);
        builder.ApplyParsed(values);
        return builder;
    }

    /// <summary>Serializes the current settings to .rdp text.</summary>
    /// <returns>RDP file content using CRLF line endings.</returns>
    public override string ToString()
    {
        var sb = new StringBuilder();
        // Reflection keeps the generated file aligned with the RdpSettings attributes.
        foreach (var prop in Properties())
        {
            var key = prop.GetCustomAttribute<RdpKeyAttribute>()!.Key;
            // Omit unset values unless they came from a template or were explicitly forced by a query override.
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

    /// <summary>Normalizes an RDP setting key for case-insensitive allow-list matching.</summary>
    /// <param name="s">Raw RDP key.</param>
    /// <returns>Lowercase key with spaces removed.</returns>
    public static string NormalizeRdpKey(string s) => s.Trim().ToLowerInvariant().Replace(" ", string.Empty);

    /// <summary>Applies validated user-supplied RDP setting overrides.</summary>
    /// <param name="values">Raw key/value override pairs.</param>
    /// <param name="allowed">RDP keys that may be overridden.</param>
    public void ApplyOverrides(IEnumerable<KeyValuePair<string, string?>> values, IEnumerable<string> allowed)
    {
        var allow = allowed.Select(NormalizeRdpKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var byKey = Properties().ToDictionary(p => NormalizeRdpKey(p.GetCustomAttribute<RdpKeyAttribute>()!.Key), StringComparer.OrdinalIgnoreCase);
        foreach (var pair in values)
        {
            var normalized = NormalizeRdpKey(pair.Key);
            // Unknown keys are ignored, but known keys must be explicitly allow-listed before mutation.
            if (!byKey.TryGetValue(normalized, out var prop)) continue;
            if (!allow.Contains(normalized)) throw new InvalidOperationException($"rdp option {pair.Key} is not allowed to be overridden");
            var value = pair.Value?.Trim();
            if (string.IsNullOrEmpty(value)) throw new InvalidOperationException($"rdp option {pair.Key} has empty value");
            SetValue(prop, value);
            _forced.Add(prop.Name);
        }
    }

    /// <summary>Applies validated RDP setting overrides from an HTTP query collection.</summary>
    /// <param name="query">Query string values to inspect.</param>
    /// <param name="allowed">RDP keys that may be overridden.</param>
    public void ApplyOverrides(IQueryCollection query, IEnumerable<string> allowed) => ApplyOverrides(query.Select(q => KeyValuePair.Create(q.Key, q.Value.FirstOrDefault())), allowed);

    /// <summary>Signs RDP content using a certificate and private key.</summary>
    /// <param name="rdpContent">RDP file content to sign.</param>
    /// <param name="certificatePath">Path to the signing certificate.</param>
    /// <param name="privateKeyPath">Path to the private key.</param>
    /// <returns>The signed RDP file bytes.</returns>
    /// <exception cref="NotSupportedException">Always thrown until rdpsign-compatible signing is implemented.</exception>
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
        // RDP files encode booleans as integer-like strings, while templates may use true/false.
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
        // Strip control bytes so user-controlled values cannot inject extra RDP directives.
        if (value.All(c => c >= 0x20 && c != 0x7f)) return value;
        Rdpgw.Logging.Log.For(typeof(Builder)).LogWarning("rdp: stripped control bytes from field {Field}", field);
        return new string(value.Where(c => c >= 0x20 && c != 0x7f).ToArray());
    }
}
