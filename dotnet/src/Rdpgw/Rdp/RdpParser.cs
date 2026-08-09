using System.Text;

namespace Rdpgw.Rdp;

/// <summary>Parses and marshals the simple key:type:value RDP file format.</summary>
public static class RdpParser
{
    /// <summary>Parses RDP file text into typed values.</summary>
    /// <param name="content">Raw RDP file content.</param>
    /// <returns>A case-insensitive map of RDP keys to parsed values.</returns>
    public static Dictionary<string, object> Parse(string content)
    {
        var map = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        using var reader = new StringReader(content);
        string? line;
        var number = 0;
        while ((line = reader.ReadLine()) is not null)
        {
            number++;
            line = line.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            // RDP rows use key:type:value; split at most twice so string values may contain colons.
            var fields = line.Split(':', 3);
            if (fields.Length != 3) throw new FormatException($"malformed line {number}: {line}");
            var key = fields[0].Trim();
            var type = fields[1].Trim();
            var value = fields[2].Trim();
            map[key] = type switch
            {
                "i" => int.TryParse(value, out var i) ? i : throw new FormatException($"cannot parse integer at line {number}: {line}"),
                "s" => value,
                "b" => value,
                _ => throw new FormatException($"malformed line {number}: {line}")
            };
        }
        return map;
    }

    /// <summary>Reads and parses an RDP file from disk.</summary>
    /// <param name="path">Path to the RDP file.</param>
    /// <returns>A case-insensitive map of RDP keys to parsed values.</returns>
    public static Dictionary<string, object> ParseFile(string path) => Parse(File.ReadAllText(path));

    /// <summary>Serializes typed RDP values to UTF-8 encoded RDP file bytes.</summary>
    /// <param name="values">RDP keys and typed values to serialize.</param>
    /// <returns>UTF-8 bytes containing CRLF-delimited RDP entries.</returns>
    public static byte[] Marshal(IDictionary<string, object> values)
    {
        var sb = new StringBuilder();
        // Stable ordering keeps generated templates deterministic.
        foreach (var key in values.Keys.Order(StringComparer.Ordinal))
        {
            var value = values[key];
            switch (value)
            {
                case bool b: sb.Append(key).Append(":i:").Append(b ? '1' : '0'); break;
                case int i: sb.Append(key).Append(":i:").Append(i); break;
                case string s: sb.Append(key).Append(":s:").Append(s); break;
                default: throw new InvalidOperationException("error marshalling");
            }
            sb.Append("\r\n");
        }
        return Encoding.UTF8.GetBytes(sb.ToString());
    }
}
