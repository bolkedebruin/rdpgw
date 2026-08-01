using System.Text;

namespace Rdpgw.Rdp;

public static class RdpParser
{
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

    public static Dictionary<string, object> ParseFile(string path) => Parse(File.ReadAllText(path));

    public static byte[] Marshal(IDictionary<string, object> values)
    {
        var sb = new StringBuilder();
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
