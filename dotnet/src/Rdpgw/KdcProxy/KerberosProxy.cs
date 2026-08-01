using System.Buffers.Binary;
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;

namespace Rdpgw.KdcProxy;

public sealed class KdcProxyMsg
{
    public byte[] Message { get; set; } = [];
    public string Realm { get; set; } = string.Empty;
    public int? Flags { get; set; }
}

public sealed record Kdc(string Realm, string Host, string Proto);

public sealed class KerberosProxy
{
    private const int MaxLength = 128 * 1024;
    private const string SystemConfigPath = "/etc/krb5.conf";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);
    private readonly Krb5Config _config;

    private KerberosProxy(Krb5Config config) => _config = config;

    public static KerberosProxy InitKdcProxy(string? krb5Conf = null)
    {
        var path = string.IsNullOrEmpty(krb5Conf) ? SystemConfigPath : krb5Conf;
        return new KerberosProxy(Krb5Config.Load(path));
    }

    public async Task Handler(HttpContext ctx)
    {
        if (!HttpMethods.IsPost(ctx.Request.Method))
        {
            ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            await ctx.Response.WriteAsync("Method not allowed");
            return;
        }
        var length = ctx.Request.ContentLength;
        if (length is null)
        {
            ctx.Response.StatusCode = StatusCodes.Status411LengthRequired;
            await ctx.Response.WriteAsync("Content length required");
            return;
        }
        if (length > MaxLength)
        {
            ctx.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            await ctx.Response.WriteAsync("Request entity too large");
            return;
        }

        var data = new byte[length.Value];
        var read = 0;
        while (read < data.Length)
        {
            var n = await ctx.Request.Body.ReadAsync(data.AsMemory(read));
            if (n == 0) break;
            read += n;
        }
        if (read != data.Length)
        {
            ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await ctx.Response.WriteAsync("Error reading from stream");
            return;
        }

        KdcProxyMsg msg;
        try { msg = Decode(data); }
        catch
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsync("Invalid request");
            return;
        }

        byte[] reply;
        try { reply = await Forward(msg.Realm, msg.Message); }
        catch
        {
            ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await ctx.Response.WriteAsync("Service unavailable");
            return;
        }

        ctx.Response.ContentType = "application/kerberos";
        await ctx.Response.Body.WriteAsync(Encode(reply));
    }

    public async Task<byte[]> Forward(string realm, byte[] data)
    {
        if (string.IsNullOrEmpty(realm)) realm = _config.DefaultRealm;
        var kdcs = _config.GetKdcs(realm, tcp: false).Select(h => new Kdc(realm, h, "udp"))
            .Concat(_config.GetKdcs(realm, tcp: true).Select(h => new Kdc(realm, h, "tcp"))).ToList();
        if (kdcs.Count == 0) throw new InvalidOperationException($"cannot get any kdcs (tcp or udp) for realm {realm}");

        using var cts = new CancellationTokenSource(Timeout);
        var tasks = kdcs.Select(k => QueryKdc(k, data, cts.Token)).ToList();
        while (tasks.Count > 0)
        {
            var done = await Task.WhenAny(tasks);
            tasks.Remove(done);
            var result = await done;
            if (result is not null)
            {
                await cts.CancelAsync();
                return result;
            }
        }
        throw new InvalidOperationException($"no replies received from kdcs for realm {realm}");
    }

    private static async Task<byte[]?> QueryKdc(Kdc kdc, byte[] data, CancellationToken cancellationToken)
    {
        try
        {
            if (kdc.Proto == "tcp")
            {
                using var client = new TcpClient();
                await client.ConnectAsync(Host(kdc.Host), Port(kdc.Host), cancellationToken);
                using var stream = client.GetStream();
                await stream.WriteAsync(data, cancellationToken);
                return await ReadAllWithTimeout(stream, cancellationToken);
            }
            using var udp = new UdpClient();
            await udp.SendAsync(data.AsMemory(data.Length >= 4 ? 4 : 0), Host(kdc.Host), Port(kdc.Host), cancellationToken);
            var resp = await udp.ReceiveAsync(cancellationToken);
            var withLength = new byte[resp.Buffer.Length + 4];
            BinaryPrimitives.WriteUInt32BigEndian(withLength, (uint)resp.Buffer.Length);
            Buffer.BlockCopy(resp.Buffer, 0, withLength, 4, resp.Buffer.Length);
            return withLength;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<byte[]> ReadAllWithTimeout(NetworkStream stream, CancellationToken cancellationToken)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var n = await stream.ReadAsync(buffer, cancellationToken);
            if (n == 0) break;
            ms.Write(buffer, 0, n);
            if (ms.Length >= 4)
            {
                var data = ms.ToArray();
                var expected = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(0, 4)) + 4;
                if (data.Length >= expected) return data;
            }
        }
        return ms.ToArray();
    }

    public static KdcProxyMsg Decode(byte[] data)
    {
        var offset = 0;
        ExpectTag(data, ref offset, 0x30);
        var end = offset + ReadLength(data, ref offset);
        var message = ReadExplicitOctets(data, ref offset, 0);
        var realm = string.Empty;
        int? flags = null;
        while (offset < end)
        {
            var tag = data[offset];
            if (tag == 0xa1) realm = ReadExplicitString(data, ref offset, 1);
            else if (tag == 0x81 || tag == 0xa2) flags = ReadTaggedInteger(data, ref offset, 2);
            else throw new FormatException("unexpected KDC proxy tag");
        }
        if (offset != end || end != data.Length) throw new FormatException("trailing data in request");
        return new KdcProxyMsg { Message = message, Realm = realm, Flags = flags };
    }

    public static byte[] Encode(byte[] krb5Data)
    {
        var octet = Der(0x04, krb5Data);
        var explicitMessage = Der(0xa0, octet);
        return Der(0x30, explicitMessage);
    }

    private static byte[] ReadExplicitOctets(byte[] data, ref int offset, int tagNo)
    {
        ExpectTag(data, ref offset, (byte)(0xa0 + tagNo));
        var end = offset + ReadLength(data, ref offset);
        ExpectTag(data, ref offset, 0x04);
        var len = ReadLength(data, ref offset);
        var value = data.AsSpan(offset, len).ToArray();
        offset += len;
        if (offset != end) throw new FormatException("bad explicit octet string");
        return value;
    }

    private static string ReadExplicitString(byte[] data, ref int offset, int tagNo)
    {
        ExpectTag(data, ref offset, (byte)(0xa0 + tagNo));
        var end = offset + ReadLength(data, ref offset);
        var tag = data[offset++];
        if (tag is not (0x1b or 0x13 or 0x0c)) throw new FormatException("bad realm string");
        var len = ReadLength(data, ref offset);
        var value = System.Text.Encoding.ASCII.GetString(data, offset, len);
        offset += len;
        if (offset != end) throw new FormatException("bad explicit string");
        return value;
    }

    private static int ReadTaggedInteger(byte[] data, ref int offset, int tagNo)
    {
        var tag = data[offset++];
        if (tag == 0xa0 + tagNo)
        {
            var end = offset + ReadLength(data, ref offset);
            ExpectTag(data, ref offset, 0x02);
            var value = ReadInteger(data, ref offset);
            if (offset != end) throw new FormatException("bad explicit integer");
            return value;
        }
        if (tag != 0x80 + tagNo) throw new FormatException("bad implicit integer");
        return ReadIntegerValue(data, ref offset);
    }

    private static int ReadInteger(byte[] data, ref int offset)
    {
        ExpectTag(data, ref offset, 0x02);
        return ReadIntegerValue(data, ref offset);
    }

    private static int ReadIntegerValue(byte[] data, ref int offset)
    {
        var len = ReadLength(data, ref offset);
        var result = 0;
        for (var i = 0; i < len; i++) result = (result << 8) | data[offset++];
        return result;
    }

    private static void ExpectTag(byte[] data, ref int offset, byte tag)
    {
        if (offset >= data.Length || data[offset++] != tag) throw new FormatException("unexpected ASN.1 tag");
    }

    private static int ReadLength(byte[] data, ref int offset)
    {
        var first = data[offset++];
        if ((first & 0x80) == 0) return first;
        var count = first & 0x7f;
        if (count is 0 or > 4) throw new FormatException("unsupported ASN.1 length");
        var len = 0;
        for (var i = 0; i < count; i++) len = (len << 8) | data[offset++];
        return len;
    }

    private static byte[] Der(byte tag, byte[] value)
    {
        using var ms = new MemoryStream();
        ms.WriteByte(tag);
        if (value.Length < 128) ms.WriteByte((byte)value.Length);
        else
        {
            var lenBytes = BitConverter.GetBytes(value.Length).Reverse().SkipWhile(b => b == 0).ToArray();
            ms.WriteByte((byte)(0x80 | lenBytes.Length));
            ms.Write(lenBytes);
        }
        ms.Write(value);
        return ms.ToArray();
    }

    private static string Host(string hostPort) => hostPort.Contains(':') ? hostPort.Split(':', 2)[0] : hostPort;
    private static int Port(string hostPort) => hostPort.Contains(':') && int.TryParse(hostPort.Split(':', 2)[1], out var p) ? p : 88;
}

internal sealed class Krb5Config
{
    public string DefaultRealm { get; private set; } = string.Empty;
    private Dictionary<string, List<string>> UdpKdcs { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, List<string>> TcpKdcs { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public static Krb5Config Load(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException($"Cannot load krb5 config {path}", path);
        var cfg = new Krb5Config();
        var section = string.Empty;
        var realm = string.Empty;
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Split('#', 2)[0].Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith('[') && line.EndsWith(']')) { section = line[1..^1].Trim().ToLowerInvariant(); realm = string.Empty; continue; }
            if (section == "libdefaults" && TryKeyValue(line, out var key, out var value) && key.Equals("default_realm", StringComparison.OrdinalIgnoreCase)) cfg.DefaultRealm = value;
            if (section != "realms") continue;
            if (line.EndsWith('{')) { realm = line[..^1].Trim().Trim('=',' '); continue; }
            if (line == "}") { realm = string.Empty; continue; }
            if (realm.Length > 0 && TryKeyValue(line, out key, out value) && key.Equals("kdc", StringComparison.OrdinalIgnoreCase))
            {
                var tcp = value.StartsWith("tcp/", StringComparison.OrdinalIgnoreCase);
                var udp = value.StartsWith("udp/", StringComparison.OrdinalIgnoreCase);
                var host = value;
                if (tcp || udp) host = value[4..];
                var dict = tcp ? cfg.TcpKdcs : cfg.UdpKdcs;
                if (!dict.TryGetValue(realm, out var list)) dict[realm] = list = [];
                list.Add(host);
                if (!tcp && !udp)
                {
                    if (!cfg.TcpKdcs.TryGetValue(realm, out var tcpList)) cfg.TcpKdcs[realm] = tcpList = [];
                    tcpList.Add(host);
                }
            }
        }
        return cfg;
    }

    public IReadOnlyList<string> GetKdcs(string realm, bool tcp) => (tcp ? TcpKdcs : UdpKdcs).TryGetValue(realm, out var list) ? list : [];

    private static bool TryKeyValue(string line, out string key, out string value)
    {
        var parts = line.Split('=', 2);
        if (parts.Length != 2) { key = value = string.Empty; return false; }
        key = parts[0].Trim(); value = parts[1].Trim(); return true;
    }
}
