using System.Buffers;
using System.Globalization;
using System.IO.Pipelines;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;

namespace Rdpgw.Transport;

public sealed class LegacyTransport : ITransport
{
    private const string CrLf = "\r\n";
    private const string HttpOk = "HTTP/1.1 200 OK\r\n";
    private readonly HttpContext _context;
    private readonly Stream _input;
    private readonly Stream? _upgradedStream;
    private readonly PipeWriter? _rawWriter;

    public LegacyTransport(HttpContext context)
    {
        _context = context;
        context.Features.Get<IHttpBodyControlFeature>()?.GetType();
        context.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();
        _input = context.Request.Body;
        _rawWriter = context.Features.Get<IConnectionTransportFeature>()?.Transport.Output;
    }

    private LegacyTransport(HttpContext context, Stream upgradedStream) : this(context) => _upgradedStream = upgradedStream;

    public static async Task<LegacyTransport> CreateAsync(HttpContext context)
    {
        // Go's net/http Hijacker exposes the TCP stream after parsing request headers.
        // Kestrel normally keeps ownership of the connection; when the raw connection
        // transport feature is exposed we write the RDG_OUT_DATA response bytes directly
        // to that PipeWriter. If only IHttpUpgradeFeature is available, UpgradeAsync is
        // used as a pragmatic fallback for hosts that support opaque upgraded streams.
        var upgrade = context.Features.Get<IHttpUpgradeFeature>();
        if (upgrade is { IsUpgradableRequest: true })
        {
            var stream = await upgrade.UpgradeAsync().ConfigureAwait(false);
            return new LegacyTransport(context, stream);
        }
        return new LegacyTransport(context);
    }

    public async Task<(int Length, byte[] Packet)> ReadPacketAsync(CancellationToken ct = default)
    {
        var buffer = new byte[4096];
        var n = await _input.ReadAsync(buffer, ct).ConfigureAwait(false);
        if (n == 0)
        {
            throw new EndOfStreamException("legacy request body ended");
        }
        return (n, buffer.AsSpan(0, n).ToArray());
    }

    public async Task<int> WritePacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct = default)
    {
        if (_upgradedStream is not null)
        {
            await _upgradedStream.WriteAsync(packet, ct).ConfigureAwait(false);
            await _upgradedStream.FlushAsync(ct).ConfigureAwait(false);
            return packet.Length;
        }
        if (_rawWriter is not null)
        {
            await _rawWriter.WriteAsync(packet, ct).ConfigureAwait(false);
            await _rawWriter.FlushAsync(ct).ConfigureAwait(false);
            return packet.Length;
        }
        await _context.Response.Body.WriteAsync(packet, ct).ConfigureAwait(false);
        await _context.Response.Body.FlushAsync(ct).ConfigureAwait(false);
        return packet.Length;
    }

    public async Task SendAcceptAsync(bool doSeed)
    {
        var response = HttpOk + "Date: " + DateTimeOffset.UtcNow.ToString("r", CultureInfo.InvariantCulture) + CrLf +
                       (doSeed ? string.Empty : "Content-Length: 0" + CrLf) + CrLf;
        var headerBytes = System.Text.Encoding.ASCII.GetBytes(response);
        await WritePacketAsync(headerBytes).ConfigureAwait(false);
        if (doSeed)
        {
            var seed = RandomNumberGenerator.GetBytes(10);
            await WritePacketAsync(seed).ConfigureAwait(false);
        }
    }

    public async Task DrainAsync()
    {
        var buffer = ArrayPool<byte>.Shared.Rent(32767);
        try
        {
            await _input.ReadAsync(buffer.AsMemory(0, buffer.Length)).ConfigureAwait(false);
        }
        catch (IOException)
        {
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public Task CloseAsync()
    {
        _upgradedStream?.Dispose();
        return Task.CompletedTask;
    }
}
