using System.Buffers;
using System.Globalization;
using System.IO.Pipelines;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;

namespace Rdpgw.Transport;

/// <summary>Implements the classic two-request RD Gateway HTTP transport.</summary>
/// <remarks>RDG_OUT_DATA carries gateway-to-client bytes and RDG_IN_DATA carries client-to-gateway bytes.</remarks>
public sealed class LegacyTransport : ITransport
{
    private const string CrLf = "\r\n";
    private const string HttpOk = "HTTP/1.1 200 OK\r\n";
    private readonly HttpContext _context;
    private readonly Stream _input;
    private readonly Stream? _upgradedStream;
    private readonly PipeWriter? _rawWriter;

    /// <summary>Initializes a legacy transport over the current HTTP request.</summary>
    /// <param name="context">ASP.NET Core context for the RDG_IN_DATA or RDG_OUT_DATA request.</param>
    public LegacyTransport(HttpContext context)
    {
        _context = context;
        context.Features.Get<IHttpBodyControlFeature>()?.GetType();
        context.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();
        _input = context.Request.Body;
        _rawWriter = context.Features.Get<IConnectionTransportFeature>()?.Transport.Output;
    }

    private LegacyTransport(HttpContext context, Stream upgradedStream) : this(context) => _upgradedStream = upgradedStream;

    /// <summary>Creates a legacy transport, upgrading to a raw stream when the host supports it.</summary>
    /// <param name="context">HTTP request context.</param>
    /// <returns>A transport bound to the request body and response path.</returns>
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

    /// <summary>Reads bytes from the legacy request body.</summary>
    /// <param name="ct">Cancellation token for the read.</param>
    /// <returns>The number of bytes read and a trimmed packet buffer.</returns>
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

    /// <summary>Writes bytes to the selected legacy response path.</summary>
    /// <param name="packet">Packet or HTTP preface bytes to send.</param>
    /// <param name="ct">Cancellation token for the write.</param>
    /// <returns>The number of bytes written.</returns>
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

    /// <summary>Sends the HTTP 200 response preface expected by legacy RD Gateway clients.</summary>
    /// <param name="doSeed">Whether to append the RDG_OUT_DATA random seed bytes.</param>
    public async Task SendAcceptAsync(bool doSeed)
    {
        // MS-TSGU section 2.1 legacy RDG_OUT_DATA receives no Content-Length and is seeded with 10 random bytes.
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

    /// <summary>Consumes the initial legacy request-body bytes before normal packet framing starts.</summary>
    public async Task DrainAsync()
    {
        // The first RDG_IN_DATA body chunk is an HTTP transport artifact rather than an MS-TSGU packet.
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

    /// <summary>Disposes any upgraded raw stream owned by the transport.</summary>
    /// <returns>A completed task.</returns>
    public Task CloseAsync()
    {
        _upgradedStream?.Dispose();
        return Task.CompletedTask;
    }
}
