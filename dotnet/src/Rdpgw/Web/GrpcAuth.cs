using System.Net.Sockets;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Http;
using Rdpgw.Identity;
using Rdpgw.Logging;
using Rdpgw.Shared.Auth;

namespace Rdpgw.Web;

/// <summary>
/// Creates gRPC channels to the external authentication helper over a Unix domain socket.
/// </summary>
internal static class GrpcAuth
{
    /// <summary>Creates a gRPC channel that dials the configured Unix domain socket.</summary>
    /// <param name="socketAddress">Filesystem path of the authentication helper socket.</param>
    /// <returns>A channel suitable for generated authentication clients.</returns>
    public static GrpcChannel Channel(string socketAddress)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, ct) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketAddress), ct).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
        };
        // The URI is a placeholder; ConnectCallback routes all HTTP/2 traffic over the Unix socket.
        return GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions { HttpHandler = handler });
    }
}

/// <summary>
/// Performs HTTP Basic authentication by delegating username/password verification to the gRPC auth service.
/// </summary>
public sealed class BasicAuthHandler
{
    private readonly ILogger _logger = Log.For<BasicAuthHandler>();
    /// <summary>Gets or sets the Unix domain socket path for the authentication service.</summary>
    public string SocketAddress { get; set; } = string.Empty;
    /// <summary>Gets or sets the authentication service timeout in seconds.</summary>
    public int Timeout { get; set; }

    /// <summary>Authenticates a request with a Basic Authorization header or returns a Basic challenge.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    /// <param name="next">Next handler to invoke on successful authentication.</param>
    public async Task BasicAuth(HttpContext ctx, Func<Task> next)
    {
        var header = ctx.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(header[6..].Trim()));
                var parts = decoded.Split(':', 2);
                if (parts.Length == 2 && await Authenticate(parts[0], parts[1]))
                {
                    _logger.LogInformation("User {User} authenticated", parts[0]);
                    var id = IdentityContext.FromContext(ctx) ?? new User();
                    id.UserName = parts[0]; id.Authenticated = true; id.AuthTime = DateTimeOffset.UtcNow;
                    IdentityContext.AddToContext(ctx, id);
                    await next(); return;
                }
                _logger.LogWarning("User {User} is not authenticated for this service", parts[0]);
            }
            catch (Exception ex) { _logger.LogError(ex, "Basic auth failed"); }
        }
        ctx.Response.Headers.Append("WWW-Authenticate", "Basic realm=\"restricted\", charset=\"UTF-8\"");
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsync("Unauthorized");
    }

    private async Task<bool> Authenticate(string username, string password)
    {
        if (string.IsNullOrEmpty(SocketAddress)) return false;
        using var channel = GrpcAuth.Channel(SocketAddress);
        var client = new Authenticate.AuthenticateClient(channel);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Timeout <= 0 ? 5 : Timeout));
        var res = await client.AuthenticateAsync(new UserPass { Username = username, Password = password }, cancellationToken: cts.Token);
        return res.Authenticated;
    }
}

/// <summary>
/// Performs NTLM/Negotiate authentication by relaying protocol messages to the gRPC auth service.
/// </summary>
public sealed class NTLMAuthHandler
{
    private readonly ILogger _logger = Log.For<NTLMAuthHandler>();
    /// <summary>Gets or sets the Unix domain socket path for the authentication service.</summary>
    public string SocketAddress { get; set; } = string.Empty;
    /// <summary>Gets or sets the authentication service timeout in seconds.</summary>
    public int Timeout { get; set; }

    /// <summary>Processes an NTLM/Negotiate authentication step and continues when the service reports success.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    /// <param name="next">Next handler to invoke on successful authentication.</param>
    public async Task NTLMAuth(HttpContext ctx, Func<Task> next)
    {
        var (payload, mode) = GetAuthPayload(ctx.Request.Headers.Authorization.ToString());
        if (payload is null) { await RequestAuthenticate(ctx); return; }
        var (authenticated, username, challenge) = await Authenticate(ctx, payload, mode);
        if (!string.IsNullOrEmpty(challenge))
        {
            _logger.LogDebug("Sending NTLM challenge");
            // NTLM is multi-round-trip; the gRPC service returns the next challenge blob to forward to the client.
            ctx.Response.Headers.Append("WWW-Authenticate", Prefix(mode) + challenge);
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Unauthorized");
            return;
        }
        if (authenticated)
        {
            _logger.LogInformation("NTLM: User {User} authenticated", username);
            var id = IdentityContext.FromContext(ctx) ?? new User();
            id.UserName = username; id.Authenticated = true; id.AuthTime = DateTimeOffset.UtcNow;
            IdentityContext.AddToContext(ctx, id);
            await next();
            return;
        }
        await RequestAuthenticate(ctx);
    }

    private static (string? Payload, int Mode) GetAuthPayload(string header)
    {
        if (header.StartsWith("NTLM ", StringComparison.Ordinal)) return (header[5..], 1);
        if (header.StartsWith("Negotiate ", StringComparison.Ordinal)) return (header[10..], 2);
        return (null, 0);
    }
    private static string Prefix(int mode) => mode == 1 ? "NTLM " : mode == 2 ? "Negotiate " : string.Empty;
    private static async Task RequestAuthenticate(HttpContext ctx)
    {
        ctx.Response.Headers.Append("WWW-Authenticate", "NTLM");
        ctx.Response.Headers.Append("WWW-Authenticate", "Negotiate");
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsync("Unauthorized");
    }
    private async Task<(bool Authenticated, string Username, string Challenge)> Authenticate(HttpContext ctx, string msg, int mode)
    {
        if (string.IsNullOrEmpty(SocketAddress)) return (false, string.Empty, string.Empty);
        using var channel = GrpcAuth.Channel(SocketAddress);
        var client = new Authenticate.AuthenticateClient(channel);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Timeout <= 0 ? 5 : Timeout));
        var res = await client.NTLMAsync(new NtlmRequest { Session = ContextMiddleware.RemoteAddr(ctx), NtlmMessage = msg }, cancellationToken: cts.Token);
        return (res.Authenticated, res.Username, res.NtlmMessage);
    }
}
