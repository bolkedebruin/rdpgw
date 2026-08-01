using System.Net.Sockets;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Http;
using Rdpgw.Identity;
using Rdpgw.Shared.Auth;

namespace Rdpgw.Web;

internal static class GrpcAuth
{
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
        return GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions { HttpHandler = handler });
    }
}

public sealed class BasicAuthHandler
{
    public string SocketAddress { get; set; } = string.Empty;
    public int Timeout { get; set; }

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
                    Console.WriteLine($"User {parts[0]} authenticated");
                    var id = IdentityContext.FromContext(ctx) ?? new User();
                    id.UserName = parts[0]; id.Authenticated = true; id.AuthTime = DateTimeOffset.UtcNow;
                    IdentityContext.AddToContext(ctx, id);
                    await next(); return;
                }
                Console.WriteLine($"User {parts[0]} is not authenticated for this service");
            }
            catch (Exception ex) { Console.WriteLine($"Basic auth failed: {ex.Message}"); }
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

public sealed class NTLMAuthHandler
{
    public string SocketAddress { get; set; } = string.Empty;
    public int Timeout { get; set; }

    public async Task NTLMAuth(HttpContext ctx, Func<Task> next)
    {
        var (payload, mode) = GetAuthPayload(ctx.Request.Headers.Authorization.ToString());
        if (payload is null) { await RequestAuthenticate(ctx); return; }
        var (authenticated, username, challenge) = await Authenticate(ctx, payload, mode);
        if (!string.IsNullOrEmpty(challenge))
        {
            Console.WriteLine("Sending NTLM challenge");
            ctx.Response.Headers.Append("WWW-Authenticate", Prefix(mode) + challenge);
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Unauthorized");
            return;
        }
        if (authenticated)
        {
            Console.WriteLine($"NTLM: User {username} authenticated");
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
