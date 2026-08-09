using System.Buffers.Binary;
using System.Net.Sockets;
using Rdpgw.Identity;
using Rdpgw.Logging;
using static Rdpgw.Protocol.Caps;
using static Rdpgw.Protocol.Fields;
using static Rdpgw.Protocol.PacketType;
using static Rdpgw.Protocol.ProtocolErrors;

namespace Rdpgw.Protocol;

public sealed class Processor
{
    private const int TunnelId = 10;
    private readonly Gateway _gw;
    private readonly Tunnel _tunnel;
    private readonly CancellationTokenSource _disconnect = new();
    private static readonly ILogger Logger = Log.For<Processor>();
    private int _state = SERVER_STATE_INITIALIZED;

    public Processor(Gateway gw, Tunnel tunnel)
    {
        _gw = gw;
        _tunnel = tunnel;
    }

    public async Task ProcessAsync(CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _disconnect.Token);
        var token = linked.Token;
        while (!token.IsCancellationRequested)
        {
            var messages = await _tunnel.ReadAsync(token).ConfigureAwait(false);
            foreach (var message in messages)
            {
                if (message.Error is not null)
                {
                    Logger.LogWarning("Cannot read message from stream {Error}", message.Error);
                    continue;
                }
                switch (message.PacketType)
                {
                    case PKT_TYPE_HANDSHAKE_REQUEST:
                        await HandleHandshakeAsync(message.Msg).ConfigureAwait(false);
                        break;
                    case PKT_TYPE_TUNNEL_CREATE:
                        await HandleTunnelCreateAsync(message.Msg).ConfigureAwait(false);
                        break;
                    case PKT_TYPE_TUNNEL_AUTH:
                        await HandleTunnelAuthAsync(message.Msg).ConfigureAwait(false);
                        break;
                    case PKT_TYPE_CHANNEL_CREATE:
                        await HandleChannelCreateAsync(message.Msg, token).ConfigureAwait(false);
                        break;
                    case PKT_TYPE_DATA:
                        if (_state < SERVER_STATE_CHANNEL_CREATE) throw new InvalidOperationException("wrong state");
                        _state = SERVER_STATE_OPENED;
                        if (_tunnel.Rwc is not null)
                        {
                            await ProtocolCommon.ReceiveAsync(message.Msg, _tunnel.Rwc.GetStream(), token).ConfigureAwait(false);
                        }
                        break;
                    case PKT_TYPE_KEEPALIVE:
                        if (_state < SERVER_STATE_CHANNEL_CREATE) throw new InvalidOperationException("wrong state");
                        break;
                    case PKT_TYPE_CLOSE_CHANNEL:
                        if (_state != SERVER_STATE_OPENED) throw new InvalidOperationException("wrong state");
                        await _tunnel.WriteAsync(ChannelCloseResponse(ERROR_SUCCESS)).ConfigureAwait(false);
                        _state = SERVER_STATE_CLOSED;
                        return;
                    default:
                        Logger.LogWarning("Unknown packet (size {Size}): {Payload}", message.Length, Convert.ToHexString(message.Msg));
                        break;
                }
            }
        }
    }

    internal void SignalDisconnect()
    {
        _disconnect.Cancel();
        _ = _tunnel.TransportIn?.CloseAsync();
        if (!ReferenceEquals(_tunnel.TransportIn, _tunnel.TransportOut))
        {
            _ = _tunnel.TransportOut?.CloseAsync();
        }
        _tunnel.Rwc?.Close();
    }

    private async Task HandleHandshakeAsync(byte[] data)
    {
        Logger.LogInformation("Client handshakeRequest from {ClientIp}", _tunnel.User.GetAttribute(IdentityContext.AttrClientIp));
        if (_state != SERVER_STATE_INITIALIZED)
        {
            await _tunnel.WriteAsync(HandshakeResponse(0, 0, 0, E_PROXY_INTERNALERROR)).ConfigureAwait(false);
            throw new InvalidOperationException($"{E_PROXY_INTERNALERROR:x}: wrong state");
        }
        var (major, minor, _, reqAuth) = HandshakeRequest(data);
        ushort caps;
        try
        {
            caps = MatchAuth(reqAuth);
        }
        catch
        {
            await _tunnel.WriteAsync(HandshakeResponse(0, 0, 0, E_PROXY_CAPABILITYMISMATCH)).ConfigureAwait(false);
            throw;
        }
        await _tunnel.WriteAsync(HandshakeResponse(major, minor, caps, ERROR_SUCCESS)).ConfigureAwait(false);
        _state = SERVER_STATE_HANDSHAKE;
    }

    private async Task HandleTunnelCreateAsync(byte[] data)
    {
        Logger.LogDebug("Tunnel create");
        if (_state != SERVER_STATE_HANDSHAKE)
        {
            await _tunnel.WriteAsync(TunnelResponse(E_PROXY_INTERNALERROR)).ConfigureAwait(false);
            throw new InvalidOperationException($"{E_PROXY_INTERNALERROR:x}: PAA cookie rejected, wrong state");
        }
        var (_, cookie) = TunnelRequest(data);
        if (_gw.CheckPAACookie is not null && !await _gw.CheckPAACookie(_tunnel.Context!, cookie).ConfigureAwait(false))
        {
            await _tunnel.WriteAsync(TunnelResponse(E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED)).ConfigureAwait(false);
            throw new UnauthorizedAccessException($"{E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED:x}: invalid PAA cookie");
        }
        await _tunnel.WriteAsync(TunnelResponse(ERROR_SUCCESS)).ConfigureAwait(false);
        _state = SERVER_STATE_TUNNEL_CREATE;
    }

    private async Task HandleTunnelAuthAsync(byte[] data)
    {
        Logger.LogDebug("Tunnel auth");
        if (_state != SERVER_STATE_TUNNEL_CREATE)
        {
            await _tunnel.WriteAsync(TunnelAuthResponse(E_PROXY_INTERNALERROR)).ConfigureAwait(false);
            throw new InvalidOperationException($"{E_PROXY_INTERNALERROR:x}: Tunnel auth rejected, wrong state");
        }
        var client = TunnelAuthRequest(data);
        if (_gw.CheckClientName is not null && !await _gw.CheckClientName(_tunnel.Context!, client).ConfigureAwait(false))
        {
            await _tunnel.WriteAsync(TunnelAuthResponse(ERROR_ACCESS_DENIED)).ConfigureAwait(false);
            throw new UnauthorizedAccessException($"{ERROR_ACCESS_DENIED:x}: Tunnel auth rejected, invalid client name");
        }
        await _tunnel.WriteAsync(TunnelAuthResponse(ERROR_SUCCESS)).ConfigureAwait(false);
        _state = SERVER_STATE_TUNNEL_AUTHORIZE;
    }

    private async Task HandleChannelCreateAsync(byte[] data, CancellationToken ct)
    {
        Logger.LogDebug("Channel create");
        if (_state != SERVER_STATE_TUNNEL_AUTHORIZE)
        {
            await _tunnel.WriteAsync(ChannelResponse(E_PROXY_INTERNALERROR)).ConfigureAwait(false);
            throw new InvalidOperationException($"{E_PROXY_INTERNALERROR:x}: Channel create rejected, wrong state");
        }
        var (server, port) = ChannelRequest(data);
        var host = $"{server}:{port}";
        if (_gw.CheckHost is not null && !await _gw.CheckHost(_tunnel.Context!, host).ConfigureAwait(false))
        {
            await _tunnel.WriteAsync(ChannelResponse(E_PROXY_RAP_ACCESSDENIED)).ConfigureAwait(false);
            throw new UnauthorizedAccessException($"{E_PROXY_RAP_ACCESSDENIED:x}: denied by security policy");
        }

        var tcp = new TcpClient();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await tcp.ConnectAsync(server, port, timeout.Token).ConfigureAwait(false);
        }
        catch
        {
            tcp.Dispose();
            await _tunnel.WriteAsync(ChannelResponse(E_PROXY_INTERNALERROR)).ConfigureAwait(false);
            throw;
        }

        if (_gw.ReceiveBuf > 0) tcp.ReceiveBufferSize = _gw.ReceiveBuf;
        if (_gw.SendBuf > 0) tcp.SendBufferSize = _gw.SendBuf;
        _tunnel.Rwc = tcp;
        _tunnel.TargetServer = host;
        await _tunnel.WriteAsync(ChannelResponse(ERROR_SUCCESS)).ConfigureAwait(false);
        _ = Task.Run(() => ProtocolCommon.ForwardAsync(tcp.GetStream(), _tunnel, ct), ct);
        _state = SERVER_STATE_CHANNEL_CREATE;
    }

    private static byte[] HandshakeResponse(byte major, byte minor, ushort caps, uint errorCode)
    {
        var buf = new byte[10];
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0, 4), errorCode);
        buf[4] = major;
        buf[5] = minor;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(8, 2), caps);
        return ProtocolCommon.CreatePacket(PKT_TYPE_HANDSHAKE_RESPONSE, buf);
    }

    private static (byte Major, byte Minor, ushort Version, ushort ExtAuth) HandshakeRequest(byte[] data)
    {
        var major = data.Length > 0 ? data[0] : (byte)0;
        var minor = data.Length > 1 ? data[1] : (byte)0;
        var version = data.Length >= 4 ? BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2, 2)) : (ushort)0;
        var extAuth = data.Length >= 6 ? BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(4, 2)) : (ushort)0;
        Logger.LogDebug("major: {Major}, minor: {Minor}, version: {Version}, ext auth: {ExtAuth}", major, minor, version, extAuth);
        return (major, minor, version, extAuth);
    }

    private ushort MatchAuth(ushort clientAuthCaps)
    {
        ushort caps = 0;
        if (_gw.SmartCardAuth) caps |= HTTP_EXTENDED_AUTH_SC;
        if (_gw.TokenAuth) caps |= HTTP_EXTENDED_AUTH_PAA;
        if ((caps & clientAuthCaps) == 0 && clientAuthCaps > 0)
        {
            throw new InvalidOperationException($"{clientAuthCaps:x} has no matching capability configured ({caps:x}). Did you configure caps?");
        }
        if (caps > 0 && clientAuthCaps == 0)
        {
            throw new InvalidOperationException($"{caps} caps are required by the server, but the client does not support them");
        }
        return caps;
    }

    private static (uint Caps, string Cookie) TunnelRequest(byte[] data)
    {
        if (data.Length < 8) return (0, string.Empty);
        var caps = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0, 4));
        var fields = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(4, 2));
        var cookie = string.Empty;
        if (fields == HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE && data.Length >= 10)
        {
            var size = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(8, 2));
            if (data.Length >= 10 + size)
            {
                cookie = Utf16.DecodeUtf16(data.AsSpan(10, size).ToArray());
            }
        }
        return (caps, cookie);
    }

    private static byte[] TunnelResponse(uint errorCode)
    {
        var buf = new byte[18];
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(0, 2), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(2, 4), errorCode);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(6, 2), HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID | HTTP_TUNNEL_RESPONSE_FIELD_CAPS);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(10, 4), TunnelId);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(14, 4), HTTP_CAPABILITY_IDLE_TIMEOUT);
        return ProtocolCommon.CreatePacket(PKT_TYPE_TUNNEL_RESPONSE, buf);
    }

    private static string TunnelAuthRequest(byte[] data)
    {
        if (data.Length < 2) return string.Empty;
        var size = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(0, 2));
        return data.Length >= 2 + size ? Utf16.DecodeUtf16(data.AsSpan(2, size).ToArray()) : string.Empty;
    }

    private byte[] TunnelAuthResponse(uint errorCode)
    {
        var buf = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0, 4), errorCode);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(4, 2), HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(6, 2), 0);
        if (_gw.IdleTimeout < 0) _gw.IdleTimeout = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(8, 4), MakeRedirectFlags(_gw.RedirectFlags));
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(12, 4), (uint)_gw.IdleTimeout);
        return ProtocolCommon.CreatePacket(PKT_TYPE_TUNNEL_AUTH_RESPONSE, buf);
    }

    private static (string Server, int Port) ChannelRequest(byte[] data)
    {
        if (data.Length < 8) return (string.Empty, 0);
        var port = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2, 2));
        var nameSize = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(6, 2));
        var server = data.Length >= 8 + nameSize ? Utf16.DecodeUtf16(data.AsSpan(8, nameSize).ToArray()) : string.Empty;
        return (server, port);
    }

    private static byte[] ChannelResponse(uint errorCode) => ChannelLikeResponse(PKT_TYPE_CHANNEL_RESPONSE, errorCode);

    private static byte[] ChannelCloseResponse(uint errorCode) => ChannelLikeResponse(PKT_TYPE_CLOSE_CHANNEL_RESPONSE, errorCode);

    private static byte[] ChannelLikeResponse(int packetType, uint errorCode)
    {
        var buf = new byte[12];
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0, 4), errorCode);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(4, 2), HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(8, 4), 1);
        return ProtocolCommon.CreatePacket(packetType, buf);
    }

    private static uint MakeRedirectFlags(RedirectFlags flags)
    {
        uint redir = 0;
        if (flags.DisableAll) return HTTP_TUNNEL_REDIR_DISABLE_ALL;
        if (flags.EnableAll) return HTTP_TUNNEL_REDIR_ENABLE_ALL;
        if (!flags.Port) redir |= HTTP_TUNNEL_REDIR_DISABLE_PORT;
        if (!flags.Clipboard) redir |= HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD;
        if (!flags.Drive) redir |= HTTP_TUNNEL_REDIR_DISABLE_DRIVE;
        if (!flags.Pnp) redir |= HTTP_TUNNEL_REDIR_DISABLE_PNP;
        if (!flags.Printer) redir |= HTTP_TUNNEL_REDIR_DISABLE_PRINTER;
        return redir;
    }
}
