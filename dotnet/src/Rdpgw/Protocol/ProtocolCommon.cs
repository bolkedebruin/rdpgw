using System.Buffers.Binary;
using Rdpgw.Transport;

namespace Rdpgw.Protocol;

internal static class ProtocolCommon
{
    internal const int HeaderLen = 8;
    internal const int MaxFragmentSize = 65536;

    internal static byte[] CreatePacket(int pktType, ReadOnlySpan<byte> data)
    {
        var packet = new byte[data.Length + HeaderLen];
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(0, 2), (ushort)pktType);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(2, 2), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4, 4), (uint)packet.Length);
        data.CopyTo(packet.AsSpan(HeaderLen));
        return packet;
    }

    internal static (ushort PacketType, uint Size, byte[] Packet) ReadHeader(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderLen)
        {
            throw new InvalidDataException("header too short, fragment likely");
        }
        var packetType = BinaryPrimitives.ReadUInt16LittleEndian(data[..2]);
        var size = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        if (size < HeaderLen || size - HeaderLen > MaxFragmentSize)
        {
            throw new InvalidDataException($"invalid declared size {size}");
        }
        if (data.Length < size)
        {
            throw new InvalidDataException("data incomplete, fragment received");
        }
        return (packetType, size, data.Slice(HeaderLen, (int)size - HeaderLen).ToArray());
    }

    internal static async Task<List<Message>> ReadMessageAsync(ITransport input, CancellationToken ct = default)
    {
        var messages = new List<Message>();
        var packet = new PacketReader(input);
        await packet.ReadAsync(ct).ConfigureAwait(false);
        while (packet.HasMoreData)
        {
            messages.Add(await HandleMsgFrameAsync(packet, ct).ConfigureAwait(false));
        }
        return messages;
    }

    private static async Task<Message> HandleMsgFrameAsync(PacketReader packet, CancellationToken ct)
    {
        ushort pt = 0;
        uint sz = 0;
        byte[]? msg = null;
        try
        {
            (pt, sz, msg) = ReadHeader(packet.Current);
            packet.Increment((int)sz);
            return new Message { PacketType = pt, Length = (int)sz, Msg = msg };
        }
        catch (Exception firstError)
        {
            var buffer = new byte[MaxFragmentSize];
            var index = 0;
            while (true)
            {
                if (packet.Current.Length > buffer.Length - index)
                {
                    return new Message { PacketType = pt, Length = (int)sz, Msg = msg ?? Array.Empty<byte>(), Error = new InvalidDataException("fragment exceeded max fragment size") };
                }
                packet.Current.CopyTo(buffer.AsSpan(index));
                index += packet.Current.Length;
                try
                {
                    await packet.ReadAsync(ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    return new Message { PacketType = pt, Length = (int)sz, Msg = msg ?? Array.Empty<byte>(), Error = ex };
                }

                var combined = new byte[index + packet.Current.Length];
                buffer.AsSpan(0, index).CopyTo(combined);
                packet.Current.CopyTo(combined.AsSpan(index));
                try
                {
                    (pt, sz, msg) = ReadHeader(combined);
                    packet.Increment((int)sz - index);
                    return new Message { PacketType = pt, Length = (int)sz, Msg = msg };
                }
                catch (Exception ex)
                {
                    firstError = ex;
                }
            }
        }
    }

    internal static async Task ForwardAsync(Stream remote, Tunnel tunnel, CancellationToken ct)
    {
        var buf = new byte[4086];
        while (!ct.IsCancellationRequested)
        {
            int n;
            try
            {
                n = await remote.ReadAsync(buf, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
                break;
            }
            if (n <= 0)
            {
                break;
            }
            var payload = new byte[n + 2];
            BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(0, 2), (ushort)n);
            buf.AsSpan(0, n).CopyTo(payload.AsSpan(2));
            await tunnel.WriteAsync(CreatePacket(PacketType.PKT_TYPE_DATA, payload)).ConfigureAwait(false);
        }
    }

    internal static async Task ReceiveAsync(ReadOnlyMemory<byte> data, Stream remote, CancellationToken ct = default)
    {
        if (data.Length < 2)
        {
            return;
        }
        var len = BinaryPrimitives.ReadUInt16LittleEndian(data.Span[..2]);
        if (len == 0)
        {
            return;
        }
        var available = Math.Min(len, data.Length - 2);
        await remote.WriteAsync(data.Slice(2, available), ct).ConfigureAwait(false);
        await remote.FlushAsync(ct).ConfigureAwait(false);
    }

    private sealed class PacketReader
    {
        private readonly ITransport _input;
        private byte[] _packet = Array.Empty<byte>();
        private int _size;
        private int _readPtr;

        public PacketReader(ITransport input) => _input = input;
        public bool HasMoreData => _readPtr < _size;
        public ReadOnlySpan<byte> Current => _packet.AsSpan(_readPtr);
        public void Increment(int size) => _readPtr += size;

        public async Task ReadAsync(CancellationToken ct)
        {
            var (size, packet) = await _input.ReadPacketAsync(ct).ConfigureAwait(false);
            _size = size;
            _packet = packet;
            _readPtr = 0;
        }
    }
}
