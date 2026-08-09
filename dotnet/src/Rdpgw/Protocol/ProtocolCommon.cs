using System.Buffers.Binary;
using Rdpgw.Transport;

namespace Rdpgw.Protocol;

/// <summary>Common MS-TSGU packet framing and RDP payload forwarding helpers.</summary>
internal static class ProtocolCommon
{
    /// <summary>Length in bytes of the MS-TSGU common packet header.</summary>
    internal const int HeaderLen = 8;
    /// <summary>Maximum accepted payload fragment size for reassembled gateway packets.</summary>
    internal const int MaxFragmentSize = 65536;

    /// <summary>Creates an MS-TSGU packet by prepending the common 8-byte header.</summary>
    /// <param name="pktType">MS-TSGU packet type identifier.</param>
    /// <param name="data">Payload bytes to copy after the header.</param>
    /// <returns>A complete gateway packet ready for transport.</returns>
    internal static byte[] CreatePacket(int pktType, ReadOnlySpan<byte> data)
    {
        var packet = new byte[data.Length + HeaderLen];
        // MS-TSGU section 2.2 packet syntax uses Type(2), Reserved(2), PacketLength(4), all little-endian.
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(0, 2), (ushort)pktType);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(2, 2), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4, 4), (uint)packet.Length);
        data.CopyTo(packet.AsSpan(HeaderLen));
        return packet;
    }

    /// <summary>Reads and validates the common MS-TSGU packet header.</summary>
    /// <param name="data">Buffer that starts with an MS-TSGU packet header.</param>
    /// <returns>The packet type, declared size, and payload bytes.</returns>
    internal static (ushort PacketType, uint Size, byte[] Packet) ReadHeader(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderLen)
        {
            throw new InvalidDataException("header too short, fragment likely");
        }
        // Bytes 2-3 are reserved and intentionally ignored; bytes 4-7 carry the declared packet size.
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

    /// <summary>Reads one transport frame and extracts every complete MS-TSGU packet it contains.</summary>
    /// <param name="input">Transport to read from.</param>
    /// <param name="ct">Cancellation token for transport reads.</param>
    /// <returns>Decoded messages or message records containing framing errors.</returns>
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
            // Some transports can split a single MS-TSGU packet; collect fragments until the header length is satisfied.
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

                // Re-run header validation over the accumulated bytes to detect when the fragment is complete.
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

    /// <summary>Forwards bytes from the target server to the RD Gateway client as DATA packets.</summary>
    /// <param name="remote">Network stream connected to the target RDP server.</param>
    /// <param name="tunnel">Tunnel used to send gateway packets.</param>
    /// <param name="ct">Cancellation token for the forwarding loop.</param>
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
            // MS-TSGU section 2.2 DATA payloads begin with a 16-bit byte count followed by raw RDP bytes.
            var payload = new byte[n + 2];
            BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(0, 2), (ushort)n);
            buf.AsSpan(0, n).CopyTo(payload.AsSpan(2));
            await tunnel.WriteAsync(CreatePacket(PacketType.PKT_TYPE_DATA, payload)).ConfigureAwait(false);
        }
    }

    /// <summary>Writes the RDP payload from a client DATA packet to the target server stream.</summary>
    /// <param name="data">DATA packet payload beginning with a 16-bit payload length.</param>
    /// <param name="remote">Network stream connected to the target RDP server.</param>
    /// <param name="ct">Cancellation token for stream writes.</param>
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
        // Be tolerant of short frames by writing only the bytes actually present after the length prefix.
        var available = Math.Min(len, data.Length - 2);
        await remote.WriteAsync(data.Slice(2, available), ct).ConfigureAwait(false);
        await remote.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Keeps cursor state while a transport frame is split into one or more gateway packets.</summary>
    private sealed class PacketReader
    {
        private readonly ITransport _input;
        private byte[] _packet = Array.Empty<byte>();
        private int _size;
        private int _readPtr;

        /// <summary>Initializes a packet reader for the specified transport.</summary>
        /// <param name="input">Transport that supplies raw frames.</param>
        public PacketReader(ITransport input) => _input = input;
        /// <summary>Gets whether unread bytes remain in the current transport frame.</summary>
        public bool HasMoreData => _readPtr < _size;
        /// <summary>Gets the unread slice of the current transport frame.</summary>
        public ReadOnlySpan<byte> Current => _packet.AsSpan(_readPtr);
        /// <summary>Advances the read cursor by the specified byte count.</summary>
        /// <param name="size">Number of bytes consumed.</param>
        public void Increment(int size) => _readPtr += size;

        /// <summary>Reads the next frame from the transport and resets the cursor.</summary>
        /// <param name="ct">Cancellation token for the transport read.</param>
        public async Task ReadAsync(CancellationToken ct)
        {
            var (size, packet) = await _input.ReadPacketAsync(ct).ConfigureAwait(false);
            _size = size;
            _packet = packet;
            _readPtr = 0;
        }
    }
}
