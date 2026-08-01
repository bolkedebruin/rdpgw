using System.Buffers.Binary;
using System.Text;

namespace Rdpgw.Auth.Ntlm;

internal static class NtlmMessage
{
    private static readonly byte[] Signature = "NTLMSSP\0"u8.ToArray();

    public const uint NegotiateUnicode = 0x00000001;
    private const uint RequestTarget = 0x00000004;
    private const uint NegotiateNtlm = 0x00000200;
    private const uint AlwaysSign = 0x00008000;
    private const uint TargetTypeDomain = 0x00010000;
    private const uint TargetTypeServer = 0x00020000;
    private const uint ExtendedSessionSecurity = 0x00080000;
    private const uint TargetInfo = 0x00800000;
    private const uint Negotiate128 = 0x20000000;
    private const uint Negotiate56 = 0x80000000;

    public static int GetMessageType(ReadOnlySpan<byte> message)
    {
        if (message.Length < 12 || !message[..8].SequenceEqual(Signature))
        {
            throw new InvalidOperationException("Failed to parse NTLM Authorisation header: invalid NTLMSSP signature");
        }
        return (int)BinaryPrimitives.ReadUInt32LittleEndian(message[8..12]);
    }

    public static uint ReadUInt32(ReadOnlySpan<byte> message, int offset)
    {
        if (message.Length < offset + 4)
        {
            return 0;
        }
        return BinaryPrimitives.ReadUInt32LittleEndian(message[offset..(offset + 4)]);
    }

    public static byte[] ReadSecurityBuffer(ReadOnlySpan<byte> message, int offset)
    {
        if (message.Length < offset + 8)
        {
            return [];
        }
        var length = BinaryPrimitives.ReadUInt16LittleEndian(message[offset..(offset + 2)]);
        var bufferOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(message[(offset + 4)..(offset + 8)]);
        if (length == 0)
        {
            return [];
        }
        if (bufferOffset < 0 || bufferOffset + length > message.Length)
        {
            throw new InvalidOperationException("Failed to parse NTLM Authorisation header: invalid security buffer");
        }
        return message.Slice(bufferOffset, length).ToArray();
    }

    public static string ReadSecurityBufferString(ReadOnlySpan<byte> message, int offset, bool unicode)
    {
        var bytes = ReadSecurityBuffer(message, offset);
        return unicode ? Encoding.Unicode.GetString(bytes) : Encoding.ASCII.GetString(bytes);
    }

    public static byte[] CreateChallenge(uint negotiateFlags, byte[] challenge, byte[] targetInfo, string domainName, string serverName)
    {
        var targetName = !string.IsNullOrEmpty(domainName) ? domainName : serverName;
        var targetNameBytes = Encoding.Unicode.GetBytes(targetName);
        var flags = NegotiateUnicode | RequestTarget | NegotiateNtlm | AlwaysSign | ExtendedSessionSecurity | TargetInfo;
        flags |= string.IsNullOrEmpty(domainName) ? TargetTypeServer : TargetTypeDomain;
        flags |= negotiateFlags & (Negotiate128 | Negotiate56);

        var payloadOffset = 48;
        var message = new byte[payloadOffset + targetNameBytes.Length + targetInfo.Length];
        Signature.CopyTo(message, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(8), 2);
        WriteSecurityBuffer(message, 12, targetNameBytes.Length, payloadOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(20), flags);
        challenge.CopyTo(message.AsSpan(24));
        WriteSecurityBuffer(message, 40, targetInfo.Length, payloadOffset + targetNameBytes.Length);
        targetNameBytes.CopyTo(message.AsSpan(payloadOffset));
        targetInfo.CopyTo(message.AsSpan(payloadOffset + targetNameBytes.Length));
        return message;
    }

    public static byte[] BuildTargetInfo(NtlmAuth auth)
    {
        using var stream = new MemoryStream();
        WriteAvPair(stream, 2, auth.DomainName);
        WriteAvPair(stream, 1, auth.ServerName);
        WriteAvPair(stream, 4, auth.DnsDomainName);
        WriteAvPair(stream, 3, auth.DnsServerName);
        WriteAvPair(stream, 5, auth.DnsTreeName);
        Span<byte> eol = stackalloc byte[4];
        stream.Write(eol);
        return stream.ToArray();
    }

    private static void WriteAvPair(Stream stream, ushort id, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return;
        }
        var bytes = Encoding.Unicode.GetBytes(value);
        Span<byte> header = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(header, id);
        BinaryPrimitives.WriteUInt16LittleEndian(header[2..], (ushort)bytes.Length);
        stream.Write(header);
        stream.Write(bytes);
    }

    private static void WriteSecurityBuffer(byte[] message, int offset, int length, int bufferOffset)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(offset), (ushort)length);
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(offset + 2), (ushort)length);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(offset + 4), (uint)bufferOffset);
    }
}
