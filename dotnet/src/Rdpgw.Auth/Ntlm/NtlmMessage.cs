using System.Buffers.Binary;
using System.Text;

namespace Rdpgw.Auth.Ntlm;

/// <summary>
/// Reads and writes NTLMSSP message structures used by the sidecar.
/// </summary>
/// <remarks>
/// The offsets and security-buffer layouts follow MS-NLMP section 2.2 message
/// syntax for NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE.
/// </remarks>
internal static class NtlmMessage
{
    private static readonly byte[] Signature = "NTLMSSP\0"u8.ToArray();

    /// <summary>
    /// Indicates that payload strings are encoded as UTF-16LE Unicode.
    /// </summary>
    public const uint NegotiateUnicode = 0x00000001;
    // Negotiate flags are defined by MS-NLMP section 2.2.2.5 and are used to
    // advertise this server's type 2 challenge capabilities.
    private const uint RequestTarget = 0x00000004;
    private const uint NegotiateNtlm = 0x00000200;
    private const uint AlwaysSign = 0x00008000;
    private const uint TargetTypeDomain = 0x00010000;
    private const uint TargetTypeServer = 0x00020000;
    private const uint ExtendedSessionSecurity = 0x00080000;
    private const uint TargetInfo = 0x00800000;
    private const uint Negotiate128 = 0x20000000;
    private const uint Negotiate56 = 0x80000000;

    /// <summary>
    /// Reads the NTLMSSP message type from a message header.
    /// </summary>
    /// <param name="message">Raw NTLMSSP message bytes.</param>
    /// <returns>The numeric NTLM message type.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the message does not start with the NTLMSSP signature.</exception>
    public static int GetMessageType(ReadOnlySpan<byte> message)
    {
        if (message.Length < 12 || !message[..8].SequenceEqual(Signature))
        {
            throw new InvalidOperationException("Failed to parse NTLM Authorisation header: invalid NTLMSSP signature");
        }
        return (int)BinaryPrimitives.ReadUInt32LittleEndian(message[8..12]);
    }

    /// <summary>
    /// Reads a little-endian 32-bit integer if it is present in the message.
    /// </summary>
    /// <param name="message">Raw NTLMSSP message bytes.</param>
    /// <param name="offset">Offset of the integer within the message.</param>
    /// <returns>The integer value, or zero when the requested bytes are not present.</returns>
    public static uint ReadUInt32(ReadOnlySpan<byte> message, int offset)
    {
        if (message.Length < offset + 4)
        {
            return 0;
        }
        return BinaryPrimitives.ReadUInt32LittleEndian(message[offset..(offset + 4)]);
    }

    /// <summary>
    /// Reads the payload referenced by an NTLM security buffer descriptor.
    /// </summary>
    /// <param name="message">Raw NTLMSSP message bytes.</param>
    /// <param name="offset">Offset of the security buffer descriptor.</param>
    /// <returns>The referenced payload bytes, or an empty array for absent or zero-length buffers.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the descriptor points outside the message.</exception>
    public static byte[] ReadSecurityBuffer(ReadOnlySpan<byte> message, int offset)
    {
        if (message.Length < offset + 8)
        {
            return [];
        }
        // MS-NLMP security buffers store length, allocated length, and payload offset.
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

    /// <summary>
    /// Reads and decodes a string referenced by an NTLM security buffer.
    /// </summary>
    /// <param name="message">Raw NTLMSSP message bytes.</param>
    /// <param name="offset">Offset of the security buffer descriptor.</param>
    /// <param name="unicode">Whether to decode the payload as UTF-16LE instead of ASCII.</param>
    /// <returns>The decoded string, or an empty string for an absent buffer.</returns>
    public static string ReadSecurityBufferString(ReadOnlySpan<byte> message, int offset, bool unicode)
    {
        var bytes = ReadSecurityBuffer(message, offset);
        return unicode ? Encoding.Unicode.GetString(bytes) : Encoding.ASCII.GetString(bytes);
    }

    /// <summary>
    /// Creates an NTLM CHALLENGE_MESSAGE for a type 1 negotiate request.
    /// </summary>
    /// <param name="negotiateFlags">Flags received in the client's NEGOTIATE_MESSAGE.</param>
    /// <param name="challenge">Eight-byte server challenge nonce.</param>
    /// <param name="targetInfo">AV_PAIR target information block included for NTLMv2.</param>
    /// <param name="domainName">Configured NetBIOS domain target name.</param>
    /// <param name="serverName">Configured NetBIOS server target name.</param>
    /// <returns>The raw NTLM CHALLENGE_MESSAGE bytes.</returns>
    public static byte[] CreateChallenge(uint negotiateFlags, byte[] challenge, byte[] targetInfo, string domainName, string serverName)
    {
        var targetName = !string.IsNullOrEmpty(domainName) ? domainName : serverName;
        var targetNameBytes = Encoding.Unicode.GetBytes(targetName);
        var flags = NegotiateUnicode | RequestTarget | NegotiateNtlm | AlwaysSign | ExtendedSessionSecurity | TargetInfo;
        // Preserve only client-advertised key-strength flags while setting the
        // target type required by MS-NLMP section 2.2.1.2.
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

    /// <summary>
    /// Builds the NTLMv2 target information AV_PAIR list advertised in the challenge.
    /// </summary>
    /// <param name="auth">Authenticator containing configured target names.</param>
    /// <returns>A serialized AV_PAIR list terminated with MsvAvEOL.</returns>
    public static byte[] BuildTargetInfo(NtlmAuth auth)
    {
        using var stream = new MemoryStream();
        // AV pair ids are defined by MS-NLMP section 2.2.2.1: NetBIOS domain,
        // NetBIOS computer, DNS domain, DNS computer, and DNS tree respectively.
        WriteAvPair(stream, 2, auth.DomainName);
        WriteAvPair(stream, 1, auth.ServerName);
        WriteAvPair(stream, 4, auth.DnsDomainName);
        WriteAvPair(stream, 3, auth.DnsServerName);
        WriteAvPair(stream, 5, auth.DnsTreeName);
        Span<byte> eol = stackalloc byte[4];
        stream.Write(eol);
        return stream.ToArray();
    }

    /// <summary>
    /// Writes a single NTLM target-info AV_PAIR when a value is configured.
    /// </summary>
    /// <param name="stream">Destination stream for the serialized AV_PAIR.</param>
    /// <param name="id">AV_PAIR identifier defined by MS-NLMP section 2.2.2.1.</param>
    /// <param name="value">String value to encode as UTF-16LE.</param>
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

    /// <summary>
    /// Writes an NTLM security buffer descriptor.
    /// </summary>
    /// <param name="message">Message buffer receiving the descriptor.</param>
    /// <param name="offset">Offset where the descriptor starts.</param>
    /// <param name="length">Length and allocated length of the payload.</param>
    /// <param name="bufferOffset">Offset of the payload within the message.</param>
    private static void WriteSecurityBuffer(byte[] message, int offset, int length, int bufferOffset)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(offset), (ushort)length);
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(offset + 2), (ushort)length);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(offset + 4), (uint)bufferOffset);
    }
}
