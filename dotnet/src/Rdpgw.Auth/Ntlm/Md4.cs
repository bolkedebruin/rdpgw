using System.Buffers.Binary;

namespace Rdpgw.Auth.Ntlm;

/// <summary>
/// Implements the MD4 hash algorithm required to derive NTLM password hashes.
/// </summary>
/// <remarks>
/// NTLM uses MD4 over the UTF-16LE password to produce the NTOWFv1 input used by
/// NTOWFv2, as described by MS-NLMP section 3.3.1.
/// </remarks>
internal static class Md4
{
    /// <summary>
    /// Computes the MD4 digest for the supplied input bytes.
    /// </summary>
    /// <param name="input">Message bytes to hash.</param>
    /// <returns>The 16-byte MD4 digest.</returns>
    public static byte[] Hash(byte[] input)
    {
        var bitLength = (ulong)input.Length * 8UL;
        var paddingLength = 56 - ((input.Length + 1) % 64);
        if (paddingLength < 0) paddingLength += 64;
        var message = new byte[input.Length + 1 + paddingLength + 8];
        Buffer.BlockCopy(input, 0, message, 0, input.Length);
        message[input.Length] = 0x80;
        // MD4 padding appends the original bit length as a little-endian 64-bit value.
        BinaryPrimitives.WriteUInt64LittleEndian(message.AsSpan(message.Length - 8), bitLength);

        uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
        for (var offset = 0; offset < message.Length; offset += 64)
        {
            var x = new uint[16];
            for (var i = 0; i < 16; i++)
            {
                x[i] = BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(offset + i * 4));
            }

            var aa = a; var bb = b; var cc = c; var dd = d;
            // MD4 processes each 512-bit block through three rounds with fixed
            // word order and rotations (RFC 1320 section 3.4).
            Round1(ref a, b, c, d, x[0], 3); Round1(ref d, a, b, c, x[1], 7); Round1(ref c, d, a, b, x[2], 11); Round1(ref b, c, d, a, x[3], 19);
            Round1(ref a, b, c, d, x[4], 3); Round1(ref d, a, b, c, x[5], 7); Round1(ref c, d, a, b, x[6], 11); Round1(ref b, c, d, a, x[7], 19);
            Round1(ref a, b, c, d, x[8], 3); Round1(ref d, a, b, c, x[9], 7); Round1(ref c, d, a, b, x[10], 11); Round1(ref b, c, d, a, x[11], 19);
            Round1(ref a, b, c, d, x[12], 3); Round1(ref d, a, b, c, x[13], 7); Round1(ref c, d, a, b, x[14], 11); Round1(ref b, c, d, a, x[15], 19);

            Round2(ref a, b, c, d, x[0], 3); Round2(ref d, a, b, c, x[4], 5); Round2(ref c, d, a, b, x[8], 9); Round2(ref b, c, d, a, x[12], 13);
            Round2(ref a, b, c, d, x[1], 3); Round2(ref d, a, b, c, x[5], 5); Round2(ref c, d, a, b, x[9], 9); Round2(ref b, c, d, a, x[13], 13);
            Round2(ref a, b, c, d, x[2], 3); Round2(ref d, a, b, c, x[6], 5); Round2(ref c, d, a, b, x[10], 9); Round2(ref b, c, d, a, x[14], 13);
            Round2(ref a, b, c, d, x[3], 3); Round2(ref d, a, b, c, x[7], 5); Round2(ref c, d, a, b, x[11], 9); Round2(ref b, c, d, a, x[15], 13);

            Round3(ref a, b, c, d, x[0], 3); Round3(ref d, a, b, c, x[8], 9); Round3(ref c, d, a, b, x[4], 11); Round3(ref b, c, d, a, x[12], 15);
            Round3(ref a, b, c, d, x[2], 3); Round3(ref d, a, b, c, x[10], 9); Round3(ref c, d, a, b, x[6], 11); Round3(ref b, c, d, a, x[14], 15);
            Round3(ref a, b, c, d, x[1], 3); Round3(ref d, a, b, c, x[9], 9); Round3(ref c, d, a, b, x[5], 11); Round3(ref b, c, d, a, x[13], 15);
            Round3(ref a, b, c, d, x[3], 3); Round3(ref d, a, b, c, x[11], 9); Round3(ref c, d, a, b, x[7], 11); Round3(ref b, c, d, a, x[15], 15);

            a += aa; b += bb; c += cc; d += dd;
        }

        var output = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(0), a);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(4), b);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(8), c);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(12), d);
        return output;
    }

    /// <summary>
    /// MD4 round 1 boolean function.
    /// </summary>
    private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);

    /// <summary>
    /// MD4 round 2 boolean function.
    /// </summary>
    private static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);

    /// <summary>
    /// MD4 round 3 boolean function.
    /// </summary>
    private static uint H(uint x, uint y, uint z) => x ^ y ^ z;

    /// <summary>
    /// Applies one MD4 round 1 operation.
    /// </summary>
    private static void Round1(ref uint a, uint b, uint c, uint d, uint x, int s) => a = uint.RotateLeft(a + F(b, c, d) + x, s);

    /// <summary>
    /// Applies one MD4 round 2 operation.
    /// </summary>
    private static void Round2(ref uint a, uint b, uint c, uint d, uint x, int s) => a = uint.RotateLeft(a + G(b, c, d) + x + 0x5a827999, s);

    /// <summary>
    /// Applies one MD4 round 3 operation.
    /// </summary>
    private static void Round3(ref uint a, uint b, uint c, uint d, uint x, int s) => a = uint.RotateLeft(a + H(b, c, d) + x + 0x6ed9eba1, s);
}
