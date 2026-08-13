using System.Security.Cryptography;

namespace Rdpgw.Security;

/// <summary>A single key entry from a JSON Web Key Set document.</summary>
public sealed record JwkKey
{
	public string Kty { get; init; } = string.Empty;
	public string Use { get; init; } = string.Empty;
	public string Alg { get; init; } = string.Empty;
	public string N { get; init; } = string.Empty;
	public string E { get; init; } = string.Empty;
	public string Kid { get; init; } = string.Empty;
}

/// <summary>A JSON Web Key Set document as returned by a <c>/.well-known/jwks.json</c> endpoint.</summary>
public sealed record JwksDocument
{
	public List<JwkKey> Keys { get; init; } = [];
}

/// <summary>Helpers for decoding RSA public keys out of JWK entries.</summary>
public static class JwkRsaConverter
{
	/// <summary>Builds an RSA public key from a JWK's modulus and exponent.</summary>
	/// <param name="key">JWK entry containing base64url-encoded RSA parameters.</param>
	/// <returns>An RSA instance holding only the public key.</returns>
	public static RSA ToRsaPublicKey(JwkKey key)
	{
		var rsa = RSA.Create();
		rsa.ImportParameters(new RSAParameters
		{
			Modulus = Base64UrlDecode(key.N),
			Exponent = Base64UrlDecode(key.E),
		});
		return rsa;
	}

	/// <summary>Decodes a base64url string (as used by JWK) into raw bytes.</summary>
	public static byte[] Base64UrlDecode(string input)
	{
		var base64 = input.Replace('-', '+').Replace('_', '/');
		var padding = (4 - base64.Length % 4) % 4;
		base64 += new string('=', padding);
		return Convert.FromBase64String(base64);
	}

	/// <summary>Builds a PEM-encoded RSA public key from a JWK entry, for storage in <c>GatewayEntry.GatewaySigningKey</c>.</summary>
	/// <param name="key">JWK entry containing base64url-encoded RSA parameters.</param>
	/// <returns>The public key encoded as a SubjectPublicKeyInfo PEM string.</returns>
	public static string ToPem(JwkKey key)
	{
		using var rsa = ToRsaPublicKey(key);
		return rsa.ExportSubjectPublicKeyInfoPem();
	}
}
