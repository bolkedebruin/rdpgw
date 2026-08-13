using Microsoft.AspNetCore.Mvc;
using Rdpgw.Config;

namespace Rdpgw.Security;

/// <summary>
/// Exposes the JSON Web Key Set (JWKS) endpoint for public key discovery.
/// </summary>
[ApiController]
public sealed class JwksController(SecurityConfigProvider securityConfigProvider) : ControllerBase
{
	/// <summary>
	/// Returns the JSON Web Key Set containing the public key parameters.
	/// </summary>
	/// <returns>JWKS JSON containing the RSA public key.</returns>
	[HttpGet("/.well-known/jwks.json")]
	[Produces("application/json")]
	public IActionResult GetJwks()
	{
		var messageRsa = securityConfigProvider.MessageSigningKey;
		var messageParameters = messageRsa.ExportParameters(includePrivateParameters: false);

		// Convert to Base64Url encoding (as per JWK specification)
		var messageModulus = Base64UrlEncode(messageParameters.Modulus!);
		var messageExponent = Base64UrlEncode(messageParameters.Exponent!);

		var messageSigningPublicKey = new
		{
			kty = "RSA",
			use = "sig",
			alg = "RS256",
			n = messageModulus,
			e = messageExponent,
			kid = "message"
		};

		var cookieRsa = securityConfigProvider.CookieSigningKey;
		var cookieParameters = cookieRsa.ExportParameters(includePrivateParameters: false);

		// Convert to Base64Url encoding (as per JWK specification)
		var cookieModulus = Base64UrlEncode(cookieParameters.Modulus!);
		var cookieExponent = Base64UrlEncode(cookieParameters.Exponent!);

		var cookieSigningPublicKey = new
		{
			kty = "RSA",
			use = "sig",
			alg = "RS256",
			n = cookieModulus,
			e = cookieExponent,
			kid = "cookie"
		};

		var jwks = new
		{
			keys = new[]
			{
				messageSigningPublicKey,
				cookieSigningPublicKey
			}
		};

		return Ok(jwks);
	}

	/// <summary>
	/// Encodes bytes to Base64Url format (URL-safe base64 without padding).
	/// </summary>
	private static string Base64UrlEncode(byte[] input)
	{
		var base64 = Convert.ToBase64String(input);
		// Convert to URL-safe format
		return base64
			.Replace('+', '-')
			.Replace('/', '_')
			.TrimEnd('=');
	}
}
