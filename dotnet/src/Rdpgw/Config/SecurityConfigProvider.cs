using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace Rdpgw.Config;

public sealed partial class SecurityConfigProvider
{
	private readonly ILogger<SecurityConfigProvider> _logger;
	private readonly SecurityConfig _securityConfig;

	public RSA MessageSigningKey { get; }

	public RSA CookieSigningKey { get; }

	public byte[] SigningKey { get; }

	public byte[] EncryptionKey { get; }

	public byte[] UserEncryptionKey { get; }

	public byte[] UserSigningKey { get; }

	public byte[] QuerySigningKey { get; }

	/// <summary>Gets the pre-shared key used to authenticate gateway registration requests.</summary>
	public byte[] GatewayRegistrationKey { get; }

	public TimeSpan ExpiryTime => _securityConfig.ExpiryTime;

	/// <summary>Context item key holding the target server authorized by a validated PAA token.</summary>
	public const string TunnelTargetServerKey = "Rdpgw.Security.TargetServer";
	/// <summary>Context item key holding the client IP bound into a validated PAA token.</summary>
	public const string TunnelRemoteAddrKey = "Rdpgw.Security.RemoteAddr";

	public SecurityConfigProvider(ILogger<SecurityConfigProvider> logger, IOptions<SecurityConfig> options)
	{
		_logger = logger;
		_securityConfig = options.Value;

		MessageSigningKey = RSA.Create();
		MessageSigningKey.ImportFromPem(_securityConfig.MessageSigningPrivateKey);

		CookieSigningKey = RSA.Create();
		CookieSigningKey.ImportFromPem(_securityConfig.CookieSigningPrivateKey);

		SigningKey = GetKeyBytes("PAATokenSigningKey", _securityConfig.PAATokenSigningKey);
		EncryptionKey = GetKeyBytes("PAATokenEncryptionKey", _securityConfig.PAATokenEncryptionKey);
		UserSigningKey = GetKeyBytes("UserTokenSigningKey", _securityConfig.UserTokenSigningKey);
		UserEncryptionKey = GetKeyBytes("UserTokenEncryptionKey", _securityConfig.UserTokenEncryptionKey);
		QuerySigningKey = GetKeyBytes("QueryTokenSigningKey", _securityConfig.QueryTokenSigningKey);
		GatewayRegistrationKey = GetKeyBytes("GatewayRegistrationKey", _securityConfig.GatewayRegistrationKey);
	}

	private byte[] GetKeyBytes(string type, string key)
	{
		if (string.IsNullOrEmpty(key))
		{
			_logger.LogCritical("Security configuration for {Type} is missing or empty.", type);
			throw new InvalidOperationException($"Security configuration for {type} is missing or empty.");
		}

		var keyBytes = System.Text.Encoding.UTF8.GetBytes(key);

		if (keyBytes.Length < 32)
		{
			_logger.LogCritical("Signing key for {Type} not long enough.", type);
			throw new InvalidOperationException($"Signing key for {type} not long enough.");
		}

		return keyBytes;
	}
}
