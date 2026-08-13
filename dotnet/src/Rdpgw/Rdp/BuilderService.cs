using Rdpgw.Data;
using Rdpgw.Security;
using System.Reflection;

namespace Rdpgw.Rdp;

/// <summary>Builds .rdp file content from defaults, templates, and validated overrides.</summary>
public sealed class BuilderService(ILogger<BuilderService> logger, ITokenService tokenService, RdpgwDbContext dbContext) : IBuilderService
{
	/// <summary>Mutable RDP settings used when rendering the file.</summary>
	public RdpSettings Settings { get; } = new();

	public async Task<string> BuildRdpFile(string clientIp, string user, int hostEntryId)
	{
		using var _ = logger.BeginScope(new { clientIp, user, hostEntryId });

		// Validate the host entry exists in the database.
		var hostEntry = dbContext.Hosts.Find(hostEntryId);
		if (hostEntry == null)
		{
			logger.LogError("Host entry {HostEntryId} not found", hostEntryId);
			throw new InvalidOperationException($"Host entry {hostEntryId} not found");
		}

		// Create the RDP gateway authentication token
		string token;
		try
		{
			token = await tokenService.GeneratePAAToken(clientIp, user, hostEntry.Address);
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "Cannot generate PAA token for user {User}", user);
			throw new InvalidOperationException($"Cannot generate PAA token for user {user}", ex);
		}

#warning parse template file for overlay settings
		var templateRdpSettings = new RdpSettings(); //RdpSettings.FromFile();

		var requiredRdpSettings = new RdpSettings()
		{
			FullAddress = hostEntry.Address,
			GatewayCredentialsSource = RdpCredentialSource.Cookie,
			GatewayAccessToken = token,
			GatewayCredentialMethod = 1,
			GatewayUsageMethod = 1
		};

		var rdpSettings = new RdpSettings()
			.ApplySettings(templateRdpSettings)
			.ApplySettings(requiredRdpSettings);

		return rdpSettings.Serialize();
	}

	/// <summary>Normalizes an RDP setting key for case-insensitive allow-list matching.</summary>
	/// <param name="s">Raw RDP key.</param>
	/// <returns>Lowercase key with spaces removed.</returns>
	public static string NormalizeRdpKey(string s) => s.Trim().ToLowerInvariant().Replace(" ", string.Empty);

	private void SetValue(PropertyInfo prop, string value)
	{
		// RDP files encode booleans as integer-like strings, while templates may use true/false.
		if (prop.PropertyType == typeof(string)) prop.SetValue(Settings, value);
		else if (prop.PropertyType == typeof(int)) prop.SetValue(Settings, int.Parse(value));
		else if (prop.PropertyType == typeof(bool))
		{
			prop.SetValue(Settings, value.ToLowerInvariant() switch
			{
				"1" or "true" => true,
				"0" or "false" => false,
				_ => throw new FormatException($"expected 0/1 or true/false, got {value}")
			});
		}
	}

	private string SanitizeRdpValue(string field, string value)
	{
		// Strip control bytes so user-controlled values cannot inject extra RDP directives.
		if (value.All(c => c >= 0x20 && c != 0x7f)) return value;
		logger.LogWarning("rdp: stripped control bytes from field {Field}", field);
		return new string([.. value.Where(c => c >= 0x20 && c != 0x7f)]);
	}

	/// <summary>Signs RDP content using a certificate and private key.</summary>
	/// <param name="rdpContent">RDP file content to sign.</param>
	/// <param name="certificatePath">Path to the signing certificate.</param>
	/// <param name="privateKeyPath">Path to the private key.</param>
	/// <returns>The signed RDP file bytes.</returns>
	/// <exception cref="NotSupportedException">Always thrown until rdpsign-compatible signing is implemented.</exception>
	public static byte[] Sign(string rdpContent, string certificatePath, string privateKeyPath)
	{
		// TODO: rdpsign-compatible RDP signature generation requires the exact mstsc signature envelope.
		throw new NotSupportedException("RDP file signing is not implemented in the .NET port yet");
	}
}
