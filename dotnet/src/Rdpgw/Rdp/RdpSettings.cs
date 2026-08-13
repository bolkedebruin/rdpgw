using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using static Prometheus.MetricServerMiddleware;

namespace Rdpgw.Rdp;

/// <summary>Associates an <see cref="RdpSettings" /> property with its .rdp file key.</summary>
/// <param name="key">Exact key text used in the RDP file.</param>
[AttributeUsage(AttributeTargets.Property)]
public sealed class RdpKeyAttribute(string key) : Attribute
{
    /// <summary>Gets the exact key text used in the RDP file.</summary>
    public string Key { get; } = key;
}

/// <summary>Specifies the default serialized value for an RDP setting.</summary>
/// <param name="value">Default value as it appears in RDP file syntax.</param>
[AttributeUsage(AttributeTargets.Property)]
public sealed class RdpDefaultAttribute(string value) : Attribute
{
    /// <summary>Gets the default value text for the setting.</summary>
    public string Value { get; } = value;
}

/// <summary>Credential source values understood by Microsoft Remote Desktop clients.</summary>
public static class RdpCredentialSource
{
    /// <summary>Prompt for NTLM credentials.</summary>
    public const int NTLM = 0;
    /// <summary>Use smart-card credentials.</summary>
    public const int SmartCard = 1;
    /// <summary>Use the current logged-on user credentials.</summary>
    public const int Current = 2;
    /// <summary>Prompt for basic username and password credentials.</summary>
    public const int Basic = 3;
    /// <summary>Allow the user to select the credential source.</summary>
    public const int UserSelect = 4;
    /// <summary>Use a gateway access token or cookie credential source.</summary>
    public const int Cookie = 5;
}

public static class RdpSettingsExtensions
{
	/// <summary>Line ending required by RDP file format entries.</summary>
	public const string RdpNewline = "\r\n";

	public static RdpSettings ApplySettings(this RdpSettings settings, RdpSettings applySettings)
    {
		foreach (var property in typeof(RdpSettings).GetProperties())
		{
			// Skip properties that don't have the RdpKeyAttribute
			if (property.GetCustomAttribute<RdpKeyAttribute>() is not RdpKeyAttribute attribute)
			{
				continue;
			}

			// Skip properties that are unset
			var value = property.GetValue(applySettings);
			if (value is null)
			{
				continue;
			}

            property.SetValue(settings, value);
		}

		return settings;
	}

	/// <summary>Serializes the current settings to .rdp text.</summary>
	/// <returns>RDP file content using CRLF line endings.</returns>
	public static string Serialize(this RdpSettings settings)
	{
		var stringBuilder = new StringBuilder();

		// Use reflection to retrieve all properties
		foreach (var property in typeof(RdpSettings).GetProperties())
		{
			// Skip properties that don't have the RdpKeyAttribute
			if (property.GetCustomAttribute<RdpKeyAttribute>() is not RdpKeyAttribute attribute)
            {
                continue;
            }

            // Skip properties that are unset
            var value = property.GetValue(settings);
            if (value is null)
            {
                continue;
            }

            stringBuilder
                .Append(attribute.Key)
                .Append(':')
                .Append(value switch
                {
                    string strValue => $"s:{strValue}",
                    int intValue => $"i:{intValue}",
                    bool boolValue => $"i:{(boolValue ? 1 : 0)}",
                    _ => throw new InvalidOperationException($"Unsupported property type: {property.PropertyType}")
                });
		}

		return stringBuilder.ToString();
	}
}

/// <summary>Strongly typed set of RDP file settings emitted by <see cref="BuilderService" />.</summary>
public sealed class RdpSettings
{
    /// <summary>Controls font smoothing in the remote session.</summary>
    [RdpKey("allow font smoothing"), RdpDefault("0")]
    public bool AllowFontSmoothing { get; set; }
    
    /// <summary>Controls desktop composition effects in the remote session.</summary>
    [RdpKey("allow desktop composition"), RdpDefault("0")]
    public bool AllowDesktopComposition { get; set; }
    
    /// <summary>Disables full-window drag rendering when true.</summary>
    [RdpKey("disable full window drag"), RdpDefault("0")]
    public bool DisableFullWindowDrag { get; set; }
    
    /// <summary>Disables menu animations when true.</summary>
    [RdpKey("disable menu anims"), RdpDefault("0")]
    public bool DisableMenuAnims { get; set; }
    
    /// <summary>Disables visual themes when true.</summary>
    [RdpKey("disable themes"), RdpDefault("0")]
    public bool DisableThemes { get; set; }
    
    /// <summary>Disables remote cursor setting changes when true.</summary>
    [RdpKey("disable cursor setting"), RdpDefault("0")]
    public bool DisableCursorSetting { get; set; }
    
    /// <summary>RD Gateway host name that the RDP client should use.</summary>
    [RdpKey("gatewayhostname")]
    public string GatewayHostname { get; set; } = string.Empty;
    
    /// <summary>Primary target computer address for the RDP session.</summary>
    [RdpKey("full address")]
    public string FullAddress { get; set; } = string.Empty;
    
    /// <summary>Alternate target computer address shown to the RDP client.</summary>
    [RdpKey("alternate full address")]
    public string AlternateFullAddress { get; set; } = string.Empty;
    
    /// <summary>Username prefilled in the RDP client.</summary>
    [RdpKey("username")]
    public string Username { get; set; } = string.Empty;
    
    /// <summary>Domain prefilled in the RDP client.</summary>
    [RdpKey("domain")]
    public string Domain { get; set; } = string.Empty;
    
    /// <summary>Credential source used for RD Gateway authentication.</summary>
    [RdpKey("gatewaycredentialssource"), RdpDefault("0")]
    public int GatewayCredentialsSource { get; set; }
    
    /// <summary>Gateway profile usage method setting.</summary>
    [RdpKey("gatewayprofileusagemethod"), RdpDefault("0")]
    public int GatewayCredentialMethod { get; set; }
    
    /// <summary>Controls whether and how the RD Gateway is used.</summary>
    [RdpKey("gatewayusagemethod"), RdpDefault("0")]
    public int GatewayUsageMethod { get; set; }
    
    /// <summary>Access token passed to clients that support token-based gateway authentication.</summary>
    [RdpKey("gatewayaccesstoken")]
    public string GatewayAccessToken { get; set; } = string.Empty;
    
    /// <summary>Controls whether the client prompts once for both gateway and target credentials.</summary>
    [RdpKey("promptcredentialonce"), RdpDefault("true")]
    public bool PromptCredentialsOnce { get; set; }
    
    /// <summary>Server authentication level required by the RDP client.</summary>
    [RdpKey("authentication level"), RdpDefault("3")]
    public int AuthenticationLevel { get; set; }
    
    /// <summary>Enables CredSSP support when true.</summary>
    [RdpKey("enablecredsspsupport"), RdpDefault("true")]
    public bool EnableCredSSPSupport { get; set; }
    
    /// <summary>Enables Azure AD/RDS AAD authentication when true.</summary>
    [RdpKey("enablerdsaadauth"), RdpDefault("false")]
    public bool EnableRdsAasAuth { get; set; }
    
    /// <summary>Disables RDP connection sharing when true.</summary>
    [RdpKey("disableconnectionsharing"), RdpDefault("false")]
    public bool DisableConnectionSharing { get; set; }
    
    /// <summary>Alternate shell or program to start after logon.</summary>
    [RdpKey("alternate shell")]
    public string AlternateShell { get; set; } = string.Empty;
    
    /// <summary>Enables automatic reconnection after transient network loss.</summary>
    [RdpKey("autoreconnection enabled"), RdpDefault("true")]
    public bool AutoReconnectionEnabled { get; set; }
    
    /// <summary>Enables bandwidth auto-detection.</summary>
    [RdpKey("bandwidthautodetect"), RdpDefault("true")]
    public bool BandwidthAutodetect { get; set; }
    
    /// <summary>Enables network characteristics auto-detection.</summary>
    [RdpKey("networkautodetect"), RdpDefault("true")]
    public bool NetworkAutodetect { get; set; }
    
    /// <summary>Enables RDP bulk compression.</summary>
    [RdpKey("compression"), RdpDefault("true")]
    public bool Compression { get; set; }
    
    /// <summary>Enables optimized video playback mode.</summary>
    [RdpKey("videoplaybackmode"), RdpDefault("true")]
    public bool VideoPlaybackMode { get; set; }
    
    /// <summary>Client connection type hint used for experience settings.</summary>
    [RdpKey("connection type"), RdpDefault("2")]
    public int ConnectionType { get; set; }
    
    /// <summary>Controls redirection of microphone/audio capture.</summary>
    [RdpKey("audiocapturemode"), RdpDefault("false")]
    public bool AudioCaptureMode { get; set; }
    
    /// <summary>Controls encoding for redirected video capture devices.</summary>
    [RdpKey("encode redirected video capture"), RdpDefault("true")]
    public bool EncodeRedirectedVideoCapture { get; set; }
    
    /// <summary>Encoding quality for redirected video capture devices.</summary>
    [RdpKey("redirected video capture encoding quality"), RdpDefault("0")]
    public int RedirectedVideoCaptureEncodingQuality { get; set; }
    
    /// <summary>Controls how remote audio playback is handled.</summary>
    [RdpKey("audiomode"), RdpDefault("0")]
    public int AudioMode { get; set; }
    
    /// <summary>Camera redirection device selector.</summary>
    [RdpKey("camerastoredirect"), RdpDefault("false")]
    public string CameraStoreRedirect { get; set; } = string.Empty;
    
    /// <summary>Generic device redirection selector.</summary>
    [RdpKey("devicestoredirect"), RdpDefault("false")]
    public string DeviceStoreRedirect { get; set; } = string.Empty;
    
    /// <summary>Drive redirection selector.</summary>
    [RdpKey("drivestoredirect"), RdpDefault("false")]
    public string DriveStoreRedirect { get; set; } = string.Empty;
    
    /// <summary>Controls where Windows key combinations are applied.</summary>
    [RdpKey("keyboardhook"), RdpDefault("2")]
    public int KeyboardHook { get; set; }
    
    /// <summary>Enables clipboard redirection when true.</summary>
    [RdpKey("redirectclipboard"), RdpDefault("true")]
    public bool RedirectClipboard { get; set; }
    
    /// <summary>Enables COM port redirection when true.</summary>
    [RdpKey("redirectcomports"), RdpDefault("false")]
    public bool RedirectComPorts { get; set; }
    
    /// <summary>Enables location redirection when true.</summary>
    [RdpKey("redirectlocation"), RdpDefault("false")]
    public bool RedirectLocation { get; set; }
    
    /// <summary>Enables printer redirection when true.</summary>
    [RdpKey("redirectprinters"), RdpDefault("true")]
    public bool RedirectPrinters { get; set; }
    
    /// <summary>Enables smart-card redirection when true.</summary>
    [RdpKey("redirectsmartcards"), RdpDefault("true")]
    public bool RedirectSmartcards { get; set; }
    
    /// <summary>Enables WebAuthn redirection when true.</summary>
    [RdpKey("redirectwebauthn"), RdpDefault("true")]
    public bool RedirectWebAuthn { get; set; }
    
    /// <summary>USB device redirection selector.</summary>
    [RdpKey("usbdevicestoredirect")]
    public string UsbDeviceStoRedirect { get; set; } = string.Empty;
    
    /// <summary>Enables multi-monitor mode when true.</summary>
    [RdpKey("use multimon"), RdpDefault("false")]
    public bool UseMultimon { get; set; }
    
    /// <summary>Comma-separated monitor list used for multi-monitor sessions.</summary>
    [RdpKey("selectedmonitors")]
    public string SelectedMonitors { get; set; } = string.Empty;
    
    /// <summary>Maximizes to the current displays when true.</summary>
    [RdpKey("maximizetocurrentdisplays"), RdpDefault("false")]
    public bool MaximizeToCurrentDisplays { get; set; }
    
    /// <summary>Uses a single monitor when the client is windowed.</summary>
    [RdpKey("singlemoninwindowedmode"), RdpDefault("0")]
    public bool SingleMonInWindowedMode { get; set; }
    
    /// <summary>Controls windowed versus full-screen mode.</summary>
    [RdpKey("screen mode id"), RdpDefault("2")]
    public int ScreenModeId { get; set; }
    
    /// <summary>Enables smart sizing when true.</summary>
    [RdpKey("smart sizing"), RdpDefault("false")]
    public bool SmartSizing { get; set; }
    
    /// <summary>Enables dynamic resolution updates when true.</summary>
    [RdpKey("dynamic resolution"), RdpDefault("true")]
    public bool DynamicResolution { get; set; }
    
    /// <summary>Preset desktop size identifier.</summary>
    [RdpKey("desktop size id")]
    public int DesktopSizeId { get; set; }
    
    /// <summary>Requested desktop height in pixels.</summary>
    [RdpKey("desktopheight")]
    public int DesktopHeight { get; set; }
    
    /// <summary>Requested desktop width in pixels.</summary>
    [RdpKey("desktopwidth")]
    public int DesktopWidth { get; set; }
    
    /// <summary>Requested desktop scale factor percentage.</summary>
    [RdpKey("desktopscalefactor")]
    public int DesktopScaleFactor { get; set; }
    
    /// <summary>Bitmap cache size setting.</summary>
    [RdpKey("bitmapcachesize"), RdpDefault("1500")]
    public int BitmapCacheSize { get; set; }
    
    /// <summary>Enables persistent bitmap caching when true.</summary>
    [RdpKey("bitmapcachepersistenable"), RdpDefault("true")]
    public bool BitmapCachePersistEnable { get; set; }
    
    /// <summary>Command-line arguments for RemoteApp launch.</summary>
    [RdpKey("remoteapplicationcmdline")]
    public string RemoteApplicationCmdLine { get; set; } = string.Empty;
    
    /// <summary>Expands the RemoteApp working directory when true.</summary>
    [RdpKey("remoteapplicationexpandworkingdir"), RdpDefault("true")]
    public bool RemoteAppExpandWorkingDir { get; set; }
    
    /// <summary>RemoteApp file association setting.</summary>
    [RdpKey("remoteapplicationfile"), RdpDefault("true")]
    public string RemoteApplicationFile { get; set; } = string.Empty;
    
    /// <summary>Icon path or resource for the RemoteApp entry.</summary>
    [RdpKey("remoteapplicationicon")]
    public string RemoteApplicationIcon { get; set; } = string.Empty;
    
    /// <summary>Enables RemoteApp mode when true.</summary>
    [RdpKey("remoteapplicationmode"), RdpDefault("false")]
    public bool RemoteApplicationMode { get; set; }
    
    /// <summary>Display name of the RemoteApp program.</summary>
    [RdpKey("remoteapplicationname")]
    public string RemoteApplicationName { get; set; } = string.Empty;
    
    /// <summary>RemoteApp program alias or path.</summary>
    [RdpKey("remoteapplicationprogram")]
    public string RemoteApplicationProgram { get; set; } = string.Empty;
}
