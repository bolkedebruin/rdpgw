namespace Rdpgw.Rdp;

[AttributeUsage(AttributeTargets.Property)]
public sealed class RdpKeyAttribute(string key) : Attribute
{
    public string Key { get; } = key;
}

[AttributeUsage(AttributeTargets.Property)]
public sealed class RdpDefaultAttribute(string value) : Attribute
{
    public string Value { get; } = value;
}

public static class RdpCredentialSource
{
    public const int NTLM = 0;
    public const int SmartCard = 1;
    public const int Current = 2;
    public const int Basic = 3;
    public const int UserSelect = 4;
    public const int Cookie = 5;
}

public sealed class RdpSettings
{
    [RdpKey("allow font smoothing"), RdpDefault("0")] public bool AllowFontSmoothing { get; set; }
    [RdpKey("allow desktop composition"), RdpDefault("0")] public bool AllowDesktopComposition { get; set; }
    [RdpKey("disable full window drag"), RdpDefault("0")] public bool DisableFullWindowDrag { get; set; }
    [RdpKey("disable menu anims"), RdpDefault("0")] public bool DisableMenuAnims { get; set; }
    [RdpKey("disable themes"), RdpDefault("0")] public bool DisableThemes { get; set; }
    [RdpKey("disable cursor setting"), RdpDefault("0")] public bool DisableCursorSetting { get; set; }
    [RdpKey("gatewayhostname")] public string GatewayHostname { get; set; } = string.Empty;
    [RdpKey("full address")] public string FullAddress { get; set; } = string.Empty;
    [RdpKey("alternate full address")] public string AlternateFullAddress { get; set; } = string.Empty;
    [RdpKey("username")] public string Username { get; set; } = string.Empty;
    [RdpKey("domain")] public string Domain { get; set; } = string.Empty;
    [RdpKey("gatewaycredentialssource"), RdpDefault("0")] public int GatewayCredentialsSource { get; set; }
    [RdpKey("gatewayprofileusagemethod"), RdpDefault("0")] public int GatewayCredentialMethod { get; set; }
    [RdpKey("gatewayusagemethod"), RdpDefault("0")] public int GatewayUsageMethod { get; set; }
    [RdpKey("gatewayaccesstoken")] public string GatewayAccessToken { get; set; } = string.Empty;
    [RdpKey("promptcredentialonce"), RdpDefault("true")] public bool PromptCredentialsOnce { get; set; }
    [RdpKey("authentication level"), RdpDefault("3")] public int AuthenticationLevel { get; set; }
    [RdpKey("enablecredsspsupport"), RdpDefault("true")] public bool EnableCredSSPSupport { get; set; }
    [RdpKey("enablerdsaadauth"), RdpDefault("false")] public bool EnableRdsAasAuth { get; set; }
    [RdpKey("disableconnectionsharing"), RdpDefault("false")] public bool DisableConnectionSharing { get; set; }
    [RdpKey("alternate shell")] public string AlternateShell { get; set; } = string.Empty;
    [RdpKey("autoreconnection enabled"), RdpDefault("true")] public bool AutoReconnectionEnabled { get; set; }
    [RdpKey("bandwidthautodetect"), RdpDefault("true")] public bool BandwidthAutodetect { get; set; }
    [RdpKey("networkautodetect"), RdpDefault("true")] public bool NetworkAutodetect { get; set; }
    [RdpKey("compression"), RdpDefault("true")] public bool Compression { get; set; }
    [RdpKey("videoplaybackmode"), RdpDefault("true")] public bool VideoPlaybackMode { get; set; }
    [RdpKey("connection type"), RdpDefault("2")] public int ConnectionType { get; set; }
    [RdpKey("audiocapturemode"), RdpDefault("false")] public bool AudioCaptureMode { get; set; }
    [RdpKey("encode redirected video capture"), RdpDefault("true")] public bool EncodeRedirectedVideoCapture { get; set; }
    [RdpKey("redirected video capture encoding quality"), RdpDefault("0")] public int RedirectedVideoCaptureEncodingQuality { get; set; }
    [RdpKey("audiomode"), RdpDefault("0")] public int AudioMode { get; set; }
    [RdpKey("camerastoredirect"), RdpDefault("false")] public string CameraStoreRedirect { get; set; } = string.Empty;
    [RdpKey("devicestoredirect"), RdpDefault("false")] public string DeviceStoreRedirect { get; set; } = string.Empty;
    [RdpKey("drivestoredirect"), RdpDefault("false")] public string DriveStoreRedirect { get; set; } = string.Empty;
    [RdpKey("keyboardhook"), RdpDefault("2")] public int KeyboardHook { get; set; }
    [RdpKey("redirectclipboard"), RdpDefault("true")] public bool RedirectClipboard { get; set; }
    [RdpKey("redirectcomports"), RdpDefault("false")] public bool RedirectComPorts { get; set; }
    [RdpKey("redirectlocation"), RdpDefault("false")] public bool RedirectLocation { get; set; }
    [RdpKey("redirectprinters"), RdpDefault("true")] public bool RedirectPrinters { get; set; }
    [RdpKey("redirectsmartcards"), RdpDefault("true")] public bool RedirectSmartcards { get; set; }
    [RdpKey("redirectwebauthn"), RdpDefault("true")] public bool RedirectWebAuthn { get; set; }
    [RdpKey("usbdevicestoredirect")] public string UsbDeviceStoRedirect { get; set; } = string.Empty;
    [RdpKey("use multimon"), RdpDefault("false")] public bool UseMultimon { get; set; }
    [RdpKey("selectedmonitors")] public string SelectedMonitors { get; set; } = string.Empty;
    [RdpKey("maximizetocurrentdisplays"), RdpDefault("false")] public bool MaximizeToCurrentDisplays { get; set; }
    [RdpKey("singlemoninwindowedmode"), RdpDefault("0")] public bool SingleMonInWindowedMode { get; set; }
    [RdpKey("screen mode id"), RdpDefault("2")] public int ScreenModeId { get; set; }
    [RdpKey("smart sizing"), RdpDefault("false")] public bool SmartSizing { get; set; }
    [RdpKey("dynamic resolution"), RdpDefault("true")] public bool DynamicResolution { get; set; }
    [RdpKey("desktop size id")] public int DesktopSizeId { get; set; }
    [RdpKey("desktopheight")] public int DesktopHeight { get; set; }
    [RdpKey("desktopwidth")] public int DesktopWidth { get; set; }
    [RdpKey("desktopscalefactor")] public int DesktopScaleFactor { get; set; }
    [RdpKey("bitmapcachesize"), RdpDefault("1500")] public int BitmapCacheSize { get; set; }
    [RdpKey("bitmapcachepersistenable"), RdpDefault("true")] public bool BitmapCachePersistEnable { get; set; }
    [RdpKey("remoteapplicationcmdline")] public string RemoteApplicationCmdLine { get; set; } = string.Empty;
    [RdpKey("remoteapplicationexpandworkingdir"), RdpDefault("true")] public bool RemoteAppExpandWorkingDir { get; set; }
    [RdpKey("remoteapplicationfile"), RdpDefault("true")] public string RemoteApplicationFile { get; set; } = string.Empty;
    [RdpKey("remoteapplicationicon")] public string RemoteApplicationIcon { get; set; } = string.Empty;
    [RdpKey("remoteapplicationmode"), RdpDefault("false")] public bool RemoteApplicationMode { get; set; }
    [RdpKey("remoteapplicationname")] public string RemoteApplicationName { get; set; } = string.Empty;
    [RdpKey("remoteapplicationprogram")] public string RemoteApplicationProgram { get; set; } = string.Empty;
}
