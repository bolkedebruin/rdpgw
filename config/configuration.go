package config

type Configuration struct {
	Server ServerConfig
	OpenId OpenIDConfig
	Caps   RDGCapsConfig
}

type ServerConfig struct {
	GatewayAddress string
	Port           int
	CertFile       string
	KeyFile        string
	FarmHosts      []string
	EnableOverride bool
	HostTemplate   string
}

type OpenIDConfig struct {
	ProviderUrl	 string
	ClientId     string
	ClientSecret string
}

type RDGCapsConfig struct {
	SmartCardAuth    bool
	TokenAuth        bool
	IdleTimeout      int
	RedirectAll      bool
	DisableRedirect  bool
	DisableClipboard bool
	DisablePrinter   bool
	DisablePort      bool
	DisablePnp       bool
	DisableDrive     bool
}
