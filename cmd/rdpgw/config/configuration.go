package config

import (
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"log"
	"strings"
)

const (
	TlsDisable = "disable"
	TlsAuto    = "auto"

	HostSelectionSigned     = "signed"
	HostSelectionRoundRobin = "roundrobin"

	SessionStoreCookie = "cookie"
	SessionStoreFile   = "file"

	AuthenticationOpenId   = "openid"
	AuthenticationBasic    = "local"
	AuthenticationKerberos = "kerberos"
)

type Configuration struct {
	Server   ServerConfig   `koanf:"server"`
	OpenId   OpenIDConfig   `koanf:"openid"`
	Kerberos KerberosConfig `koanf:"kerberos"`
	Caps     RDGCapsConfig  `koanf:"caps"`
	Security SecurityConfig `koanf:"security"`
	Client   ClientConfig   `koanf:"client"`
}

type ServerConfig struct {
	GatewayAddress       string   `koanf:"gatewayaddress"`
	Port                 int      `koanf:"port"`
	CertFile             string   `koanf:"certfile"`
	KeyFile              string   `koanf:"keyfile"`
	Hosts                []string `koanf:"hosts"`
	HostSelection        string   `koanf:"hostselection"`
	SessionKey           string   `koanf:"sessionkey"`
	SessionEncryptionKey string   `koanf:"sessionencryptionkey"`
	SessionStore         string   `koanf:"sessionstore"`
	MaxSessionLength     int      `koanf:"maxsessionlength"`
	SendBuf              int      `koanf:"sendbuf"`
	ReceiveBuf           int      `koanf:"receivebuf"`
	Tls                  string   `koanf:"tls"`
	Authentication       []string `koanf:"authentication"`
	AuthSocket           string   `koanf:"authsocket"`
}

type KerberosConfig struct {
	Keytab   string `koanf:"keytab"`
	Krb5Conf string `koanf:"krb5conf"`
}

type OpenIDConfig struct {
	ProviderUrl  string `koanf:"providerurl"`
	ClientId     string `koanf:"clientid"`
	ClientSecret string `koanf:"clientsecret"`
}

type RDGCapsConfig struct {
	SmartCardAuth   bool `koanf:"smartcardauth"`
	TokenAuth       bool `koanf:"tokenauth"`
	IdleTimeout     int  `koanf:"idletimeout"`
	RedirectAll     bool `koanf:"redirectall"`
	DisableRedirect bool `koanf:"disableredirect"`
	EnableClipboard bool `koanf:"enableclipboard"`
	EnablePrinter   bool `koanf:"enableprinter"`
	EnablePort      bool `koanf:"enableport"`
	EnablePnp       bool `koanf:"enablepnp"`
	EnableDrive     bool `koanf:"enabledrive"`
}

type SecurityConfig struct {
	PAATokenEncryptionKey  string `koanf:"paatokenencryptionkey"`
	PAATokenSigningKey     string `koanf:"paatokensigningkey"`
	UserTokenEncryptionKey string `koanf:"usertokenencryptionkey"`
	UserTokenSigningKey    string `koanf:"usertokensigningkey"`
	QueryTokenSigningKey   string `koanf:"querytokensigningkey"`
	QueryTokenIssuer       string `koanf:"querytokenissuer"`
	VerifyClientIp         bool   `koanf:"verifyclientip"`
	EnableUserToken        bool   `koanf:"enableusertoken"`
}

type ClientConfig struct {
	NetworkAutoDetect           int               `koanf:"networkautodetect"`
	BandwidthAutoDetect         int               `koanf:"bandwidthautodetect"`
	ConnectionType              int               `koanf:"connectiontype"`
	UsernameTemplate            string            `koanf:"usernametemplate"`
	SplitUserDomain             bool              `koanf:"splituserdomain"`
	DefaultDomain               string            `koanf:"defaultdomain"`
	ExtraSettings               map[string]interface{} `koanf:"extrasettings"`
	AllowExtraSettingsFromQuery bool              `koanf:"allowextrasettingsfromquery"`
}

func ToCamel(s string) string {
	s = strings.TrimSpace(s)
	n := strings.Builder{}
	n.Grow(len(s))
	var capNext bool = true
	for i, v := range []byte(s) {
		vIsCap := v >= 'A' && v <= 'Z'
		vIsLow := v >= 'a' && v <= 'z'
		if capNext {
			if vIsLow {
				v += 'A'
				v -= 'a'
			}
		} else if i == 0 {
			if vIsCap {
				v += 'a'
				v -= 'A'
			}
		}
		if vIsCap || vIsLow {
			n.WriteByte(v)
			capNext = false
		} else if vIsNum := v >= '0' && v <= '9'; vIsNum {
			n.WriteByte(v)
			capNext = true
		} else {
			capNext = v == '_' || v == ' ' || v == '-' || v == '.'
			if v == '.' {
				n.WriteByte(v)
			}
		}
	}
	return n.String()
}

var Conf Configuration

func Load(configFile string) Configuration {

	var k = koanf.New(".")

	k.Load(confmap.Provider(map[string]interface{}{
		"Server.Tls":                         "auto",
		"Server.Port":                        443,
		"Server.SessionStore":                "cookie",
		"Server.HostSelection":               "roundrobin",
		"Server.Authentication":              "openid",
		"Server.AuthSocket":                  "/tmp/rdpgw-auth.sock",
		"Client.NetworkAutoDetect":           1,
		"Client.BandwidthAutoDetect":         1,
		"Client.AllowExtraSettingsFromQuery": false,
		"Security.VerifyClientIp":            true,
		"Caps.TokenAuth":                     true,
	}, "."), nil)

	if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		log.Fatalf("Error loading config from file: %v", err)
	}

	if err := k.Load(env.ProviderWithValue("RDPGW_", ".", func(s string, v string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(s, "RDPGW_")), "__", ".", -1)
		key = ToCamel(key)
		return key, v
	}), nil); err != nil {
		log.Fatalf("Error loading config from file: %v", err)
	}

	koanfTag := koanf.UnmarshalConf{Tag: "koanf"}
	k.UnmarshalWithConf("Server", &Conf.Server, koanfTag)
	k.UnmarshalWithConf("OpenId", &Conf.OpenId, koanfTag)
	k.UnmarshalWithConf("Caps", &Conf.Caps, koanfTag)
	k.UnmarshalWithConf("Security", &Conf.Security, koanfTag)
	k.UnmarshalWithConf("Client", &Conf.Client, koanfTag)
	k.UnmarshalWithConf("Kerberos", &Conf.Kerberos, koanfTag)

	if len(Conf.Security.PAATokenEncryptionKey) != 32 {
		Conf.Security.PAATokenEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokenencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(Conf.Security.PAATokenSigningKey) != 32 {
		Conf.Security.PAATokenSigningKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokensigningkey` specified (empty or not 32 characters). Setting to random")
	}

	if Conf.Security.EnableUserToken {
		if len(Conf.Security.UserTokenEncryptionKey) != 32 {
			Conf.Security.UserTokenEncryptionKey, _ = security.GenerateRandomString(32)
			log.Printf("No valid `security.usertokenencryptionkey` specified (empty or not 32 characters). Setting to random")
		}

		if len(Conf.Security.UserTokenSigningKey) != 32 {
			Conf.Security.UserTokenSigningKey, _ = security.GenerateRandomString(32)
			log.Printf("No valid `security.usertokensigningkey` specified (empty or not 32 characters). Setting to random")
		}
	}

	if len(Conf.Server.SessionKey) != 32 {
		Conf.Server.SessionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(Conf.Server.SessionEncryptionKey) != 32 {
		Conf.Server.SessionEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if Conf.Server.HostSelection == "signed" && len(Conf.Security.QueryTokenSigningKey) == 0 {
		log.Fatalf("host selection is set to `signed` but `querytokensigningkey` is not set")
	}

	if Conf.Server.BasicAuthEnabled() && Conf.Server.Tls == "disable" {
		log.Fatalf("basicauth=local and tls=disable are mutually exclusive")
	}

	if !Conf.Caps.TokenAuth && Conf.Server.OpenIDEnabled() {
		log.Fatalf("openid is configured but tokenauth disabled")
	}

	if Conf.Server.KerberosEnabled() && Conf.Kerberos.Keytab == "" {
		log.Fatalf("kerberos is configured but no keytab was specified")
	}

	// prepend '//' if required for URL parsing
	if !strings.Contains(Conf.Server.GatewayAddress, "//") {
		Conf.Server.GatewayAddress = "//" + Conf.Server.GatewayAddress
	}

	return Conf

}

func (s *ServerConfig) OpenIDEnabled() bool {
	return s.matchAuth("openid")
}

func (s *ServerConfig) KerberosEnabled() bool {
	return s.matchAuth("kerberos")
}

func (s *ServerConfig) BasicAuthEnabled() bool {
	return s.matchAuth("local") || s.matchAuth("basic")
}

func (s *ServerConfig) matchAuth(needle string) bool {
	for _, q := range s.Authentication {
		if q == needle {
			return true
		}
	}
	return false
}
