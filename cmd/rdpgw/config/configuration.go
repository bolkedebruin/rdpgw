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

type Configuration struct {
	Server   ServerConfig   `koanf:"server"`
	OpenId   OpenIDConfig   `koanf:"openid"`
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
	SendBuf              int      `koanf:"sendbuf"`
	ReceiveBuf           int      `koanf:"recievebuf"`
	DisableTLS           bool     `koanf:"disabletls"`
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
	NetworkAutoDetect   int    `koanf:"networkautodetect"`
	BandwidthAutoDetect int    `koanf:"bandwidthautodetect"`
	ConnectionType      int    `koanf:"connectiontype"`
	UsernameTemplate    string `koanf:"usernametemplate"`
	SplitUserDomain     bool   `koanf:"splituserdomain"`
	DefaultDomain       string `koanf:"defaultdomain"`
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
		"Server.CertFile":            "server.pem",
		"Server.KeyFile":             "key.pem",
		"Server.TlsDisabled":         false,
		"Server.Port":                443,
		"Server.SessionStore":        "cookie",
		"Server.HostSelection":       "roundrobin",
		"Client.NetworkAutoDetect":   1,
		"Client.BandwidthAutoDetect": 1,
		"Security.VerifyClientIp":    true,
		"Caps.TokenAuth":             true,
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

	return Conf

}
