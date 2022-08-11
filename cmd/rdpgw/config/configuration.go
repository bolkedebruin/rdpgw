package config

import (
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
	RoundRobin           bool     `koanf:"roundrobin"`
	SessionKey           string   `koanf:"sessionkey"`
	SessionEncryptionKey string   `koanf:"sessionencryptionkey"`
	SessionStore         string   `koanf:"sessionstore"`
	SendBuf              int      `koanf:"sendbuf"`
	ReceiveBuf           int      `koanf:"recievebuf"`
	DisableTLS			 bool	  `koanf:"disabletls"`
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
		"Server.TlsDisabled":		  false,
		"Server.Port":                443,
		"Server.SessionStore":		  "cookie",
		"Client.NetworkAutoDetect":   1,
		"Client.BandwidthAutoDetect": 1,
		"Security.VerifyClientIp":    true,
		"Caps.TokenAuth":			  true,
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

	return Conf

}