package config

import (
	"github.com/spf13/viper"
	"log"
)

type Configuration struct {
	Server   ServerConfig
	OpenId   OpenIDConfig
	Caps     RDGCapsConfig
	Security SecurityConfig
	Client	 ClientConfig
}

type ServerConfig struct {
	GatewayAddress string
	Port           int
	CertFile       string
	KeyFile        string
	Hosts          []string
	RoundRobin     bool
	SessionKey     string
}

type OpenIDConfig struct {
	ProviderUrl  string
	ClientId     string
	ClientSecret string
}

type RDGCapsConfig struct {
	SmartCardAuth   bool
	TokenAuth       bool
	IdleTimeout     int
	RedirectAll     bool
	DisableRedirect bool
	EnableClipboard bool
	EnablePrinter   bool
	EnablePort      bool
	EnablePnp       bool
	EnableDrive     bool
}

type SecurityConfig struct {
	EnableOpenId        bool
	TokenSigningKey     string
	PassTokenAsPassword bool
}

type ClientConfig struct {
	NetworkAutoDetect   int
	BandwidthAutoDetect int
	ConnectionType      int
	UsernameTemplate    string
}

func init() {
	viper.SetDefault("server.certFile", "server.pem")
	viper.SetDefault("server.keyFile", "key.pem")
	viper.SetDefault("server.port", 443)
	viper.SetDefault("security.enableOpenId", true)
	viper.SetDefault("client.networkAutoDetect", 1)
	viper.SetDefault("client.bandwidthAutoDetect", 1)
}

func Load(configFile string) Configuration {
	var conf Configuration

	viper.SetConfigName("rdpgw")
	viper.SetConfigFile(configFile)
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("RDPGW")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("No config file found (%s)", err)
	}

	if err := viper.Unmarshal(&conf); err != nil {
		log.Fatalf("Cannot unmarshal the config file; %s", err)
	}

	if len(conf.Security.TokenSigningKey) < 32 {
		log.Fatalf("Token signing key not long enough")
	}

	return conf
}
