package config

import (
	"github.com/spf13/viper"
	"log"
)

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
	Hosts          []string
	RoundRobin	   bool
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

func init() {
	viper.SetDefault("server.certFile", "server.pem")
	viper.SetDefault("server.keyFile", "key.pem")
	viper.SetDefault("server.port", 443)
}

func Load(configFile string) Configuration {
	var conf Configuration

	viper.SetConfigName("rdpgw")
	viper.SetConfigFile(configFile)
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("RDPGW")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("No config file found (%s). Using defaults", err)
	}

	if err := viper.Unmarshal(&conf); err != nil {
		log.Fatalf("Cannot unmarshal the config file; %s", err)
	}

	return conf
}
