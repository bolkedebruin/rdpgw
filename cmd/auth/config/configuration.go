package config

import (
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"log"
	"os"
)

type Configuration struct {
	Users    []UserConfig   `koanf:"users"`
}

type UserConfig struct {
	Username             string   `koanf:"username"`
	Password             string   `koanf:"password"`
}

var Conf Configuration

func Load(configFile string) Configuration {

	var k = koanf.New(".")

	k.Load(confmap.Provider(map[string]interface{}{}, "."), nil)

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Config file %s not found, skipping config file", configFile)
	} else {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			log.Fatalf("Error loading config from file: %v", err)
		}
	}

	koanfTag := koanf.UnmarshalConf{Tag: "koanf"}
	k.UnmarshalWithConf("Users", &Conf.Users, koanfTag)

	return Conf

}
