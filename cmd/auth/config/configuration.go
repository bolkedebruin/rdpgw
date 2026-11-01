package config

import (
	"errors"
	"fmt"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"log"
	"os"
)

const (
	// NtlmBackendFile verifies NTLM responses against the users listed in
	// this configuration file (plain text passwords).
	NtlmBackendFile = "file"
	// NtlmBackendWinbind delegates the NTLM handshake to Samba's ntlm_auth
	// helper, which in turn asks a domain controller (pass-through
	// authentication via winbindd). The host must be joined to the domain.
	NtlmBackendWinbind = "winbind"
)

type Configuration struct {
	Users []UserConfig `koanf:"users"`
	Ntlm  NtlmConfig   `koanf:"ntlm"`
}

type UserConfig struct {
	Username string `koanf:"username"`
	Password string `koanf:"password"`
}

type NtlmConfig struct {
	// Backend selects how NTLM AUTHENTICATE messages are verified: "file"
	// (default) or "winbind".
	Backend string        `koanf:"backend"`
	Winbind WinbindConfig `koanf:"winbind"`
}

type WinbindConfig struct {
	// NtlmAuthPath is the path to Samba's ntlm_auth binary.
	NtlmAuthPath string `koanf:"ntlmauthpath"`
	// Domain is passed to ntlm_auth as --domain. Optional; winbind uses its
	// own domain when empty.
	Domain string `koanf:"domain"`
	// RequireMembershipOf is passed to ntlm_auth as
	// --require-membership-of. Optional; accepts a SID or DOMAIN\Group.
	RequireMembershipOf string `koanf:"requiremembershipof"`
	// Timeout (seconds) for a single exchange with ntlm_auth.
	Timeout int `koanf:"timeout"`
	// StripDomain removes the "DOMAIN<separator>" prefix from the user
	// name that winbind reports, so rdpgw sees the bare account name.
	StripDomain bool `koanf:"stripdomain"`
	// Separator is the winbind separator configured in smb.conf
	// ("winbind separator", default "\").
	Separator string `koanf:"separator"`
}

var Conf Configuration

// Load reads the rdpgw-auth configuration file, applies defaults and
// validates the result. Invalid configuration is fatal.
func Load(configFile string) Configuration {
	c, err := load(configFile)
	if err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	Conf = c
	return Conf
}

func load(configFile string) (Configuration, error) {
	var c Configuration
	var k = koanf.New(".")

	k.Load(confmap.Provider(map[string]interface{}{
		"Ntlm.Backend":              NtlmBackendFile,
		"Ntlm.Winbind.NtlmAuthPath": "/usr/bin/ntlm_auth",
		"Ntlm.Winbind.Timeout":      10,
		"Ntlm.Winbind.StripDomain":  false,
		"Ntlm.Winbind.Separator":    `\`,
	}, "."), nil)

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Config file %s not found, skipping config file", configFile)
	} else {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			return c, fmt.Errorf("error loading config from file: %w", err)
		}
	}

	koanfTag := koanf.UnmarshalConf{Tag: "koanf"}
	k.UnmarshalWithConf("Users", &c.Users, koanfTag)
	k.UnmarshalWithConf("Ntlm", &c.Ntlm, koanfTag)

	return c, c.Validate()
}

// Validate checks the NTLM backend settings.
func (c *Configuration) Validate() error {
	switch c.Ntlm.Backend {
	case NtlmBackendFile:
		return nil
	case NtlmBackendWinbind:
		w := c.Ntlm.Winbind
		if w.NtlmAuthPath == "" {
			return errors.New("Ntlm.Winbind.NtlmAuthPath must be set")
		}
		if _, err := os.Stat(w.NtlmAuthPath); err != nil {
			return fmt.Errorf("Ntlm.Winbind.NtlmAuthPath %q is not usable: %w", w.NtlmAuthPath, err)
		}
		if w.Timeout <= 0 {
			return errors.New("Ntlm.Winbind.Timeout must be positive")
		}
		return nil
	default:
		return fmt.Errorf("unknown Ntlm.Backend %q (expected %q or %q)", c.Ntlm.Backend, NtlmBackendFile, NtlmBackendWinbind)
	}
}
