package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/mitchellh/copystructure"
	"github.com/samber/lo"
	yaml "sigs.k8s.io/yaml"
)

const (
	// NtlmBackendLegacyFile verifies NTLM responses against the users listed in
	// this configuration file (plain text passwords).
	NtlmBackendLegacyFile = "file"
	// NtlmBackendWinbind delegates the NTLM handshake to Samba's ntlm_auth
	// helper, which in turn asks a domain controller (pass-through
	// authentication via winbindd). The host must be joined to the domain.
	NtlmBackendWinbind = "winbind"
	// NtlmBackendUsers verifies NTLM responses against local YAML users.
	NtlmBackendUsers = "users"

	// Default configuration constants
	DefaultNtlmAuthPath   = "/usr/bin/ntlm_auth"
	DefaultWinbindTimeout = 10
	// DefaultSeparator matches winbind's own documented default.
	DefaultSeparator    SingleChar = '\\'
	DefaultSharedKeytab            = "/var/lib/samba/rdpgw.keytab"
	DefaultKdcPort                 = 88
	DefaultKdcAdminPort            = 749
	DefaultStripDomain             = false
)

// DefaultConfig holds the default configuration values applied via yaml.
// These defaults are loaded first, then overridden by the YAML config file
// if present. Winbind values are loaded but winbind domain join is only
// enabled when actually referenced by authprotocols (ntlm/basic backends
// or kerberos share). In this case users is the default backend for NTLM.
var DefaultConfig = &Configuration{
	AuthProtocols: &AuthProtocolsConfig{
		Ntlm: &NtlmProtocolConfig{
			Enabled:  true,
			Backends: []string{NtlmBackendUsers},
		},
	},
	Winbind: &WinbindConfig{
		NtlmAuthPath: DefaultNtlmAuthPath,
		Timeout:      DefaultWinbindTimeout,
		StripDomain:  DefaultStripDomain,
		Separator:    DefaultSeparator,
	},
}

// Configuration holds the modern (new schema) rdpgw-auth configuration.
type Configuration struct {
	Winbind       *WinbindConfig       `json:"winbind" yaml:"winbind"`
	Users         []UserConfig         `json:"users" yaml:"users"`
	AuthProtocols *AuthProtocolsConfig `json:"authprotocols" yaml:"authprotocols"`
}

type UserConfig struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}

// WinbindConfig represents the modern Active Directory Winbind configuration.
type WinbindConfig struct {
	// Domain is the FQDN of the domain (DNS Realm).
	Domain string `json:"domain" yaml:"domain"`
	// Workgroup is the NetBIOS Domain Name / Workgroup (Pre-Windows 2000 domain).
	Workgroup string `json:"workgroup" yaml:"workgroup"`
	// Hostname is the Machine Computer Name in AD (sets 'netbios name' in smb.conf).
	Hostname string `json:"hostname" yaml:"hostname"`
	// RequireMembershipOf is passed to ntlm_auth as
	// --require-membership-of. Optional; accepts a SID or DOMAIN\Group.
	RequireMembershipOf string `json:"requiremembershipof" yaml:"requiremembershipof"`
	// NtlmAuthPath is the path to Samba's ntlm_auth binary.
	NtlmAuthPath string `json:"ntlmauthpath" yaml:"ntlmauthpath"`
	// Timeout (seconds) for a single exchange with ntlm_auth.
	Timeout int `json:"timeout" yaml:"timeout"`
	// AutoJoin controls whether rdpgw-auth automatically attempts to join the domain if unjoined.
	AutoJoin bool `json:"autojoin" yaml:"autojoin"`
	// JoinTimeout is the max minutes to attempt automatic AD domain join or wait for manual join.
	JoinTimeout int `json:"jointimeout" yaml:"jointimeout"`
	// StripDomain removes the "DOMAIN<separator>" prefix from the user
	// name that winbind reports, so rdpgw sees the bare account name.
	StripDomain bool `json:"stripdomain" yaml:"stripdomain"`
	// Separator is the winbind separator configured in smb.conf ("winbind separator", default "\").
	Separator SingleChar `json:"separator" yaml:"separator"`
	// DomainControllers lists domain controllers supporting both host strings and host/port objects.
	DomainControllers []FlexibleDomainController `json:"domaincontrollers" yaml:"domaincontrollers"`
}

type AuthProtocolsConfig struct {
	Kerberos *KerberosProtocolConfig `json:"kerberos" yaml:"kerberos"`
	Ntlm     *NtlmProtocolConfig     `json:"ntlm" yaml:"ntlm"`
}

type KerberosProtocolConfig struct {
	Share      bool   `json:"share" yaml:"share"`
	KeytabPath string `json:"keytabpath" yaml:"keytabpath"`
	// Spns is the list of Kerberos Service Principal Names to register in
	// Active Directory and keep present in the shared keytab. SPNs are a
	// Kerberos concern: without a keytab share there is nothing to register,
	// so they live here rather than under Winbind.
	Spns []string `json:"spns" yaml:"spns"`
}

type NtlmProtocolConfig struct {
	Enabled  bool     `json:"enabled" yaml:"enabled"`
	Backends []string `json:"backends" yaml:"backends"`
}

// LegacyConfiguration holds legacy schema fields parsed only when the modern
// AuthProtocols block is missing from the configuration file.
type LegacyConfiguration struct {
	// Ntlm holds the legacy NTLM backend configuration (yaml field: ntlm).
	Ntlm *LegacyNtlmConfig `json:"ntlm" yaml:"ntlm"`
}

// LegacyNtlmConfig defines the legacy NTLM backend configuration.
type LegacyNtlmConfig struct {
	// Backend selects how NTLM AUTHENTICATE messages are verified:
	// "file" (default), "winbind", or "users".
	Backend string              `json:"backend" yaml:"backend"`
	Winbind LegacyWinbindConfig `json:"winbind" yaml:"winbind"`
}

// LegacyWinbindConfig defines the legacy winbind sub-configuration.
type LegacyWinbindConfig struct {
	// NtlmAuthPath is the path to Samba's ntlm_auth binary.
	NtlmAuthPath string `json:"ntlmauthpath" yaml:"ntlmauthpath"`
	// Domain is passed to ntlm_auth as --domain. Optional; winbind uses its
	// own domain when empty. In legacy configuration, domain represented the workgroup/NetBIOS domain.
	Domain string `json:"domain" yaml:"domain"`
	// RequireMembershipOf is passed to ntlm_auth as
	// --require-membership-of. Optional; accepts a SID or DOMAIN\Group.
	RequireMembershipOf string `json:"requiremembershipof" yaml:"requiremembershipof"`
	// Timeout (seconds) for a single exchange with ntlm_auth.
	Timeout int `json:"timeout" yaml:"timeout"`
	// StripDomain removes the "DOMAIN<separator>" prefix from the user
	// name that winbind reports, so rdpgw sees the bare account name.
	StripDomain bool `json:"stripdomain" yaml:"stripdomain"`
	// Separator is the winbind separator configured in smb.conf
	// ("winbind separator", default "\").
	Separator string `json:"separator" yaml:"separator"`
	// Spns is a list of Kerberos Service Principal Names (SPNs) to register
	// in Active Directory and ensure are present in the keytab.
	Spns []string `json:"spns" yaml:"spns"`
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
	cRaw, err := copystructure.Copy(DefaultConfig)
	var c Configuration = *(cRaw.(*Configuration))
	if err != nil {
		return c, fmt.Errorf("error loading dafault configuration: %w", err)
	}

	// Parse the YAML config file if present. If missing, defaults remain in effect.
	fileBytes, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("Config file %s not found, skipping config file", configFile)
	} else {
		c.AuthProtocols = nil
		// Unmarshal directly into config struct (case-insensitive via sigs.k8s.io/yaml)
		if err := yaml.Unmarshal(fileBytes, &c); err != nil {
			return c, fmt.Errorf("error loading config from file: %w", err)
		}
	}

	// Convert legacy configuration into modern structure.
	// Runs when authprotocols is undefined, meaning that the file still holds the legacy configuration
	if c.AuthProtocols == nil {
		// Unmarshal legacy configuration section (yaml field: ntlm) separately.
		var legacyC LegacyConfiguration
		yaml.Unmarshal(fileBytes, &legacyC)

		c.AuthProtocols = &AuthProtocolsConfig{}

		var legacyBackend = NtlmBackendLegacyFile
		var legacyNtlm = legacyC.Ntlm
		if legacyNtlm != nil && legacyNtlm.Backend != "" {
			legacyBackend = legacyNtlm.Backend
		}
		switch legacyBackend {
		case NtlmBackendWinbind:
			c.AuthProtocols.Kerberos = &KerberosProtocolConfig{
				Share:      true,
				KeytabPath: DefaultSharedKeytab,
			}
			c.AuthProtocols.Ntlm = &NtlmProtocolConfig{
				Enabled:  true,
				Backends: []string{NtlmBackendWinbind},
			}

			// Carry over legacy winbind configuration to modern WinbindConfig if present
			if c.Winbind == nil {
				c.Winbind = &WinbindConfig{}
			}

			if legacyNtlm.Winbind.Domain != "" && c.Winbind.Workgroup == DefaultConfig.Winbind.Workgroup {
				c.Winbind.Workgroup = legacyNtlm.Winbind.Domain
			}

			if legacyNtlm.Winbind.RequireMembershipOf != "" && c.Winbind.RequireMembershipOf == DefaultConfig.Winbind.RequireMembershipOf {
				c.Winbind.RequireMembershipOf = legacyNtlm.Winbind.RequireMembershipOf
			}

			if legacyNtlm.Winbind.NtlmAuthPath != "" && c.Winbind.NtlmAuthPath == DefaultConfig.Winbind.NtlmAuthPath {
				c.Winbind.NtlmAuthPath = legacyNtlm.Winbind.NtlmAuthPath
			}

			if legacyNtlm.Winbind.Timeout > 0 && c.Winbind.Timeout == DefaultConfig.Winbind.Timeout {
				c.Winbind.Timeout = legacyNtlm.Winbind.Timeout
			}

			if c.Winbind.StripDomain == DefaultConfig.Winbind.StripDomain {
				c.Winbind.StripDomain = legacyNtlm.Winbind.StripDomain
			}

			if legacyNtlm.Winbind.Separator != "" && c.Winbind.Separator == DefaultConfig.Winbind.Separator {
				c.Winbind.Separator = newSingleChar(legacyNtlm.Winbind.Separator)
			}

			// The legacy schema nested SPNs under winbind because the old
			// wrapper used them while registering keytab entries; they are a
			// Kerberos concern and carry over to the Kerberos block, which
			// this legacy mapping enables (share = true) above.
			if len(legacyNtlm.Winbind.Spns) > 0 && c.AuthProtocols.Kerberos != nil && len(c.AuthProtocols.Kerberos.Spns) == 0 {
				c.AuthProtocols.Kerberos.Spns = legacyNtlm.Winbind.Spns
			}
		case NtlmBackendLegacyFile:
			fallthrough
		default:
			if len(c.Users) > 0 {
				c.AuthProtocols.Ntlm = &NtlmProtocolConfig{
					Enabled:  true,
					Backends: []string{NtlmBackendUsers},
				}
			}
		}
	}

	// NetBIOS auto-derivation for modern WinbindConfig.
	if c.Winbind != nil && c.Winbind.Workgroup == "" && c.Winbind.Domain != "" {
		parts := strings.Split(c.Winbind.Domain, ".")
		c.Winbind.Workgroup = strings.ToUpper(parts[0])
	}

	return c, c.Validate()
}

// Validate checks the NTLM backend settings.
func (c *Configuration) Validate() error {
	authProtocols := c.AuthProtocols
	if authProtocols == nil {
		return errors.New("unknown AuthProtocols")
	}
	kerberos := authProtocols.Kerberos
	hasKerberos := kerberos != nil && kerberos.Share
	ntlm := authProtocols.Ntlm
	hasNtlm := ntlm != nil && ntlm.Enabled

	if !hasKerberos && !hasNtlm {
		return errors.New("unknown AuthProtocols")
	}

	if hasKerberos {
		if kerberos.KeytabPath == "" {
			return errors.New("AuthProtocols.Kerberos.KeytabPath must be set when you are sharing Kerberos")
		}
	}

	var hasNtlmWithWinbindBackend = false
	if hasNtlm {
		if len(ntlm.Backends) == 0 {
			return fmt.Errorf("unknown AuthProtocols.Ntlm.Backends")
		}

		lowerBackends := lo.Map(ntlm.Backends, func(b string, _ int) string { return strings.ToLower(b) })
		distinctBackends := lo.Uniq(lowerBackends)

		if len(distinctBackends) > 2 {
			return fmt.Errorf("unknown AuthProtocols.Ntlm.Backends %q (expected %q and/or %q)", ntlm.Backends, NtlmBackendUsers, NtlmBackendWinbind)
		}

		ntlmBackendWinbindLower := strings.ToLower(NtlmBackendWinbind)
		permitted := []string{strings.ToLower(NtlmBackendUsers), ntlmBackendWinbindLower}
		if !lo.Every(permitted, distinctBackends) {
			return fmt.Errorf("unknown AuthProtocols.Ntlm.Backends %q (expected %q and/or %q)", ntlm.Backends, NtlmBackendUsers, NtlmBackendWinbind)
		}

		hasNtlmWithWinbindBackend = lo.Contains(distinctBackends, ntlmBackendWinbindLower)
	}

	if !hasKerberos && !hasNtlmWithWinbindBackend {
		// If neither Kerberos nor NTLM with Winbind backend is enabled, it means Ntlm is configured with only the Users backend. No Winbind configuration is needed.
		return nil
	}

	winbind := c.Winbind
	if (hasKerberos || hasNtlmWithWinbindBackend) && winbind == nil {
		return errors.New("Winbind must be configured when AuthProtocols Kerberos or NTLM with Winbind backend are enabled")
	}

	if winbind.NtlmAuthPath == "" {
		return errors.New("Winbind.NtlmAuthPath must be set")
	}

	if _, err := os.Stat(winbind.NtlmAuthPath); err != nil {
		return fmt.Errorf("Winbind.NtlmAuthPath %q is not usable: %w", winbind.NtlmAuthPath, err)
	}

	if winbind.Timeout <= 0 {
		return errors.New("Winbind.Timeout must be positive")
	}
	return nil
}
