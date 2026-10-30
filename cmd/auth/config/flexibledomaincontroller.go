package config

import (
	"encoding/json"
	"fmt"
)

// DomainController describes one Active Directory domain controller and the
// ports krb5.conf should use for it.
type DomainController struct {
	Host      string `json:"host" yaml:"host"`
	Port      int    `json:"port" yaml:"port"`
	AdminPort int    `json:"adminport" yaml:"adminport"`
}

// FlexibleDomainController supports both documented domainControllers entry
// shapes in configuration files: a bare host string ("dc1.example.com",
// default ports) or a detailed object ({host, port, adminPort}).
type FlexibleDomainController struct {
	DomainController
}

// UnmarshalJSON implements the flexible decoding. sigs.k8s.io/yaml decodes
// through encoding/json, so this is the decoder that actually runs for YAML
// files; an UnmarshalYAML method would never be invoked on this path.
func (f *FlexibleDomainController) UnmarshalJSON(data []byte) error {
	var host string
	if err := json.Unmarshal(data, &host); err == nil {
		f.Host = host
		f.Port = DefaultKdcPort
		f.AdminPort = DefaultKdcAdminPort
		return nil
	}
	var dc DomainController
	if err := json.Unmarshal(data, &dc); err != nil {
		return fmt.Errorf("domainControllers entry must be a host string or a host/port object: %w", err)
	}
	f.DomainController = dc
	if f.Port == 0 {
		f.Port = DefaultKdcPort
	}
	if f.AdminPort == 0 {
		f.AdminPort = DefaultKdcAdminPort
	}
	return nil
}
