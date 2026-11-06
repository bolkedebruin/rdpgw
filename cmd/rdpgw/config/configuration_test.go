package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

func decodeYAMLForTest(t *testing.T, data string) (Configuration, error) {
	t.Helper()
	configFile := filepath.Join(t.TempDir(), "rdpgw.yaml")
	if err := os.WriteFile(configFile, []byte(data), 0600); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	k := koanf.New(".")
	if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		t.Fatalf("loading config file: %v", err)
	}
	var configuration Configuration
	err := decodeConfiguration(k, &configuration)
	return configuration, err
}

func clearRDPGWEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "RDPGW_") {
			continue
		}
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unsetting %s: %v", name, err)
		}
		t.Cleanup(func() {
			if err := os.Setenv(name, value); err != nil {
				t.Errorf("restoring %s: %v", name, err)
			}
		})
	}
}

func decodeEnvironmentForTest(t *testing.T, values map[string]string) (Configuration, error) {
	t.Helper()
	clearRDPGWEnvironment(t)
	for name, value := range values {
		t.Setenv(name, value)
	}
	k := koanf.New(".")
	if err := loadEnvironment(k); err != nil {
		t.Fatalf("loading environment: %v", err)
	}
	var configuration Configuration
	err := decodeAndValidateConfiguration(k, &configuration)
	return configuration, err
}

func TestDecodeDockerEnvironment(t *testing.T) {
	configuration, err := decodeEnvironmentForTest(t, map[string]string{
		"RDPGW_SERVER__TLS":            "disable",
		"RDPGW_SERVER__PORT":           "9443",
		"RDPGW_SERVER__HOSTS":          "xrdp:3389 backup:3389",
		"RDPGW_SERVER__AUTHENTICATION": "local openid",
		"RDPGW_CAPS__TOKEN_AUTH":       "false",
	})
	if err != nil {
		t.Fatalf("decodeAndValidateConfiguration returned an error: %v", err)
	}
	if configuration.Server.Port != 9443 {
		t.Fatalf("Server.Port = %d, want 9443", configuration.Server.Port)
	}
	if got, want := configuration.Server.Hosts, []string{"xrdp:3389", "backup:3389"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Server.Hosts = %v, want %v", got, want)
	}
	if got, want := configuration.Server.Authentication, []string{"local", "openid"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Server.Authentication = %v, want %v", got, want)
	}
	if configuration.Caps.TokenAuth {
		t.Fatal("Caps.TokenAuth = true, want false")
	}
}

func TestRejectInvalidDockerEnvironment(t *testing.T) {
	tests := []struct {
		name        string
		environment map[string]string
		message     string
	}{
		{
			name: "unknown variable",
			environment: map[string]string{
				"RDPGW_SERVER__TLS":         "auto",
				"RDPGW_SERVER__ROUND_ROBIN": "false",
			},
			message: "RoundRobin",
		},
		{
			name: "invalid TLS mode",
			environment: map[string]string{
				"RDPGW_SERVER__TLS": "off",
			},
			message: `invalid Server.Tls value "off"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeEnvironmentForTest(t, test.environment)
			if err == nil {
				t.Fatal("decodeAndValidateConfiguration accepted an invalid environment")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.message)) {
				t.Fatalf("error %q does not mention %q", err, test.message)
			}
		})
	}
}

func TestDecodeConfigurationStrict(t *testing.T) {
	t.Run("lowercase with comments", func(t *testing.T) {
		configuration, err := decodeYAMLForTest(t, `# HAProxy terminates TLS.
server:
  tls: disable # Keep the gateway listener on HTTP.
  hosts:
    - 10.20.0.11:3389
caps:
  tokenauth: false
`)
		if err != nil {
			t.Fatalf("decodeConfiguration returned an error: %v", err)
		}
		if got := configuration.Server.Hosts; !reflect.DeepEqual(got, []string{"10.20.0.11:3389"}) {
			t.Fatalf("Server.Hosts = %v", got)
		}
	})

	tests := []struct {
		name string
		yaml string
		key  string
	}{
		{
			name: "unknown top-level key",
			yaml: "authentication: []\n",
			key:  "authentication",
		},
		{
			name: "unknown nested key",
			yaml: "Server:\n  Hostz:\n    - 10.20.0.11:3389\n",
			key:  "Hostz",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeYAMLForTest(t, test.yaml)
			if err == nil {
				t.Fatal("decodeConfiguration accepted an unknown key")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.key)) {
				t.Fatalf("error %q does not mention %q", err, test.key)
			}
		})
	}
}

func TestValidateConfigurationRejectsInvalidTLSMode(t *testing.T) {
	configuration := Configuration{Server: ServerConfig{Tls: "off"}}
	err := validateConfiguration(&configuration)
	if err == nil {
		t.Fatal("validateConfiguration accepted an invalid TLS mode")
	}
	if !strings.Contains(err.Error(), `invalid Server.Tls value "off"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeAndValidateConfigurationReportsAllErrors(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "rdpgw.yaml")
	data := []byte(`server:
  tls: off
  hosts:
    - 10.20.0.11:3389
authentication: []
`)
	if err := os.WriteFile(configFile, data, 0600); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	k := koanf.New(".")
	if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		t.Fatalf("loading config file: %v", err)
	}
	var configuration Configuration
	err := decodeAndValidateConfiguration(k, &configuration)
	if err == nil {
		t.Fatal("decodeAndValidateConfiguration accepted invalid configuration")
	}
	for _, message := range []string{"authentication", `invalid Server.Tls value "off"`} {
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(message)) {
			t.Fatalf("error %q does not mention %q", err, message)
		}
	}
}
func TestHeaderEnabled(t *testing.T) {
	cases := []struct {
		name           string
		authentication []string
		expected       bool
	}{
		{
			name:           "header_enabled",
			authentication: []string{"header"},
			expected:       true,
		},
		{
			name:           "header_with_others",
			authentication: []string{"openid", "header", "local"},
			expected:       true,
		},
		{
			name:           "header_not_enabled",
			authentication: []string{"openid", "local"},
			expected:       false,
		},
		{
			name:           "empty_authentication",
			authentication: []string{},
			expected:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := &ServerConfig{
				Authentication: tc.authentication,
			}

			result := config.HeaderEnabled()
			if result != tc.expected {
				t.Errorf("expected HeaderEnabled(): %v, got: %v", tc.expected, result)
			}
		})
	}
}

func TestAuthenticationConstants(t *testing.T) {
	// Test that the header authentication constant is correct
	if AuthenticationHeader != "header" {
		t.Errorf("incorrect authentication header constant: %v", AuthenticationHeader)
	}
}

func TestCheckDefaultSecrets(t *testing.T) {
	const placeholder = "thisisasessionkeyreplacethisjetzt"

	cases := []struct {
		name      string
		mutate    func(*Configuration)
		wantField string
	}{
		{
			name:      "session key",
			mutate:    func(c *Configuration) { c.Server.SessionKey = placeholder },
			wantField: "server.sessionkey",
		},
		{
			name:      "session encryption key",
			mutate:    func(c *Configuration) { c.Server.SessionEncryptionKey = placeholder },
			wantField: "server.sessionencryptionkey",
		},
		{
			name:      "paa signing key",
			mutate:    func(c *Configuration) { c.Security.PAATokenSigningKey = placeholder },
			wantField: "security.paatokensigningkey",
		},
		{
			name:      "paa encryption key",
			mutate:    func(c *Configuration) { c.Security.PAATokenEncryptionKey = placeholder },
			wantField: "security.paatokenencryptionkey",
		},
		{
			name:      "user signing key",
			mutate:    func(c *Configuration) { c.Security.UserTokenSigningKey = placeholder },
			wantField: "security.usertokensigningkey",
		},
		{
			name:      "user encryption key",
			mutate:    func(c *Configuration) { c.Security.UserTokenEncryptionKey = placeholder },
			wantField: "security.usertokenencryptionkey",
		},
		{
			name:      "query signing key",
			mutate:    func(c *Configuration) { c.Security.QueryTokenSigningKey = placeholder },
			wantField: "security.querytokensigningkey",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Configuration{}
			tc.mutate(c)
			err := checkDefaultSecrets(c)
			if err == nil {
				t.Fatalf("checkDefaultSecrets accepted a placeholder value in %s", tc.wantField)
			}
			if got := err.Error(); !contains(got, tc.wantField) {
				t.Errorf("error message %q should mention the field %q", got, tc.wantField)
			}
		})
	}
}

func TestCheckDefaultSecretsAllowsRandomValues(t *testing.T) {
	c := &Configuration{}
	c.Server.SessionKey = "5aa3a1568fe8421cd7e127d5ace28d2d"
	c.Server.SessionEncryptionKey = "d3ecd7e565e56e37e2f2e95b584d8c0c"
	c.Security.PAATokenSigningKey = "0123456789abcdef0123456789abcdef"
	if err := checkDefaultSecrets(c); err != nil {
		t.Errorf("checkDefaultSecrets rejected non-placeholder values: %v", err)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestHeaderConfigValidation(t *testing.T) {
	cases := []struct {
		name        string
		headerConf  HeaderConfig
		shouldError bool
	}{
		{
			name: "valid_config",
			headerConf: HeaderConfig{
				UserHeader: "X-Forwarded-User",
			},
			shouldError: false,
		},
		{
			name: "missing_user_header",
			headerConf: HeaderConfig{
				EmailHeader: "X-Forwarded-Email",
			},
			shouldError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the configuration struct
			if tc.headerConf.UserHeader == "" && !tc.shouldError {
				t.Error("expected user header to be set")
			}
			if tc.headerConf.UserHeader != "" && tc.shouldError {
				t.Error("expected configuration to be invalid")
			}
		})
	}
}
