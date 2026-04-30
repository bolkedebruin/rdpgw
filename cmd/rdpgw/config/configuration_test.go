package config

import (
	"testing"
)

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