package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaultsToFileBackend(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Users:
  - Username: alice
    Password: secret
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Ntlm.Backend != NtlmBackendFile {
		t.Errorf("Backend = %q, want %q", c.Ntlm.Backend, NtlmBackendFile)
	}
	if len(c.Users) != 1 || c.Users[0].Username != "alice" || c.Users[0].Password != "secret" {
		t.Errorf("unexpected users: %+v", c.Users)
	}
	w := c.Ntlm.Winbind
	if w.NtlmAuthPath != "/usr/bin/ntlm_auth" || w.Timeout != 10 || w.StripDomain || w.Separator != `\` {
		t.Errorf("unexpected winbind defaults: %+v", w)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	c, err := load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Ntlm.Backend != NtlmBackendFile || len(c.Users) != 0 {
		t.Errorf("unexpected config: %+v", c)
	}
}

func TestLoadWinbind(t *testing.T) {
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Ntlm:
  Backend: winbind
  Winbind:
    NtlmAuthPath: `+helper+`
    Domain: EXAMPLE
    RequireMembershipOf: "EXAMPLE\\RDP Users"
    Timeout: 3
    StripDomain: true
    Separator: "+"
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	want := WinbindConfig{
		NtlmAuthPath:        helper,
		Domain:              "EXAMPLE",
		RequireMembershipOf: `EXAMPLE\RDP Users`,
		Timeout:             3,
		StripDomain:         true,
		Separator:           "+",
	}
	if c.Ntlm.Backend != NtlmBackendWinbind || c.Ntlm.Winbind != want {
		t.Errorf("got %+v, want backend winbind with %+v", c.Ntlm, want)
	}
}

func TestValidate(t *testing.T) {
	helper := writeFile(t, t.TempDir(), "ntlm_auth", "#!/bin/sh\n")
	cases := []struct {
		name    string
		ntlm    NtlmConfig
		wantErr string
	}{
		{"file", NtlmConfig{Backend: NtlmBackendFile}, ""},
		{"winbind ok", NtlmConfig{Backend: NtlmBackendWinbind, Winbind: WinbindConfig{NtlmAuthPath: helper, Timeout: 1}}, ""},
		{"unknown backend", NtlmConfig{Backend: "ldap"}, "unknown Ntlm.Backend"},
		{"empty backend", NtlmConfig{}, "unknown Ntlm.Backend"},
		{"missing path", NtlmConfig{Backend: NtlmBackendWinbind, Winbind: WinbindConfig{Timeout: 1}}, "NtlmAuthPath must be set"},
		{"nonexistent path", NtlmConfig{Backend: NtlmBackendWinbind, Winbind: WinbindConfig{NtlmAuthPath: "/nonexistent/ntlm_auth", Timeout: 1}}, "is not usable"},
		{"zero timeout", NtlmConfig{Backend: NtlmBackendWinbind, Winbind: WinbindConfig{NtlmAuthPath: helper}}, "Timeout must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Configuration{Ntlm: tc.ntlm}
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
