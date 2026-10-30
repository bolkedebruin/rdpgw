package ntlm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/database"
	"github.com/samber/lo"
)

// Mirrors newNtlmBackend from cmd/auth/auth.go so the modern Configuration
// surface can be type-checked on any OS (cmd/auth itself stays
// Linux-buildable-only due to PAM). Must stay in sync with auth.go: same
// reasons, same backends switch, same single/ordered/null decision tree.
func newNtlmBackendCompat(conf config.Configuration) Backend {
	var reason string
	var chain []Backend

	ntlmProto := conf.AuthProtocols
	switch {
	case ntlmProto == nil || ntlmProto.Ntlm == nil:
		reason = "AuthProtocols.Ntlm is not configured"
	case !ntlmProto.Ntlm.Enabled:
		reason = "AuthProtocols.Ntlm is disabled by configuration"
	default:
		backends := lo.Map(ntlmProto.Ntlm.Backends, func(b string, _ int) string { return strings.ToLower(b) })
		backends = lo.Uniq(backends)

		for _, b := range backends {
			switch b {
			case config.NtlmBackendWinbind:
				w := conf.Winbind
				if w == nil {
					continue
				}
				sep := w.Separator
				if sep == 0 {
					sep = config.DefaultSeparator
				}
				chain = append(chain, &WinbindBackend{
					NtlmAuthPath:        w.NtlmAuthPath,
					Domain:              w.Workgroup,
					RequireMembershipOf: w.RequireMembershipOf,
					Timeout:             time.Duration(w.Timeout) * time.Second,
					StripDomain:         w.StripDomain,
					Separator:           sep.String(),
				})
			case config.NtlmBackendUsers, config.NtlmBackendLegacyFile:
				chain = append(chain, NewLocalBackend(database.NewConfig(conf.Users)))
			default:
				// unknown backend: skipped also here
			}
		}

		if len(chain) == 0 {
			reason = fmt.Sprintf("AuthProtocols.Ntlm contains no usable backend (configured: %v)", backends)
		}
	}

	if len(chain) == 0 {
		return &NullBackend{Reason: reason}
	}
	if len(chain) == 1 {
		return chain[0]
	}
	return NewOrderedBackend(chain...)
}

// Static compile-time check: the mirrored factory must produce a Backend.
var _ Backend = newNtlmBackendCompat(config.Configuration{})

// TestCompatOrderedModernConfigFromYAML verifies the compatibility contract
// between the new YAML configuration and the backend factory mirrored from
// cmd/auth/auth.go: a config enlisting both winbind and users builds an
// ordered chain with exactly those two verifiers in order, the winbind
// entry configured from the modern Winbind block.
func TestCompatOrderedModernConfigFromYAML(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "ntlm_auth")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	yamlFile := filepath.Join(dir, "rdpgw-auth.yaml")
	yamlBody := `
winbind:
  ntlmauthpath: ` + helper + `
  workgroup: CORP
  requiremembershipof: "CORP\\RDP Users"
  timeout: 7
  stripdomain: true
  separator: "+"
authprotocols:
  kerberos:
    share: true
    keytabpath: /var/lib/samba/rdpgw.keytab
    spns:
      - HTTP/gw.corp.local  # SPNs are a Kerberos concern, never a winbind one
  ntlm:
    enabled: true
    backends:
      - winbind
      - users
`
	if err := os.WriteFile(yamlFile, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded := config.Load(yamlFile) // non-fatal path per the validation rules
	b := newNtlmBackendCompat(loaded)
	ob, ok := b.(*OrderedBackend)
	if !ok {
		t.Fatalf("want OrderedBackend, got %T", b)
	}
	if len(ob.Backends) != 2 {
		t.Fatalf("chain length = %d, want 2 (winbind, users)", len(ob.Backends))
	}
	wb, ok := ob.Backends[0].(*WinbindBackend)
	if !ok {
		t.Fatalf("first backend = %T, want *WinbindBackend", ob.Backends[0])
	}
	if wb.NtlmAuthPath != helper || wb.Domain != "CORP" || wb.RequireMembershipOf != `CORP\RDP Users` {
		t.Errorf("winbind mapping wrong: %+v", wb)
	}
	if wb.Timeout != 7*time.Second || !wb.StripDomain || wb.Separator != "+" {
		t.Errorf("winbind tuning wrong: %+v", wb)
	}
	if _, ok := ob.Backends[1].(*LocalBackend); !ok {
		t.Errorf("second backend = %T, want *LocalBackend", ob.Backends[1])
	}
}

func writeCompatConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "rdpgw-auth.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCompatSimpleConfigReturnsBackendDirectly(t *testing.T) {
	// Single users backend must NOT be wrapped in OrderedBackend.
	p := writeCompatConfig(t, `
users:
  - username: alice
    password: secret
`)
	c := config.Load(p)
	b := newNtlmBackendCompat(c)
	if _, ok := b.(*LocalBackend); !ok {
		t.Fatalf("want bare *LocalBackend for a simple config, got %T", b)
	}
}

func TestCompatWinbindOnlyConfigReturnsBackendDirectly(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "ntlm_auth")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := writeCompatConfig(t, `
winbind:
  ntlmauthpath: `+helper+`
  workgroup: CORP
authprotocols:
  ntlm:
    enabled: true
    backends:
      - winbind
`)
	c := config.Load(p)
	b := newNtlmBackendCompat(c)
	if _, ok := b.(*WinbindBackend); !ok {
		t.Fatalf("want bare *WinbindBackend for a single-backend config, got %T", b)
	}
}

func TestCompatDisabledNtlmIsDenied(t *testing.T) {
	// Disabled NTLM is only valid together with another protocol (Kerberos);
	// Validate stats Winbind.NtlmAuthPath, so point it at a fake helper to
	// keep the test hermetic. The factory must install NullBackend.
	helper := filepath.Join(t.TempDir(), "ntlm_auth")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := writeCompatConfig(t, `
winbind:
  ntlmauthpath: `+helper+`
authprotocols:
  kerberos:
    share: true
    keytabpath: /var/lib/samba/rdpgw.keytab
  ntlm:
    enabled: false
`)
	c := config.Load(p)
	nb, ok := newNtlmBackendCompat(c).(*NullBackend)
	if !ok {
		t.Fatalf("want NullBackend for disabled NTLM, got %T", newNtlmBackendCompat(c))
	}
	if !strings.Contains(nb.Reason, "disabled") {
		t.Errorf("Reason = %q, want it to mention the explicit disable", nb.Reason)
	}
}

func TestCompatKerberosOnlyIsDenied(t *testing.T) {
	// Any kerberos-share config implies a samba host: Validate always stats
	// the (DefaultConfig-seeded) Winbind.NtlmAuthPath, so override it with a
	// fake helper. Ntlm is intentionally unconfigured -> NullBackend.
	helper := filepath.Join(t.TempDir(), "ntlm_auth")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := writeCompatConfig(t, `
winbind:
  ntlmauthpath: `+helper+`
authprotocols:
  kerberos:
    share: true
    keytabpath: /var/lib/samba/rdpgw.keytab
`)
	c := config.Load(p)
	nb, ok := newNtlmBackendCompat(c).(*NullBackend)
	if !ok {
		t.Fatalf("want NullBackend when Ntlm protocol is absent, got %T", newNtlmBackendCompat(c))
	}
	if !strings.Contains(nb.Reason, "not configured") {
		t.Errorf("Reason = %q, want it to mention the missing protocol", nb.Reason)
	}
}

func TestCompatUnknownOnlyBackendsDenied(t *testing.T) {
	// All-unknown backends fail Validate (unknown AuthProtocols.Ntlm.Backends),
	// so this shape only reaches the factory as a constructed value; it must
	// still degrade to an explicit denial instead of a nil panic.
	c := config.Configuration{
		Winbind: &config.WinbindConfig{
			NtlmAuthPath: config.DefaultNtlmAuthPath,
			Timeout:      1,
		},
		AuthProtocols: &config.AuthProtocolsConfig{
			Ntlm: &config.NtlmProtocolConfig{
				Enabled:  true,
				Backends: []string{"LDAP"},
			},
		},
	}
	nb, ok := newNtlmBackendCompat(c).(*NullBackend)
	if !ok {
		t.Fatalf("want NullBackend when no listed backend is usable, got %T", newNtlmBackendCompat(c))
	}
	if !strings.Contains(nb.Reason, "[ldap]") {
		t.Errorf("Reason = %q, want it to include the (normalized) configured list", nb.Reason)
	}
}
