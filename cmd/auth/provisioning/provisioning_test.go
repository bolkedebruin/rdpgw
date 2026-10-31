package provisioning

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
)

// modernWinbindConf returns a validated, modern-schema winbind deployment
// for provisioning tests: the ntlm_auth helper points at a real fake file
// in the test directory so Validate() never trips over /usr/bin/ntlm_auth.
func modernWinbindConf(t *testing.T) config.Configuration {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "ntlm_auth")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return config.Configuration{
		Winbind: &config.WinbindConfig{
			Domain:       "corp.example.com",
			Workgroup:    "CORP",
			Hostname:     "rdpgw-auth",
			NtlmAuthPath: helper,
			Timeout:      10,
			// '+' exercises the explicit-directive rendering path; the
			// backslash default is covered by the legacy helper (omission).
			Separator: config.SingleChar('+'),
		},
		AuthProtocols: &config.AuthProtocolsConfig{
			Kerberos: &config.KerberosProtocolConfig{
				Share:      true,
				KeytabPath: "/var/lib/samba/rdpgw.keytab",
			},
			Ntlm: &config.NtlmProtocolConfig{
				Enabled:  true,
				Backends: []string{config.NtlmBackendWinbind},
			},
		},
	}
}

// legacyConf returns a legacy-schema configuration with only the
// ntlm/backend=winbind mapping present (migration plan shape 3.2 case 1).
func legacyConf(t *testing.T) config.Configuration {
	return config.Configuration{
		Winbind: &config.WinbindConfig{
			Workgroup:    "CORP",
			Hostname:     "rdpgw-auth",
			NtlmAuthPath: mustFakeHelper(t),
			Timeout:      3,
		},
		AuthProtocols: &config.AuthProtocolsConfig{
			Kerberos: &config.KerberosProtocolConfig{
				Share:      true,
				KeytabPath: config.DefaultSharedKeytab,
			},
			Ntlm: &config.NtlmProtocolConfig{
				Enabled:  true,
				Backends: []string{config.NtlmBackendWinbind},
			},
		},
	}
}

func mustFakeHelper(t *testing.T) string {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "ntlm_auth")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return helper
}

func optsFor(t *testing.T) provisionOptions {
	return provisionOptions{
		StageDir:   filepath.Join(t.TempDir(), "stage"),
		SmbTarget:  filepath.Join(t.TempDir(), "smb.conf"),
		Krb5Target: filepath.Join(t.TempDir(), "krb5.conf"),
	}
}

func stageFor(t *testing.T, conf config.Configuration) (stagedSmb, stagedKrb5 string) {
	t.Helper()
	p := optsFor(t)
	if err := os.MkdirAll(p.StageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	smbData, err := buildSmbData(conf)
	if err != nil {
		t.Fatal(err)
	}
	smb, err := stageTemplate("smb.conf.tmpl", smbData, p.StageDir)
	if err != nil {
		t.Fatal(err)
	}
	krb5, err := stageTemplate("krb5.conf.tmpl", buildKrb5Data(conf), p.StageDir)
	if err != nil {
		t.Fatal(err)
	}
	return smb, krb5
}

func TestProvisionSkippedWithoutWinbind(t *testing.T) {
	conf := config.Configuration{}
	if Provision(conf) != nil {
		t.Fatal("provisioning must be a no-op without any winbind capability")
	}
}

func TestProvisionInstallsTargetsWhenAbsent(t *testing.T) {
	for _, tc := range []struct {
		name             string
		conf             config.Configuration
		wants            []string
		krb5DefaultRealm string
		krb5DomainLine   string
		wantSeparator    string
	}{
		{
			name:             "modern",
			conf:             modernWinbindConf(t),
			krb5DefaultRealm: "CORP.EXAMPLE.COM",
			krb5DomainLine:   ".corp.example.com = CORP.EXAMPLE.COM",
			wantSeparator:    `+`,
			wants: []string{
				"realm = CORP.EXAMPLE.COM",
				"workgroup = CORP",
				"netbios name = rdpgw-auth",
				"winbind separator = +", // non-default separators are rendered
				"kerberos method = secrets and keytab",
				"dedicated keytab file = /var/lib/samba/rdpgw.keytab",
				"sync machine password to keytab = \"/var/lib/samba/rdpgw.keytab:sync_spns:sync_kvno:machine_password\"",
			},
		},
		{
			name:             "legacy",
			conf:             legacyConf(t),
			krb5DefaultRealm: "CORP",
			krb5DomainLine:   ".CORP = CORP",
			wantSeparator:    `\`,
			wants: []string{
				"realm = CORP", // NetBIOS fallback documented in the migration plan
				"workgroup = CORP",
				"netbios name = rdpgw-auth",
				"# winbind separator omitted on purpose", // backslash = default, never written
				"dedicated keytab file = /var/lib/samba/rdpgw.keytab",
				"sync machine password to keytab = \"/var/lib/samba/rdpgw.keytab:sync_spns:sync_kvno:machine_password\"",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := optsFor(t)
			if err := provision(tc.conf, p); err != nil {
				t.Fatal(err)
			}
			staged, stkrb5 := stageFor(t, tc.conf)
			smb, err := os.ReadFile(p.SmbTarget)
			if err != nil {
				t.Fatal(err)
			}
			if want, _ := os.ReadFile(staged); string(smb) != string(want) {
				t.Errorf("smb.conf not a copy of the staged template:\n%s", smb)
			}
			krb5, err := os.ReadFile(p.Krb5Target)
			if err != nil {
				t.Fatal(err)
			}
			if want, _ := os.ReadFile(stkrb5); string(krb5) != string(want) {
				t.Errorf("krb5.conf not a copy of the staged template:\n%s", krb5)
			}
			for _, want := range tc.wants {
				if !strings.Contains(string(smb), want) {
					t.Errorf("smb.conf missing %q:\n%s", want, smb)
				}
			}
			// The generated file is proven against samba's own parser when
			// the host ships testparm (WSL2/Linux CI); skipped elsewhere.
			validateSmbConfWithTestparm(t, p.SmbTarget, tc.wantSeparator)
			if !strings.Contains(string(krb5), fmt.Sprintf("default_realm = %s", tc.krb5DefaultRealm)) {
				t.Errorf("krb5.conf wrong default_realm:\n%s", krb5)
			}
			// [domain_realm] keeps the configured domain spelling on the left;
			// the realm on the right is upper case.
			if !strings.Contains(string(krb5), tc.krb5DomainLine) {
				t.Errorf("krb5.conf missing domain_realm line %q:\n%s", tc.krb5DomainLine, krb5)
			}
		})
	}
}

// readOnlyFor makes writes to one of the targets fail with err, simulating
// an operator read-only mount, while staged-file writes keep working.
func readOnlyFor(t *testing.T, target string, err error) func() {
	t.Helper()
	previous := writeStagedFile
	writeStagedFile = func(name string, data []byte, perm os.FileMode) error {
		if name == target {
			return &os.PathError{Op: "open", Path: name, Err: err}
		}
		return previous(name, data, perm)
	}
	return func() { writeStagedFile = previous }
}

func TestProvisionMergesIntoWritableOperatorFile(t *testing.T) {
	// Writable target = merge: missing generated settings are added, the
	// operator's own values are kept (with a drift warning when they differ).
	conf := modernWinbindConf(t)
	p := optsFor(t)
	preexisting := []byte("[global]\n    security = user\n    passdb backend = tdbsam\n")
	if err := os.WriteFile(p.SmbTarget, preexisting, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := provision(conf, p); err != nil {
		t.Fatal(err)
	}
	got := string(mustRead(t, p.SmbTarget))
	for _, want := range []string{
		"passdb backend = tdbsam", // operator setting preserved
		"security = user",         // conflicting operator setting NOT replaced
		"realm = CORP.EXAMPLE.COM",
		"workgroup = CORP",
		"dedicated keytab file = /var/lib/samba/rdpgw.keytab",
		"sync machine password to keytab = \"/var/lib/samba/rdpgw.keytab:sync_spns:sync_kvno:machine_password\"",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("merged smb.conf missing %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "security =") != 1 {
		t.Errorf("existing operator settings must not be duplicated:\n%s", got)
	}
}

func TestProvisionMergeInsertsInsideGlobalSection(t *testing.T) {
	// The merge must not append at EOF: with a [printers] section after
	// [global], samba would reject global parameters found in a service
	// section.
	conf := modernWinbindConf(t)
	p := optsFor(t)
	preexisting := []byte(`[global]
    security = ads
    realm = CORP.EXAMPLE.COM
    workgroup = CORP
    netbios name = rdpgw-auth
    winbind use default domain = no

[printers]
    printable = yes
    path = /var/spool/samba
`)
	if err := os.WriteFile(p.SmbTarget, preexisting, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := provision(conf, p); err != nil {
		t.Fatal(err)
	}
	got := string(mustRead(t, p.SmbTarget))
	keytabAt := strings.Index(got, "dedicated keytab file")
	sectionAt := strings.Index(got, "[printers]")
	if keytabAt < 0 || sectionAt < 0 {
		t.Fatalf("missing keytab directive or printers section:\n%s", got)
	}
	if keytabAt > sectionAt {
		t.Errorf("keytab directives must be merged inside [global], before [printers]:\n%s", got)
	}
	validateSmbConfWithTestparm(t, p.SmbTarget, `+`)
}

func TestProvisionWritableAlreadyCompleteUntouched(t *testing.T) {
	// A writable file that already carries every generated setting and no
	// conflicts is left byte-identical.
	conf := modernWinbindConf(t)
	p := optsFor(t)
	staged, _ := stageFor(t, conf)
	if err := os.WriteFile(p.SmbTarget, mustRead(t, staged), 0o644); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, p.SmbTarget)
	if err := provision(conf, p); err != nil {
		t.Fatal(err)
	}
	if after := mustRead(t, p.SmbTarget); string(after) != string(before) {
		t.Errorf("complete writable operator file must stay untouched:\n%s", after)
	}
}

func TestProvisionReadOnlyEquivalentAccepted(t *testing.T) {
	// Read-only target that already matches the generated configuration
	// semantically: nothing to do, no warning.
	conf := modernWinbindConf(t)
	p := optsFor(t)
	staged, stkrb5 := stageFor(t, conf)
	for _, pair := range []struct{ staged, target string }{{staged, p.SmbTarget}, {stkrb5, p.Krb5Target}} {
		body, err := os.ReadFile(pair.staged)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pair.target, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	restoreSmb := readOnlyFor(t, p.SmbTarget, syscall.EROFS)
	defer restoreSmb()
	restoreKrb5 := readOnlyFor(t, p.Krb5Target, syscall.EROFS)
	defer restoreKrb5()

	if err := provision(conf, p); err != nil {
		t.Fatalf("semantically equal read-only targets must be accepted: %v", err)
	}
	if got, _ := os.ReadFile(p.SmbTarget); string(got) != string(mustRead(t, staged)) {
		t.Errorf("read-only smb.conf must stay untouched")
	}
}

func TestProvisionReadOnlyDriftWarns(t *testing.T) {
	// Read-only target that differs: the operator file wins and provisioning
	// continues with an explicit warning (no fatal, no crashloop).
	conf := modernWinbindConf(t)
	p := optsFor(t)
	operator := []byte("[global]\n    security = user\n")
	if err := os.WriteFile(p.SmbTarget, operator, 0o644); err != nil {
		t.Fatal(err)
	}
	restore := readOnlyFor(t, p.SmbTarget, syscall.EROFS)
	defer restore()

	if err := provision(conf, p); err != nil {
		t.Fatalf("drifted read-only smb.conf must only warn, got %v", err)
	}
	body, _ := os.ReadFile(p.SmbTarget)
	if string(body) != string(operator) {
		t.Errorf("read-only smb.conf must stay untouched:\n%s", body)
	}
}

func TestProvisionReadOnlyContinuationDriftDetected(t *testing.T) {
	// The real-world homelab shape: an operator copy of the generated file
	// with 'winbind separator = \\' — the continuation joins the next line
	// into the value, so it is NOT semantically equal even though it looks
	// like the default at a glance.
	conf := legacyConf(t) // default backslash separator => directive omitted
	p := optsFor(t)
	stagedBody := string(mustRead(t, mustStageSmb(t, conf)))
	broken := strings.Replace(stagedBody,
		"    winbind use default domain = no\n",
		"    winbind use default domain = no\n    winbind separator = \\\\\n", 1)
	if broken == stagedBody {
		t.Fatal("fixture: separator insertion point not found in staged smb.conf")
	}
	if err := os.WriteFile(p.SmbTarget, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	equal, key := smbConfSemanticallyEqual(stagedBody, broken)
	if equal {
		t.Fatalf("continuation-joined separator must not compare equal")
	}
	if key != "global/winbind separator" {
		t.Errorf("first drifted setting = %q, want global/winbind separator", key)
	}
	restore := readOnlyFor(t, p.SmbTarget, syscall.EROFS)
	defer restore()
	if err := provision(conf, p); err != nil {
		t.Fatalf("drift must warn, not fail: %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func mustStageSmb(t *testing.T, conf config.Configuration) string {
	t.Helper()
	smb, _ := stageFor(t, conf)
	return smb
}

// validateSmbConfWithTestparm proves a generated smb.conf against samba's
// own parser: it must load without errors and the effective winbind
// separator must match wantSeparator (proving the omission strategy for the
// backslash default). Skipped where testparm is not installed.
func validateSmbConfWithTestparm(t *testing.T, path, wantSeparator string) {
	t.Helper()
	testparm, err := exec.LookPath("testparm")
	if err != nil {
		t.Skip("testparm not installed, skipping parser validation")
	}
	out, err := exec.Command(testparm, "-s", path).CombinedOutput()
	if err != nil {
		t.Fatalf("testparm rejected the generated smb.conf: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "ERROR") {
		t.Fatalf("testparm reported errors for the generated smb.conf:\n%s", out)
	}
	// -s must directly precede the file name: with it placed before another
	// option testparm ignores the positional and silently reads the host's
	// /etc/samba/smb.conf instead.
	out, err = exec.Command(testparm, `--parameter-name=winbind separator`, "-s", path).CombinedOutput()
	if err != nil {
		t.Fatalf("testparm parameter query failed: %v\n%s", err, out)
	}
	// samba prints its banner/warnings to stdout as well; the queried value
	// is the last non-empty line.
	var got string
	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if v := strings.TrimSpace(lines[i]); v != "" {
			got = v
			break
		}
	}
	if got != wantSeparator {
		t.Fatalf("effective winbind separator = %q, want %q\n%s", got, wantSeparator, out)
	}
	t.Logf("testparm accepted the generated smb.conf: %s", path)
}

// TestBuildSmbDataSeparatorFormatting pins the separator rendering contract
// derived from smb.conf(5): no escape syntax exists, any line ending in a
// backslash continues onto the next line, therefore only the backslash
// default is expressed by omitting the directive. Invalid values cannot even
// reach this function: the Separator type rejects them during decoding, and
// that decoding contract is covered in the config package tests.
func TestBuildSmbDataSeparatorFormatting(t *testing.T) {
	cases := []struct {
		separator config.SingleChar
		want      string
	}{
		{separator: config.SingleChar('\\'), want: ""}, // default: omit the directive
		{separator: 0, want: ""},                       // unset: same default, omitted
		{separator: config.SingleChar('+'), want: "+"}, // explicit non-default: written
		{separator: config.SingleChar('|'), want: "|"}, // any other single char works
	}
	for _, tc := range cases {
		conf := modernWinbindConf(t)
		conf.Winbind.Separator = tc.separator
		data, err := buildSmbData(conf)
		if err != nil {
			t.Errorf("separator %q: unexpected error: %v", tc.separator, err)
			continue
		}
		if data.SeparatorDirective != tc.want {
			t.Errorf("separator %q: directive = %q, want %q", tc.separator, data.SeparatorDirective, tc.want)
		}
	}
}

func TestProvisionKrb5DriftWarns(t *testing.T) {
	// Exactly the calacirya deployment: krb5.conf is a read-only ConfigMap
	// subPath mount. Provisioning must warn about the drift and continue —
	// never crashloop the daemon.
	conf := modernWinbindConf(t)
	p := optsFor(t)
	operator := []byte("[libdefaults]\n    default_realm = EX.FI\n")
	if err := os.WriteFile(p.Krb5Target, operator, 0o644); err != nil {
		t.Fatal(err)
	}
	restore := readOnlyFor(t, p.Krb5Target, syscall.EROFS)
	defer restore()

	if err := provision(conf, p); err != nil {
		t.Fatalf("read-only krb5.conf must not fail provisioning: %v", err)
	}
	body, _ := os.ReadFile(p.Krb5Target)
	if string(body) != string(operator) {
		t.Errorf("read-only krb5.conf content must stay untouched:\n%s", body)
	}
}

func TestProvisionKrb5NonErofsWriteErrorWarns(t *testing.T) {
	// Mounts can also deny writes with EACCES; any unwritable target is
	// operator-managed and only produces a warning.
	conf := modernWinbindConf(t)
	p := optsFor(t)
	operator := []byte("[libdefaults]\n    default_realm = EX.FI\n")
	if err := os.WriteFile(p.Krb5Target, operator, 0o644); err != nil {
		t.Fatal(err)
	}
	restore := readOnlyFor(t, p.Krb5Target, syscall.EACCES)
	defer restore()

	if err := provision(conf, p); err != nil {
		t.Fatalf("unwritable krb5.conf must not fail provisioning: %v", err)
	}
	body, _ := os.ReadFile(p.Krb5Target)
	if string(body) != string(operator) {
		t.Errorf("unwritable krb5.conf content must stay untouched:\n%s", body)
	}
}

func TestProvisionMissingTargetUnwritableExplodes(t *testing.T) {
	// Policy 1: a missing file MUST be written; if that is impossible the
	// daemon refuses to start.
	conf := modernWinbindConf(t)
	p := optsFor(t)
	restore := readOnlyFor(t, p.SmbTarget, syscall.EROFS)
	defer restore()

	if err := provision(conf, p); !errors.Is(err, ErrExplosion) {
		t.Fatalf("missing unwritable smb.conf must explode, got %v", err)
	}
}
