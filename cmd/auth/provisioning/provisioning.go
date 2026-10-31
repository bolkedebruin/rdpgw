package provisioning

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"unicode"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
)

const (
	// defaultStageDir is transient and owned by the container image; it is
	// never an operator mount. Rendering happens here first, then the
	// operator's targets are reconciled against the staged result.
	defaultStageDir = "/tmp/rdpgw"

	defaultSmbTarget  = "/etc/samba/smb.conf"
	defaultKrb5Target = "/etc/krb5.conf"
)

// provisionOptions parameterizes the filesystem locations so the
// provisioner can be exercised inside temporary directories by tests.
type provisionOptions struct {
	StageDir   string
	SmbTarget  string
	Krb5Target string
}

// ErrExplosion is returned when a required target file does not exist and
// cannot be created (read-only parent, no permissions): the daemon refuses
// to start without the configuration files it depends on.
var ErrExplosion = errors.New("rdpgw-auth: required configuration file is missing and cannot be created")

// smbTemplateData carries the fields rendered into smb.conf.tmpl. Realm is
// the FQDN of the domain (winbind.Domain), falling back to the NetBIOS
// workgroup name for legacy deployments that only configure the shorthand.
type smbTemplateData struct {
	Realm     string
	Workgroup string
	Hostname  string
	// SeparatorDirective is the exact text following "winbind separator ="
	// in the rendered file. Empty means the directive is OMITTED: that is
	// the only correct spelling for the default backslash separator, since
	// smb.conf has no escape syntax and any line ending in a backslash is
	// continued onto the next line.
	SeparatorDirective string
	KerberosShare      bool
	KeytabPath         string
}

// krb5TemplateData carries the fields rendered into krb5.conf.tmpl. KDCs
// and admin servers come from the configured DomainControllers; without
// any, kerberos falls back to SRV record discovery.
type krb5TemplateData struct {
	// Realm is the kerberos realm in upper case (AD convention).
	Realm string
	// Domain is the DNS domain as configured, used for [domain_realm].
	Domain            string
	DomainControllers []config.FlexibleDomainController
}

// Provision prepares the container's Samba and Kerberos configuration for
// a winbind-backed deployment: it renders both templates into the staging
// directory and then reconciles the operator targets. Deployments without
// any winbind capability (no Kerberos keytab share and no winbind NTLM
// backend) skip provisioning entirely.
//
// An operator-managed smb.conf on a read-only volume that lacks the
// mandatory keytab directives terminates the daemon via log.Fatalf: the
// gateway must never run half-configured against the domain (strict
// explode policy of the operations plan, Milestone 2).
func Provision(conf config.Configuration) error {
	if !UsesWinbind(conf) {
		log.Printf("Provisioning: no Kerberos keytab share and no winbind NTLM backend enabled, skipping smb.conf/krb5.conf provisioning")
		return nil
	}
	if conf.Winbind == nil {
		// Unreachable through config.Load (Validate requires Winbind for
		// every winbind-capable deployment); guarded for direct callers.
		return fmt.Errorf("provisioning: winbind capability requested but the Winbind configuration block is missing")
	}
	return provision(conf, provisionOptions{
		StageDir:   defaultStageDir,
		SmbTarget:  defaultSmbTarget,
		Krb5Target: defaultKrb5Target,
	})
}

// UsesWinbind reports whether the deployment needs Samba/Kerberos files at
// all: either the Kerberos keytab share or a winbind NTLM backend is on.
func UsesWinbind(conf config.Configuration) bool {
	if conf.AuthProtocols == nil {
		return false
	}
	if kerberos := conf.AuthProtocols.Kerberos; kerberos != nil && kerberos.Share {
		return true
	}
	if ntlm := conf.AuthProtocols.Ntlm; ntlm != nil && ntlm.Enabled {
		for _, b := range ntlm.Backends {
			if strings.EqualFold(b, config.NtlmBackendWinbind) {
				return true
			}
		}
	}
	return false
}

func provision(conf config.Configuration, p provisionOptions) error {
	if err := os.MkdirAll(p.StageDir, 0o700); err != nil {
		return fmt.Errorf("provisioning: cannot create staging dir %s: %w", p.StageDir, err)
	}

	smbData, err := buildSmbData(conf)
	if err != nil {
		return err
	}
	krb5Data := buildKrb5Data(conf)

	smbStaged, err := stageTemplate("smb.conf.tmpl", smbData, p.StageDir)
	if err != nil {
		return fmt.Errorf("provisioning: cannot stage smb.conf: %w", err)
	}
	krb5Staged, err := stageTemplate("krb5.conf.tmpl", krb5Data, p.StageDir)
	if err != nil {
		return fmt.Errorf("provisioning: cannot stage krb5.conf: %w", err)
	}
	log.Printf("Provisioning: staged configuration under %s (smb.conf, krb5.conf)", p.StageDir)

	if err := reconcile(smbStaged, p.SmbTarget, true, smbConfSemanticallyEqual); err != nil {
		return err
	}
	return reconcile(krb5Staged, p.Krb5Target, false, krb5ConfSemanticallyEqual)
}

// buildSmbData fills the smb.conf template view model from any schema
// shape: with the legacy workgroup shorthand the realm falls back to the
// NetBIOS name so net ads can still discover the real FQDN via DNS.
func buildSmbData(conf config.Configuration) (smbTemplateData, error) {
	kerberos := conf.AuthProtocols.Kerberos
	keytabSharing := kerberos != nil && kerberos.Share
	keytabPath := ""
	if keytabSharing {
		keytabPath = kerberos.KeytabPath
	}
	data := smbTemplateData{
		// Samba's `realm` is the kerberos realm; AD issues tickets with the
		// upper-case realm, so normalize it (same as krb5.conf).
		Realm: strings.ToUpper(conf.Winbind.Domain),
		// NetBIOS name of the machine account in AD; empty means Samba
		// derives it from the container hostname, which the operations
		// plan flags as deficit-prone for pod restarts.
		Hostname:      conf.Winbind.Hostname,
		Workgroup:     conf.Winbind.Workgroup,
		KerberosShare: keytabSharing,
		KeytabPath:    keytabPath,
	}
	if data.Realm == "" {
		data.Realm = strings.ToUpper(data.Workgroup)
	}

	// Format the separator for the smb.conf parser:
	//   - the zero value means "samba default", which is exactly the backslash;
	//   - backslash itself is rendered by OMITTING the directive: the file
	//     parser performs no escape resolution and any line ending in a
	//     backslash continues onto the next line (verified with testparm);
	//   - any other single character (the Separator type guarantees exactly
	//     one, non-control rune) is written verbatim.
	sep := conf.Winbind.Separator
	if sep == 0 {
		sep = config.DefaultSeparator
	}
	if sep != config.DefaultSeparator {
		data.SeparatorDirective = sep.String()
	}

	// smb.conf values are written verbatim: no control characters and no
	// trailing backslash are tolerated, the latter because it would make
	// the rendered parameter line continue onto the next one.
	for name, value := range map[string]string{
		"winbind.domain":      data.Realm,
		"winbind.workgroup":   data.Workgroup,
		"winbind.hostname":    data.Hostname,
		"kerberos.keytabPath": data.KeytabPath,
	} {
		if value == "" {
			continue
		}
		if strings.HasSuffix(value, `\`) {
			return smbTemplateData{}, fmt.Errorf(
				"provisioning: %s %q ends with a backslash, which would make the rendered smb.conf line continue onto the next one", name, value)
		}
		if strings.ContainsAny(value, "\r\n") || containsControlRune(value) {
			return smbTemplateData{}, fmt.Errorf(
				"provisioning: %s %q contains a newline or control character and cannot be written to smb.conf", name, value)
		}
	}
	return data, nil
}

// containsControlRune rejects smb.conf injection vectors: unprintable runes
// make the rendered parameter line untrustworthy. Plain spaces are fine,
// internal whitespace is preserved by the samba parser.
func containsControlRune(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// buildKrb5Data fills the krb5.conf template view model. Kerberos realms are
// upper-case by convention (and Active Directory issues tickets with the
// upper-case realm), so Realm is normalized to upper case while Domain keeps
// the operator's spelling for the [domain_realm] lookups, which are DNS
// domain names and conventionally lower case.
func buildKrb5Data(conf config.Configuration) krb5TemplateData {
	domain := conf.Winbind.Domain
	if domain == "" {
		domain = conf.Winbind.Workgroup
	}
	return krb5TemplateData{
		Realm:             strings.ToUpper(domain),
		Domain:            domain,
		DomainControllers: conf.Winbind.DomainControllers,
	}
}

// stageTemplate renders one embedded template into the staging directory
// and returns the path of the rendered artifact.
func stageTemplate(name string, data interface{}, stageDir string) (string, error) {
	body, err := templatesFS.ReadFile(templatesDir + name)
	if err != nil {
		return "", fmt.Errorf("template %s not packaged: %w", name, err)
	}
	t, err := template.New(name).Parse(string(body))
	if err != nil {
		return "", fmt.Errorf("template %s is invalid: %w", name, err)
	}
	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return "", fmt.Errorf("cannot render %s: %w", name, err)
	}
	staged := strings.TrimSuffix(filepath.Join(stageDir, name), ".tmpl")
	if err := os.WriteFile(staged, out.Bytes(), 0o644); err != nil {
		return "", fmt.Errorf("cannot write staged file %s: %w", staged, err)
	}
	return staged, nil
}

// reconcile applies the uniform provisioning policy to one target file:
//
//  1. target missing: write the staged file — if that is impossible the
//     daemon refuses to start (ErrExplosion), because the file is required;
//  2. target present: try to merge the generated settings into it (smb) or
//     overwrite it (krb5) when writable;
//  3. merge/overwrite succeeded: done — existing operator settings are kept,
//     missing managed settings are added, nothing is replaced;
//  4. target not writable: accept when it is semantically equal to the
//     generated configuration;
//  5. otherwise warn that the operator setting wins and expected features
//     (Kerberos/winbind authentication) may fail until reconciled.
func reconcile(staged, target string, merge bool, semanticallyEqual func(staged, current string) (bool, string)) error {
	stagedContent, err := os.ReadFile(staged)
	if err != nil {
		return fmt.Errorf("provisioning: cannot read staged %s: %w", staged, err)
	}

	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		if err := writeStagedFile(target, stagedContent, 0o644); err != nil {
			return fmt.Errorf("%w: %s does not exist and cannot be created (%v): "+
				"provide the file or a writable location for it", ErrExplosion, target, err)
		}
		log.Printf("Provisioning: installed %s", target)
		return nil
	}

	current, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("provisioning: cannot read %s: %w", target, err)
	}

	if merge {
		_, changedKeys, conflict, mergeErr := mergeSmbConf(target, string(stagedContent), string(current))
		if mergeErr == nil {
			if len(changedKeys) > 0 {
				log.Printf("Provisioning: merged missing settings into %s: %v", target, changedKeys)
			} else {
				log.Printf("Provisioning: %s already carries all generated settings", target)
			}
			if conflict != "" {
				log.Printf("WARNING: %s keeps its own value for %q (not replaced). "+
					"The operator setting wins; expected features such as Kerberos/winbind "+
					"authentication may fail until it matches the generated configuration.", target, conflict)
			}
			return nil
		}
		if !isReadOnlyFS(mergeErr) {
			return fmt.Errorf("provisioning: cannot merge into %s: %w", target, mergeErr)
		}
	} else {
		if err := writeStagedFile(target, stagedContent, 0o644); err == nil {
			log.Printf("Provisioning: wrote %s", target)
			return nil
		}
	}

	if equal, key := semanticallyEqual(string(stagedContent), string(current)); equal {
		log.Printf("Provisioning: %s is read-only but semantically identical to the generated configuration", target)
		return nil
	} else {
		log.Printf("WARNING: %s is not writable and differs from the generated configuration (%s). "+
			"The operator-managed file wins; expected features such as Kerberos/winbind authentication "+
			"may fail until it matches.", target, describeDrift(target, key))
		return nil
	}
}

// mergeSmbConf adds the generated settings that the operator file does not
// carry yet, inside [global], and reports which were added plus the first
// operator setting that conflicts with the generated value (conflicts are
// reported but never replaced). A [global] section whose last line ends in a
// backslash is treated as a conflict and left alone: the parser would join
// any appended line into that value.
func mergeSmbConf(target, staged, current string) (merged bool, addedKeys []string, conflict string, err error) {
	missing, conflict, hazard := smbMergePlan(staged, current)
	if hazard {
		return false, nil, "winbind separator (trailing backslash would swallow appended settings)", nil
	}
	if len(missing) == 0 {
		return false, nil, conflict, nil
	}
	updated := insertAtGlobalEnd(current, missing)
	if err := writeStagedFile(target, []byte(updated), 0o644); err != nil {
		return false, nil, "", err
	}
	for _, line := range missing {
		eq := strings.Index(line, "=")
		if eq > 0 {
			addedKeys = append(addedKeys, strings.ToLower(strings.TrimSpace(line[:eq])))
		}
	}
	return true, addedKeys, conflict, nil
}

// insertAtGlobalEnd places the given setting lines at the end of the
// [global] section: directly before the next section header, or at EOF when
// no further section exists. A file without a [global] section gets one
// prepended, because parameters are only legal inside a section.
func insertAtGlobalEnd(content string, lines []string) string {
	kept := strings.SplitAfter(strings.ReplaceAll(content, "\r\n", "\n"), "\n")

	globalStart := -1
	for i, line := range kept {
		if strings.EqualFold(strings.TrimSpace(line), "[global]") {
			globalStart = i
			break
		}
	}
	if globalStart == -1 {
		var b strings.Builder
		b.WriteString("[global]\n")
		for _, line := range lines {
			b.WriteString("    ")
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("\n")
		b.WriteString(content)
		return b.String()
	}

	insertAt := len(kept)
	for i := globalStart + 1; i < len(kept); i++ {
		trimmed := strings.TrimSpace(kept[i])
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			insertAt = i
			break
		}
	}

	var b strings.Builder
	for i := 0; i < insertAt; i++ {
		b.WriteString(kept[i])
	}
	for _, line := range lines {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	if insertAt < len(kept) {
		b.WriteString("\n")
	}
	for i := insertAt; i < len(kept); i++ {
		b.WriteString(kept[i])
	}
	return b.String()
}

// isReadOnlyFS reports the platform's "read-only file system" failures,
// including wrapped ones.
func isReadOnlyFS(err error) bool {
	return errors.Is(err, syscall.EROFS)
}

// writeStagedFile is swappable in tests so read-only mounts can be simulated
// deterministically (a real read-only mount needs privileges unavailable on
// CI).
var writeStagedFile = os.WriteFile
