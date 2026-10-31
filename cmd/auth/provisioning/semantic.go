package provisioning

import (
	"fmt"
	"sort"
	"strings"
)

// The provisioner compares the staged (desired) configuration with an
// operator-managed target that cannot be overwritten. Equality is semantic,
// not byte-wise: only the settings this program manages are compared, after
// normalizing formatting, comments, continuation lines and insignificant
// case. Extra operator settings are always acceptable.

// smbConfSemanticallyEqual reports whether current already carries the
// settings of the generated file. The second return value names the first
// drifted setting, for the operator-facing warning.
func smbConfSemanticallyEqual(staged, current string) (bool, string) {
	want := parseSmbConf(staged)
	got := parseSmbConf(current)

	// samba defaults for managed settings that the generated file may omit
	// on purpose: the backslash separator is expressed by NOT writing it.
	want["global/winbind separator"] = wantOr(want["global/winbind separator"], `\`)
	got["global/winbind separator"] = wantOr(got["global/winbind separator"], `\`)

	for _, key := range sortedKeys(want) {
		if normalizeSmbValue(key, got[key]) != normalizeSmbValue(key, want[key]) {
			return false, key
		}
	}
	return true, ""
}

// wantOr returns value unless empty, in which case fallback applies.
func wantOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// smbMergePlan returns the generated [global] settings whose key is absent
// from the current file, the first conflicting operator setting (reported,
// never replaced), and hazard=true when the last [global] line ends with a
// backslash: appending there would be swallowed into that value by samba's
// line continuation.
func smbMergePlan(staged, current string) (missing []string, conflict string, hazard bool) {
	if smbGlobalEndsWithBackslash(current) {
		return nil, "winbind separator (trailing backslash would swallow appended settings)", true
	}

	currentSettings := parseSmbConf(current)
	for _, line := range smbGlobalLines(staged) {
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.Join(strings.Fields(line[:eq]), " "))
		value := strings.Join(strings.Fields(line[eq+1:]), " ")
		full := "global/" + key

		currentValue, present := currentSettings[full]
		if !present {
			missing = append(missing, line)
			continue
		}
		if conflict == "" && normalizeSmbValue(full, currentValue) != normalizeSmbValue(full, value) {
			conflict = key
		}
	}

	// The generated file may express the default backslash separator by
	// omitting the directive; any operator value that differs from the
	// generated one is a conflict.
	desiredSeparator := `\`
	if v, present := parseSmbConf(staged)["global/winbind separator"]; present {
		desiredSeparator = v
	}
	if v, present := currentSettings["global/winbind separator"]; present &&
		normalizeSmbValue("global/winbind separator", v) != normalizeSmbValue("global/winbind separator", desiredSeparator) &&
		conflict == "" {
		conflict = "winbind separator"
	}
	return missing, conflict, false
}

// smbGlobalLines extracts the settable lines (no comments/blanks/section
// headers) of the generated [global] section.
func smbGlobalLines(content string) []string {
	var lines []string
	section := ""
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(trimmed[1 : len(trimmed)-1])
			continue
		}
		if section != "global" {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

// smbGlobalEndsWithBackslash reports whether the last meaningful line of the
// [global] section ends with a continuation backslash.
func smbGlobalEndsWithBackslash(content string) bool {
	section := ""
	last := ""
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(trimmed[1 : len(trimmed)-1])
			continue
		}
		if section == "global" {
			last = raw
		}
	}
	return strings.HasSuffix(strings.TrimRight(last, " \t"), `\`)
}

// parseSmbConf flattens an smb.conf into "section/key" -> value. It applies
// the file format rules that matter for comparison: line continuation on a
// trailing backslash, comment/blank line removal, first '=' only, keys case
// insensitive, surrounding whitespace trimmed.
func parseSmbConf(content string) map[string]string {
	out := make(map[string]string)
	section := ""

	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// continuation: a line ending in a backslash joins the next one
		for strings.HasSuffix(strings.TrimRight(line, " \t"), `\`) && i+1 < len(lines) {
			line = strings.TrimRight(line, " \t")
			line = line[:len(line)-1] + lines[i+1]
			i++
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.Join(strings.Fields(trimmed[:eq]), " "))
		value := strings.Join(strings.Fields(trimmed[eq+1:]), " ")
		out[section+"/"+key] = value
	}
	return out
}

// normalizeSmbValue makes values comparable: case-insensitive, except for
// keytab paths where the filesystem is case sensitive.
func normalizeSmbValue(key, value string) string {
	if strings.Contains(key, "keytab") {
		return value
	}
	return strings.ToLower(value)
}

// krb5ConfSemanticallyEqual reports whether current carries the settings of
// the generated krb5.conf (realm, KDC/admin servers, domain mappings).
func krb5ConfSemanticallyEqual(staged, current string) (bool, string) {
	want := parseKrb5Conf(staged)
	got := parseKrb5Conf(current)

	for _, key := range sortedKeys(want) {
		w := strings.Join(want[key], ",")
		g := strings.Join(got[key], ",")
		if w != g {
			return false, key
		}
	}
	return true, ""
}

// parseKrb5Conf flattens krb5.conf into "section/key" -> sorted values.
// Realms nest an extra level: "realms/<REALM>/kdc" is a list per realm.
func parseKrb5Conf(content string) map[string][]string {
	out := make(map[string][]string)
	section := ""
	realm := ""
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			realm = ""
			continue
		}
		if section == "realms" {
			if strings.HasSuffix(line, "{") {
				realm = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line, "{")))
				continue
			}
			if line == "}" {
				realm = ""
				continue
			}
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		value := strings.TrimSpace(line[eq+1:])
		full := section + "/" + key
		if section == "realms" && realm != "" {
			full = section + "/" + realm + "/" + key
		}
		out[full] = append(out[full], value)
	}
	for key := range out {
		sort.Strings(out[key])
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// describeDrift renders a short operator-facing summary of the first
// mismatching setting.
func describeDrift(target, key string) string {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) == 2 {
		return fmt.Sprintf("%s: setting %q differs", target, parts[1])
	}
	return fmt.Sprintf("%s: setting %q differs", target, key)
}
