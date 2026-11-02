package security

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
)

var (
	Hosts         []string
	HostSelection string
)

func CheckHost(ctx context.Context, host string) (bool, error) {
	switch HostSelection {
	case "any":
		return true, nil
	case "signed":
		// In signed mode the host is resolved from the signed query token at
		// /connect and bound into the PAA token as RemoteServer. CheckPAACookie
		// copies it to tunnel.TargetServer, so the channel request must match it
		// and must still be on the configured allow-list.
		t := getTunnel(ctx)
		if t == nil || t.TargetServer == "" {
			return false, errors.New("no token-bound target host found in context")
		}
		if t.TargetServer != host {
			return false, fmt.Errorf("host %s does not match token host %s", host, t.TargetServer)
		}
		var username string
		if t.User != nil {
			username = t.User.UserName()
		}
		for _, h := range Hosts {
			if matchSignedHost(h, host, username) {
				return true, nil
			}
		}
		return false, fmt.Errorf("invalid host %s", host)
	case "roundrobin", "unsigned":
		s := getTunnel(ctx)
		if s.User.UserName() == "" {
			return false, errors.New("no valid session info or username found in context")
		}

		log.Printf("Checking host for user %s", s.User.UserName())
		for _, h := range Hosts {
			h = strings.Replace(h, "{{ preferred_username }}", s.User.UserName(), 1)
			if h == host {
				return true, nil
			}
		}
		return false, fmt.Errorf("invalid host %s", host)
	}

	return false, errors.New("unrecognized host selection criteria")
}

const usernamePlaceholder = "{{ preferred_username }}"

// matchSignedHost reports whether host matches the allow-list entry for the
// given PAA token subject. Plain entries must match exactly. Templated entries
// are expanded at /connect with the full username, while the PAA subject may
// have been shortened by SplitUserDomain ("alice@corp" -> "alice"), so the
// substituted part must equal the subject or the subject followed by "@domain".
func matchSignedHost(entry, host, username string) bool {
	i := strings.Index(entry, usernamePlaceholder)
	if i < 0 {
		return entry == host
	}
	if username == "" {
		return false
	}
	prefix, suffix := entry[:i], entry[i+len(usernamePlaceholder):]
	if len(host) < len(prefix)+len(suffix) ||
		!strings.HasPrefix(host, prefix) || !strings.HasSuffix(host, suffix) {
		return false
	}
	name := host[len(prefix) : len(host)-len(suffix)]
	return name == username || strings.HasPrefix(name, username+"@")
}
