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
		// todo get from context?
		return false, errors.New("cannot verify host in 'signed' mode as token data is missing")
	case "roundrobin", "unsigned":
		log.Printf("Checking host")
		s := getSessionInfo(ctx)
		if s == nil {
			return false, errors.New("no valid session info found in context")
		}
		for _, h := range Hosts {
			if s.UserName != "" {
				h = strings.Replace(h, "{{ preferred_username }}", s.UserName, 1)
			}
			if h == host {
				return true, nil
			}
		}
		return false, fmt.Errorf("invalid host %s", host)
	}

	return false, errors.New("unrecognized host selection criteria")
}
