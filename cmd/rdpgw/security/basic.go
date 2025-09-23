package security

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config/hostselection"
)

var (
	Hosts         []string
	HostSelection string
)

func CheckHost(ctx context.Context, host string) (bool, error) {
	switch HostSelection {
	case hostselection.Any, hostselection.AnySigned:
		return true, nil
	case hostselection.Signed:
		// todo get from context?
		return false, errors.New("cannot verify host in 'signed' mode as token data is missing")
	case hostselection.RoundRobin, hostselection.Unsigned:
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
