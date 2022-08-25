package security

import (
	"context"
	"errors"
	"fmt"
	"log"
)

var (
	Hosts         []string
	HostSelection string
)

func BasicVerifyServer(ctx context.Context, host string) (bool, error) {
	if HostSelection == "any" {
		return true, nil
	}

	if HostSelection == "signed" {
		// todo get from context
		return false, errors.New("cannot verify host in 'signed' mode as token data is missing")
	}

	if HostSelection == "roundrobin" || HostSelection == "unsigned" {
		log.Printf("Checking host")
		for _, h := range Hosts {
			if h == host {
				return true, nil
			}
		}
		return false, fmt.Errorf("invalid host %s", host)
	}

	return false, errors.New("unrecognized host selection criteria")
}
