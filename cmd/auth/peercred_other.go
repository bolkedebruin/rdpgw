//go:build !linux

package main

import (
	"log"
	"net"
)

// On non-Linux platforms SO_PEERCRED isn't portable, so we don't gate by
// peer credentials. rdpgw-auth itself depends on PAM and is effectively
// Linux-only; this file just keeps the build green if anyone tries.
func newGatedListener(l net.Listener, _, _ []int) net.Listener {
	log.Printf("rdpgw-auth: peer-credential gating is not implemented on this platform; relying on socket file mode for access control")
	return l
}
