//go:build linux

package main

import (
	"fmt"
	"log"
	"net"

	"golang.org/x/sys/unix"
)

// gatedListener wraps a unix-socket net.Listener and accepts only
// connections whose peer UID/GID is on the allow-list. The check is
// applied at Accept(), before any application data is read, so the
// gRPC server never sees an unauthorized caller.
type gatedListener struct {
	net.Listener
	allowedUIDs map[uint32]struct{}
	allowedGIDs map[uint32]struct{}
}

func newGatedListener(l net.Listener, uids []int, gids []int) net.Listener {
	uidSet := make(map[uint32]struct{}, len(uids))
	for _, u := range uids {
		uidSet[uint32(u)] = struct{}{}
	}
	gidSet := make(map[uint32]struct{}, len(gids))
	for _, g := range gids {
		gidSet[uint32(g)] = struct{}{}
	}
	return &gatedListener{Listener: l, allowedUIDs: uidSet, allowedGIDs: gidSet}
}

func (l *gatedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ucred, err := peerCred(conn)
		if err != nil {
			log.Printf("rejecting connection: cannot read peer credentials: %s", err)
			conn.Close()
			continue
		}
		if !l.allowed(ucred) {
			log.Printf("rejecting connection from uid=%d gid=%d pid=%d", ucred.Uid, ucred.Gid, ucred.Pid)
			conn.Close()
			continue
		}
		return conn, nil
	}
}

func (l *gatedListener) allowed(c *unix.Ucred) bool {
	if _, ok := l.allowedUIDs[c.Uid]; ok {
		return true
	}
	if _, ok := l.allowedGIDs[c.Gid]; ok {
		return true
	}
	return false
}

func peerCred(conn net.Conn) (*unix.Ucred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a *net.UnixConn (got %T)", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		ucred    *unix.Ucred
		credErr  error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return nil, ctrlErr
	}
	if credErr != nil {
		return nil, credErr
	}
	return ucred, nil
}
