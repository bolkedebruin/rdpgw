//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func startGatedListener(t *testing.T, allowUIDs, allowGIDs []int) (string, <-chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	addr := filepath.Join(dir, "auth.sock")

	old := syscall.Umask(0117)
	raw, err := net.Listen("unix", addr)
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { raw.Close() })

	accepted := make(chan struct{}, 1)
	gated := newGatedListener(raw, allowUIDs, allowGIDs)
	go func() {
		for {
			conn, err := gated.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			conn.Close()
		}
	}()
	return addr, accepted
}

func TestGatedListenerAcceptsCurrentUID(t *testing.T) {
	addr, accepted := startGatedListener(t, []int{os.Getuid()}, nil)

	conn, err := net.DialTimeout("unix", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	select {
	case <-accepted:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("listener did not accept connection from current UID %d", os.Getuid())
	}
}

func TestGatedListenerRejectsForeignUID(t *testing.T) {
	// Allow a UID we are not running as.
	addr, accepted := startGatedListener(t, []int{os.Getuid() + 1}, nil)

	conn, err := net.DialTimeout("unix", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected EOF / closed conn after gate rejection, got data")
	}

	select {
	case <-accepted:
		t.Fatal("Accept handed a connection from a UID outside the allow-list to the application")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestSocketModeUmask0117(t *testing.T) {
	dir := t.TempDir()
	addr := filepath.Join(dir, "auth.sock")

	old := syscall.Umask(0117)
	l, err := net.Listen("unix", addr)
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	st, err := os.Stat(addr)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	mode := st.Mode().Perm()
	if mode&0007 != 0 {
		t.Errorf("socket mode = %#o, expected no permissions for `other`", mode)
	}
}
