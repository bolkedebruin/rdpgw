package protocol

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// resetConnections clears the global registry under its lock. Tests must
// not reassign the package-level Connections variable, since the lock
// protects the map's contents but not the variable's storage; concurrent
// goroutines from other tests can otherwise read a stale reference.
func resetConnections() {
	connectionsMu.Lock()
	clear(Connections)
	connectionsMu.Unlock()
}

// TestTunnelTrackerConcurrent hammers the global tunnel registry from many
// goroutines. The package's RegisterTunnel/RemoveTunnel write to a shared
// map, so the registry must serialize access. A concurrent write would be
// caught by the Go runtime as a fatal `concurrent map writes` (or by the
// race detector under -race).
func TestTunnelTrackerConcurrent(t *testing.T) {
	resetConnections()
	t.Cleanup(resetConnections)

	const goroutines = 200
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("tun-%d", i)
			RegisterTunnel(&Tunnel{Id: id}, &Processor{ctl: make(chan int)})
		}()
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("tun-%d", i)
			RemoveTunnel(&Tunnel{Id: id})
		}()
	}
	wg.Wait()
}

// TestDisconnectKnownConnection verifies that Disconnect signals the
// processor for a connection that exists in the registry.
func TestDisconnectKnownConnection(t *testing.T) {
	resetConnections()
	t.Cleanup(resetConnections)

	p := &Processor{ctl: make(chan int, 1)}
	connectionsMu.Lock()
	Connections["known"] = &Monitor{Processor: p}
	connectionsMu.Unlock()

	if err := Disconnect("known"); err != nil {
		t.Fatalf("Disconnect on known id returned err: %v", err)
	}
	select {
	case v := <-p.ctl:
		if v != ctlDisconnect {
			t.Errorf("ctl received %d, want ctlDisconnect=%d", v, ctlDisconnect)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Disconnect did not signal ctlDisconnect on the processor channel")
	}
}

// TestDisconnectMissingConnectionDoesNotPanic verifies that Disconnect on
// an id that is not in the registry returns an error rather than
// dereferencing a nil Monitor.
func TestDisconnectMissingConnectionDoesNotPanic(t *testing.T) {
	resetConnections()
	t.Cleanup(resetConnections)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Disconnect panicked on missing id: %v", r)
		}
	}()
	if err := Disconnect("nonexistent"); err == nil {
		t.Error("Disconnect on missing id returned no error")
	}
}
