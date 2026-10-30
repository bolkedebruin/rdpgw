package ntlm

import (
	"errors"
	"log"
	"sync"
)

// ErrNullBackend is the denial reported by NullBackend. Wrap it (fmt.Errorf
// with %w) when a cause is known so callers can tell misconfiguration from
// protocol failures.
var ErrNullBackend = errors.New("ntlm: backend inactive due to misconfiguration")

// NullBackend is the verifier installed when the NTLM configuration is
// unusable (AuthProtocols.Ntlm missing/disabled/empty, or no backend could
// be built from it). It keeps the gRPC auth service alive and answers:
// every handshake is explicitly denied with ErrNullBackend and the reason
// is logged once at install time, so operators see the exact configuration
// defect instead of a silent panic or connection hang. No client can
// authenticate until the configuration is fixed.
type NullBackend struct {
	// Reason explains what is wrong with the configuration. Logged at
	// install time and wrapped into every denial.
	Reason string

	once sync.Once
}

func (b *NullBackend) NewContext() Context { return &nullContext{b: b} }

type nullContext struct {
	b *NullBackend
}

// Negotiate answers the handshake with an explicit denial; the reason is
// logged exactly once to avoid log flooding under client retries.
func (c *nullContext) Negotiate(negotiate []byte) ([]byte, error) {
	c.b.once.Do(func() {
		log.Printf("NTLM: rejecting all handshakes: %s", c.b.Reason)
	})
	return nil, ErrNullBackend
}

func (c *nullContext) Authenticate(authenticate []byte) (string, bool, error) {
	return "", false, ErrNullBackend
}

func (c *nullContext) Close() {}
