package ntlm

import (
	"errors"
	"log"
)

// Sentinel errors reported by OrderedBackend.
var (
	// ErrNoBackend is returned when the ordered chain is empty.
	ErrNoBackend = errors.New("ntlm: no backend configured")
	// ErrNoBackendClaimed is returned when every backend in the chain
	// refused to commit to a handshake during Negotiate.
	ErrNoBackendClaimed = errors.New("ntlm: no backend claimed the handshake")
)

// OrderedBackend chains multiple NTLM verifiers in an operator-defined
// order. The chain is resolved per handshake at the NEGOTIATE step: each
// backend in turn is asked for a CHALLENGE; the first backend that
// successfully commits to the handshake is used for the AUTHENTICATE step
// of that handshake. Failed or unresponsive backends are skipped, which
// makes the chain work as alternative/exclusive verifiers (e.g. winbind
// first, local users as a fallback when the host is not joined to the
// domain or ntlm_auth is unavailable).
//
// Failover deliberately happens only during Negotiate. Once a backend has
// produced a challenge, credential verification errors are reported by
// that backend with ok == false and are never retried elsewhere: the
// client has already bound its response to that challenge.
type OrderedBackend struct {
	// Backends is the ordered chain of verifiers to try.
	Backends []Backend
}

// NewOrderedBackend constructs an OrderedBackend. Nil entries and entries
// of nil-pointer concrete types are dropped defensively, but no reordering
// is ever applied: the operator dictates the execution order.
func NewOrderedBackend(backends ...Backend) *OrderedBackend {
	var chain []Backend
	for _, b := range backends {
		if b == nil || isNilBackend(b) {
			continue
		}
		chain = append(chain, b)
	}
	return &OrderedBackend{Backends: chain}
}

func isNilBackend(b Backend) bool {
	switch t := b.(type) {
	case *LocalBackend:
		return t == nil
	case *WinbindBackend:
		return t == nil
	case *OrderedBackend:
		return t == nil
	case *NullBackend:
		return t == nil
	default:
		return false
	}
}

func (b *OrderedBackend) NewContext() Context {
	// An empty chain still yields a live context that answers with
	// ErrNoBackend: NTLMAuth calls NewContext() unconditionally before
	// Negotiate, so returning nil here would panic the handshake path.
	return &orderedContext{b: b}
}

type orderedContext struct {
	b       *OrderedBackend
	chosen  Context
	claimed bool
}

// Negotiate walks the backend chain. The first backend producing a
// challenge is claimed for the remainder of the handshake. A backend whose
// Negotiate yields no challenge (ok == false without a protocol error) or
// fails is closed and the next backend is tried.
func (c *orderedContext) Negotiate(negotiate []byte) ([]byte, error) {
	var lastErr error
	for _, b := range c.b.Backends {
		ctx := b.NewContext()
		challenge, err := ctx.Negotiate(negotiate)
		if err != nil {
			log.Printf("NTLM: backend %T failed during negotiate: %v", b, err)
			lastErr = err
			ctx.Close()
			continue
		}
		if challenge == nil {
			log.Printf("NTLM: backend %T did not commit to the handshake, trying next", b)
			ctx.Close()
			continue
		}
		c.chosen = ctx
		c.claimed = true
		return challenge, nil
	}
	if len(c.b.Backends) == 0 {
		return nil, ErrNoBackend
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoBackendClaimed
}

func (c *orderedContext) Authenticate(authenticate []byte) (string, bool, error) {
	if !c.claimed {
		return "", false, ErrNoBackendClaimed
	}
	return c.chosen.Authenticate(authenticate)
}

func (c *orderedContext) Close() {
	if c.chosen != nil {
		c.chosen.Close()
		c.chosen = nil
		c.claimed = false
	}
}
