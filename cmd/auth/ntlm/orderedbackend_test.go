package ntlm

import (
	"errors"
	"testing"
)

type fakeBackend struct {
	// challenge returned by Negotiate; nil means the backend refuses to
	// commit to the handshake.
	challenge []byte
	// negotiateErr is returned as an infrastructure failure.
	negotiateErr error
	// auth results.
	authUser string
	authOK   bool
	authErr  error
	// closed is set by fakeContext.Close.
	closed bool
}

func (f *fakeBackend) NewContext() Context { return &fakeContext{b: f} }

type fakeContext struct {
	b *fakeBackend
}

func (c *fakeContext) Negotiate([]byte) ([]byte, error) { return c.b.challenge, c.b.negotiateErr }
func (c *fakeContext) Authenticate([]byte) (string, bool, error) {
	return c.b.authUser, c.b.authOK, c.b.authErr
}
func (c *fakeContext) Close() { c.b.closed = true }

func TestOrderedBackendSkipsRefusingBackend(t *testing.T) {
	refusing := &fakeBackend{challenge: nil}
	willing := &fakeBackend{challenge: []byte{0x01}, authUser: "alice", authOK: true}
	oc := NewOrderedBackend(refusing, willing)

	ctx := oc.NewContext()
	challenge, err := ctx.Negotiate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(challenge) != "\x01" {
		t.Fatalf("challenge = %v, want [1]", challenge)
	}
	if !refusing.closed {
		t.Errorf("refusing backend context was not closed after skipping")
	}
	user, ok, err := ctx.Authenticate(nil)
	if err != nil || !ok || user != "alice" {
		t.Fatalf("Authenticate = (%q, %v, %v), want (alice, true, nil)", user, ok, err)
	}
}

func TestOrderedBackendAllRefuse(t *testing.T) {
	oc := NewOrderedBackend(&fakeBackend{}, &fakeBackend{})
	ctx := oc.NewContext()
	if _, err := ctx.Negotiate(nil); !errors.Is(err, ErrNoBackendClaimed) {
		t.Fatalf("error = %v, want ErrNoBackendClaimed", err)
	}
	if _, _, err := ctx.Authenticate(nil); !errors.Is(err, ErrNoBackendClaimed) {
		t.Fatalf("Authenticate error = %v, want ErrNoBackendClaimed", err)
	}
}

func TestOrderedBackendEmpty(t *testing.T) {
	oc := NewOrderedBackend()
	ctx := oc.NewContext()
	if ctx == nil {
		t.Fatalf("empty chain must still yield a live denying context")
	}
	if _, err := ctx.Negotiate(nil); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("error = %v, want ErrNoBackend", err)
	}
	if _, _, err := ctx.Authenticate(nil); !errors.Is(err, ErrNoBackendClaimed) {
		t.Fatalf("Authenticate error = %v, want ErrNoBackendClaimed", err)
	}
}

func TestOrderedBackendNegotiateErrorSkipsToNext(t *testing.T) {
	failing := &fakeBackend{negotiateErr: errors.New("boom")}
	willing := &fakeBackend{challenge: []byte{0x02}}
	oc := NewOrderedBackend(failing, willing)

	ctx := oc.NewContext()
	challenge, err := ctx.Negotiate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(challenge) != "\x02" {
		t.Fatalf("challenge = %v, want [2]", challenge)
	}
	if !failing.closed {
		t.Errorf("failing backend context was not closed")
	}
}

func TestOrderedBackendNilEntriesDropped(t *testing.T) {
	var nilLocal *LocalBackend
	oc := NewOrderedBackend(nil, nilLocal, &fakeBackend{challenge: []byte{0x01}})
	if len(oc.Backends) != 1 {
		t.Fatalf("chain length = %d, want 1", len(oc.Backends))
	}
	ctx := oc.NewContext()
	if _, err := ctx.Negotiate(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
