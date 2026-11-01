package ntlm

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/auth/database"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"github.com/patrickmn/go-cache"
)

const (
	cacheExpiration = time.Minute
	cleanupInterval = time.Minute * 5

	ntlmSignature = "NTLMSSP\x00"

	messageTypeNegotiate    = 1
	messageTypeChallenge    = 2
	messageTypeAuthenticate = 3
)

// NTLMAuth drives NTLM handshakes over the gRPC interface. It keeps one
// Context per session (keyed by the gateway supplied session id) for the
// duration of the handshake and delegates the actual protocol work to a
// Backend.
type NTLMAuth struct {
	contextCache *cache.Cache
	backend      Backend
}

// NewNTLMAuth returns an NTLMAuth backed by the in-process verifier that
// looks up passwords in the given database. Use NewNTLMAuthWithBackend to
// plug in a different backend such as winbind.
func NewNTLMAuth(database database.Database) *NTLMAuth {
	return NewNTLMAuthWithBackend(NewLocalBackend(database))
}

func NewNTLMAuthWithBackend(backend Backend) *NTLMAuth {
	h := &NTLMAuth{
		contextCache: cache.New(cacheExpiration, cleanupInterval),
		backend:      backend,
	}
	// Make sure abandoned handshakes release their resources (e.g. child
	// processes held by the winbind backend). Delete() triggers this too.
	h.contextCache.OnEvicted(func(_ string, v interface{}) {
		if c, ok := v.(Context); ok {
			c.Close()
		}
	})
	return h
}

func (h *NTLMAuth) Authenticate(message *auth.NtlmRequest) (*auth.NtlmResponse, error) {
	r := &auth.NtlmResponse{}
	r.Authenticated = false

	if message.Session == "" {
		return r, errors.New("Invalid (empty) session specified")
	}

	if message.NtlmMessage == "" {
		return r, errors.New("Empty NTLM message specified")
	}

	raw, err := base64.StdEncoding.DecodeString(message.NtlmMessage)
	if err != nil {
		return r, fmt.Errorf("Failed to decode NTLM Authorisation header: %s", err)
	}

	messageType, err := parseMessageType(raw)
	if err != nil {
		return r, err
	}

	switch messageType {
	case messageTypeNegotiate:
		// A NEGOTIATE message always starts a new handshake, even if a
		// previous one for this session was left unfinished.
		h.removeContext(message.Session)
		c := h.backend.NewContext()
		challenge, err := c.Negotiate(raw)
		if err != nil {
			c.Close()
			return r, err
		}
		h.contextCache.Set(message.Session, c, cache.DefaultExpiration)
		r.NtlmMessage = base64.StdEncoding.EncodeToString(challenge)
		return r, nil

	case messageTypeAuthenticate:
		c, found := h.getContext(message.Session)
		if !found {
			return r, errors.New("New NTLM auth sequence should start with negotiate request")
		}
		defer h.removeContext(message.Session)
		username, ok, err := c.Authenticate(raw)
		if err != nil {
			return r, err
		}
		if ok {
			r.Authenticated = true
			r.Username = username
		}
		return r, nil

	default:
		return r, fmt.Errorf("Unexpected NTLM message type %d", messageType)
	}
}

// parseMessageType validates the NTLMSSP signature and returns the
// MessageType field (see MS-NLMP 2.2.1).
func parseMessageType(raw []byte) (uint32, error) {
	if len(raw) < 12 || string(raw[:8]) != ntlmSignature {
		return 0, errors.New("Failed to parse NTLM Authorisation header: not an NTLMSSP message")
	}
	return binary.LittleEndian.Uint32(raw[8:12]), nil
}

func (h *NTLMAuth) getContext(session string) (Context, bool) {
	if c_, found := h.contextCache.Get(session); found {
		if c, ok := c_.(Context); ok {
			return c, true
		}
	}
	return nil, false
}

func (h *NTLMAuth) removeContext(session string) {
	h.contextCache.Delete(session)
}
