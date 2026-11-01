package ntlm

// Backend produces a fresh Context for every NTLM handshake. A handshake
// consists of one NEGOTIATE message (answered with a CHALLENGE) followed by
// one AUTHENTICATE message.
type Backend interface {
	NewContext() Context
}

// Context holds the state of a single NTLM handshake.
type Context interface {
	// Negotiate consumes a raw NTLM NEGOTIATE message and returns the raw
	// CHALLENGE message to send back to the client.
	Negotiate(negotiate []byte) (challenge []byte, err error)
	// Authenticate consumes a raw NTLM AUTHENTICATE message. It returns the
	// authenticated user name and true on success. A wrong password or an
	// unknown user yields ok == false with a nil error; err is reserved for
	// protocol or infrastructure failures.
	Authenticate(authenticate []byte) (username string, ok bool, err error)
	// Close releases any resources held by the handshake. It is safe to
	// call more than once.
	Close()
}
