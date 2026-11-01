package ntlm

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// WinbindBackend delegates the NTLM handshake to Samba's ntlm_auth helper
// running in --helper-protocol=squid-2.5-ntlmssp mode. ntlm_auth talks to
// winbindd, which performs pass-through authentication against a domain
// controller. The gateway therefore never needs to know any password or
// NT hash; the host only has to be joined to the Active Directory domain.
//
// One ntlm_auth process is spawned per handshake and terminated as soon
// as the handshake finishes, fails or is evicted from the session cache.
type WinbindBackend struct {
	// NtlmAuthPath is the ntlm_auth binary, e.g. /usr/bin/ntlm_auth.
	NtlmAuthPath string
	// Domain is passed as --domain when non-empty.
	Domain string
	// RequireMembershipOf is passed as --require-membership-of when
	// non-empty (SID or DOMAIN\Group).
	RequireMembershipOf string
	// Timeout bounds every single request/response exchange with ntlm_auth.
	Timeout time.Duration
	// StripDomain removes the DOMAIN+Separator prefix from the user name
	// reported by winbind.
	StripDomain bool
	// Separator is winbind's "winbind separator" (default "\").
	Separator string
}

func (b *WinbindBackend) NewContext() Context {
	return &winbindContext{b: b}
}

func (b *WinbindBackend) args() []string {
	args := []string{"--helper-protocol=squid-2.5-ntlmssp"}
	if b.Domain != "" {
		args = append(args, "--domain="+b.Domain)
	}
	if b.RequireMembershipOf != "" {
		args = append(args, "--require-membership-of="+b.RequireMembershipOf)
	}
	return args
}

type winbindContext struct {
	b *WinbindBackend

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan helperLine
	done   chan struct{}
	closed bool
}

type helperLine struct {
	line string
	err  error
}

func (c *winbindContext) start() error {
	cmd := exec.Command(c.b.NtlmAuthPath, c.b.args()...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("winbind: cannot open stdin of ntlm_auth: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("winbind: cannot open stdout of ntlm_auth: %w", err)
	}
	cmd.Stderr = &logWriter{prefix: "ntlm_auth: "}
	// Bound cmd.Wait() even if a grandchild of ntlm_auth keeps the pipes
	// open after the helper itself was killed.
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("winbind: cannot start %s: %w", c.b.NtlmAuthPath, err)
	}

	c.cmd = cmd
	c.stdin = stdin
	c.lines = make(chan helperLine)
	c.done = make(chan struct{})

	// A dedicated reader goroutine lets exchange() apply a timeout. It
	// exits when the helper's output reaches EOF or when Close() signals
	// done, so it never blocks forever on an unread line.
	go func(r *bufio.Reader, lines chan<- helperLine, done <-chan struct{}) {
		for {
			line, err := r.ReadString('\n')
			l := helperLine{line: strings.TrimRight(line, "\r\n"), err: err}
			select {
			case lines <- l:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}(bufio.NewReader(stdout), c.lines, c.done)
	return nil
}

// exchange writes one helper request ("YR <b64>" / "KK <b64>") and returns
// the response code and payload, e.g. ("TT", "<b64>") or ("AF", "DOMAIN\\user").
func (c *winbindContext) exchange(code string, payload []byte) (string, string, error) {
	req := code + " " + base64.StdEncoding.EncodeToString(payload) + "\n"
	if _, err := io.WriteString(c.stdin, req); err != nil {
		return "", "", fmt.Errorf("winbind: failed to write to ntlm_auth: %w", err)
	}

	timer := time.NewTimer(c.b.Timeout)
	defer timer.Stop()

	select {
	case l := <-c.lines:
		if l.err != nil {
			return "", "", fmt.Errorf("winbind: ntlm_auth closed its output: %w", l.err)
		}
		resp, rest, _ := strings.Cut(l.line, " ")
		return resp, rest, nil
	case <-timer.C:
		return "", "", fmt.Errorf("winbind: ntlm_auth did not answer within %s", c.b.Timeout)
	}
}

func (c *winbindContext) Negotiate(negotiate []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cmd != nil || c.closed {
		return nil, errors.New("winbind: handshake already started")
	}
	if err := c.start(); err != nil {
		return nil, err
	}

	resp, rest, err := c.exchange("YR", negotiate)
	if err != nil {
		return nil, err
	}
	switch resp {
	case "TT":
		challenge, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return nil, fmt.Errorf("winbind: invalid challenge from ntlm_auth: %w", err)
		}
		return challenge, nil
	case "BH":
		return nil, fmt.Errorf("winbind: ntlm_auth reported a broken helper state: %s", rest)
	default:
		return nil, fmt.Errorf("winbind: unexpected reply to negotiate from ntlm_auth: %s %s", resp, rest)
	}
}

func (c *winbindContext) Authenticate(authenticate []byte) (string, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cmd == nil || c.closed {
		return "", false, errors.New("winbind: NTLM Authenticate requires active session: first call negotiate")
	}

	resp, rest, err := c.exchange("KK", authenticate)
	if err != nil {
		return "", false, err
	}
	switch resp {
	case "AF":
		return c.b.normalizeUsername(rest), true, nil
	case "NA":
		// Wrong password, unknown user, disabled account, not a member of
		// the required group, ... winbind gives the NT_STATUS as reason.
		log.Printf("winbind: authentication rejected: %s", rest)
		return "", false, nil
	case "BH":
		return "", false, fmt.Errorf("winbind: ntlm_auth reported a broken helper state: %s", rest)
	default:
		return "", false, fmt.Errorf("winbind: unexpected reply to authenticate from ntlm_auth: %s %s", resp, rest)
	}
}

func (b *WinbindBackend) normalizeUsername(name string) string {
	if !b.StripDomain {
		return name
	}
	sep := b.Separator
	if sep == "" {
		sep = `\`
	}
	if _, user, found := strings.Cut(name, sep); found {
		return user
	}
	return name
}

func (c *winbindContext) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true
	if c.cmd == nil {
		return
	}
	close(c.done)
	// Closing stdin makes a healthy ntlm_auth exit on its own; the kill is
	// the safety net for a hung helper.
	_ = c.stdin.Close()
	done := make(chan struct{})
	go func() {
		_ = c.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = c.cmd.Process.Kill()
		<-done
	}
}

// logWriter forwards ntlm_auth's stderr to the standard logger.
type logWriter struct {
	prefix string
}

func (w *logWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line != "" {
			log.Printf("%s%s", w.prefix, line)
		}
	}
	return len(p), nil
}
