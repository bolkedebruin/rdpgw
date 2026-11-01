package ntlm

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/shared/auth"
	"github.com/m7913d/go-ntlm/ntlm"
)

// fakeNtlmAuth mimics the squid-2.5-ntlmssp helper protocol of Samba's
// ntlm_auth closely enough to exercise the winbind backend without a
// domain. It answers YR with a fixed challenge, and KK with AF when the
// (UTF-16LE) user name "my_username" appears in the AUTHENTICATE message,
// NA otherwise. A KK payload that decodes to "hang" makes it stall so
// timeouts can be tested.
const fakeNtlmAuth = `#!/bin/sh
echo "$@" > "$FAKE_ARGS_FILE"
while read -r code payload; do
  decoded=$(printf '%s' "$payload" | base64 -d 2>/dev/null | tr -d '\000')
  case "$code" in
    YR) echo "TT $FAKE_CHALLENGE" ;;
    KK)
      case "$decoded" in
        hang) sleep 30 ;;
        *my_username*) echo "AF EXAMPLE\\my_username" ;;
        *) echo "NA NT_STATUS_WRONG_PASSWORD" ;;
      esac ;;
    *) echo "BH unknown command" ;;
  esac
done
`

func newFakeWinbind(t *testing.T) (*WinbindBackend, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake ntlm_auth is a shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ntlm_auth")
	if err := os.WriteFile(path, []byte(fakeNtlmAuth), 0o755); err != nil {
		t.Fatal(err)
	}
	argsFile := filepath.Join(dir, "args")
	t.Setenv("FAKE_ARGS_FILE", argsFile)

	// Produce a genuine CHALLENGE message so the go-ntlm client can
	// complete the handshake against the fake helper.
	server, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
	if err != nil {
		t.Fatal(err)
	}
	cm, err := server.GenerateChallengeMessage()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_CHALLENGE", base64.StdEncoding.EncodeToString(cm.Bytes()))

	return &WinbindBackend{
		NtlmAuthPath:        path,
		Domain:              "EXAMPLE",
		RequireMembershipOf: `EXAMPLE\RDP Users`,
		Timeout:             2 * time.Second,
		Separator:           `\`,
	}, argsFile
}

func runHandshake(t *testing.T, server *NTLMAuth, username, password string) *auth.NtlmResponse {
	t.Helper()
	client := ntlm.V2ClientSession{}
	client.SetUserInfo(username, password, "EXAMPLE")

	negotiate, err := client.GenerateNegotiateMessage()
	if err != nil {
		t.Fatal(err)
	}
	res, err := server.Authenticate(&auth.NtlmRequest{Session: "S", NtlmMessage: base64.StdEncoding.EncodeToString(negotiate.Bytes())})
	if err != nil {
		t.Fatalf("negotiate failed: %s", err)
	}
	if res.Authenticated || res.NtlmMessage == "" {
		t.Fatalf("negotiate should yield a challenge only")
	}
	raw, err := base64.StdEncoding.DecodeString(res.NtlmMessage)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := ntlm.ParseChallengeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	client.ProcessChallengeMessage(challenge)
	am, err := client.GenerateAuthenticateMessage()
	if err != nil {
		t.Fatal(err)
	}
	res, err = server.Authenticate(&auth.NtlmRequest{Session: "S", NtlmMessage: base64.StdEncoding.EncodeToString(am.Bytes())})
	if err != nil {
		t.Fatalf("authenticate failed: %s", err)
	}
	return res
}

func TestWinbindValidCredentials(t *testing.T) {
	b, argsFile := newFakeWinbind(t)
	server := NewNTLMAuthWithBackend(b)

	res := runHandshake(t, server, "my_username", "irrelevant")
	if !res.Authenticated {
		t.Fatalf("expected authentication to succeed")
	}
	if res.Username != `EXAMPLE\my_username` {
		t.Errorf("unexpected username %q", res.Username)
	}

	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "--helper-protocol=squid-2.5-ntlmssp --domain=EXAMPLE --require-membership-of=EXAMPLE\\RDP Users\n"
	if string(args) != want {
		t.Errorf("ntlm_auth invoked with %q, want %q", args, want)
	}
}

func TestWinbindStripDomain(t *testing.T) {
	b, _ := newFakeWinbind(t)
	b.StripDomain = true
	server := NewNTLMAuthWithBackend(b)

	res := runHandshake(t, server, "my_username", "irrelevant")
	if !res.Authenticated || res.Username != "my_username" {
		t.Errorf("expected bare username, got authenticated=%v username=%q", res.Authenticated, res.Username)
	}
}

func TestWinbindRejected(t *testing.T) {
	b, _ := newFakeWinbind(t)
	server := NewNTLMAuthWithBackend(b)

	res := runHandshake(t, server, "someone_else", "irrelevant")
	if res.Authenticated || res.Username != "" {
		t.Errorf("expected rejection, got authenticated=%v username=%q", res.Authenticated, res.Username)
	}
}

func TestWinbindAuthenticateWithoutNegotiate(t *testing.T) {
	b, _ := newFakeWinbind(t)
	server := NewNTLMAuthWithBackend(b)

	// A syntactically valid AUTHENTICATE header (type 3) without a prior negotiate.
	msg := append([]byte("NTLMSSP\x00"), 3, 0, 0, 0)
	_, err := server.Authenticate(&auth.NtlmRequest{Session: "S", NtlmMessage: base64.StdEncoding.EncodeToString(msg)})
	if err == nil {
		t.Errorf("expected an error when authenticate precedes negotiate")
	}
}

func TestWinbindTimeout(t *testing.T) {
	b, _ := newFakeWinbind(t)
	b.Timeout = 300 * time.Millisecond
	c := b.NewContext().(*winbindContext)
	defer c.Close()

	if _, err := c.Negotiate([]byte("NTLMSSP\x00\x01\x00\x00\x00")); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, ok, err := c.Authenticate([]byte("hang"))
	if err == nil || ok {
		t.Fatalf("expected a timeout error, got ok=%v err=%v", ok, err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Authenticate() took %s; timeout was not applied", elapsed)
	}

	start = time.Now()
	c.Close()
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Close() took %s; hung helper was not killed", elapsed)
	}
}

func TestWinbindBrokenHelper(t *testing.T) {
	b, _ := newFakeWinbind(t)
	c := b.NewContext().(*winbindContext)
	defer c.Close()

	if _, err := c.Negotiate([]byte("NTLMSSP\x00\x01\x00\x00\x00")); err != nil {
		t.Fatal(err)
	}
	// An unknown request code makes the fake helper reply "BH".
	resp, _, err := c.exchange("XX", nil)
	if err != nil || resp != "BH" {
		t.Fatalf("expected BH from helper, got %q err=%v", resp, err)
	}
}

func TestWinbindMissingBinary(t *testing.T) {
	b := &WinbindBackend{NtlmAuthPath: "/nonexistent/ntlm_auth", Timeout: time.Second}
	c := b.NewContext()
	defer c.Close()
	if _, err := c.Negotiate([]byte("NTLMSSP\x00\x01\x00\x00\x00")); err == nil {
		t.Errorf("expected an error when ntlm_auth cannot be started")
	}
}

func TestWinbindCloseIdempotent(t *testing.T) {
	b, _ := newFakeWinbind(t)
	c := b.NewContext()
	if _, err := c.Negotiate([]byte("NTLMSSP\x00\x01\x00\x00\x00")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.Close()
	if _, _, err := c.Authenticate([]byte("x")); err == nil {
		t.Errorf("Authenticate after Close should fail")
	}
}

func TestNormalizeUsername(t *testing.T) {
	cases := []struct {
		strip bool
		sep   string
		in    string
		want  string
	}{
		{false, `\`, `EXAMPLE\alice`, `EXAMPLE\alice`},
		{true, `\`, `EXAMPLE\alice`, "alice"},
		{true, "", `EXAMPLE\alice`, "alice"},
		{true, "+", "EXAMPLE+alice", "alice"},
		{true, `\`, "alice", "alice"},
	}
	for _, tc := range cases {
		b := &WinbindBackend{StripDomain: tc.strip, Separator: tc.sep}
		if got := b.normalizeUsername(tc.in); got != tc.want {
			t.Errorf("normalizeUsername(%q, strip=%v, sep=%q) = %q, want %q", tc.in, tc.strip, tc.sep, got, tc.want)
		}
	}
}

func TestWinbindNegotiateRestartsHandshake(t *testing.T) {
	b, _ := newFakeWinbind(t)
	server := NewNTLMAuthWithBackend(b)

	// Two negotiates in a row for the same session must not leak the first
	// helper and must still allow a full handshake afterwards.
	client := ntlm.V2ClientSession{}
	client.SetUserInfo("my_username", "x", "EXAMPLE")
	nm, _ := client.GenerateNegotiateMessage()
	req := &auth.NtlmRequest{Session: "S", NtlmMessage: base64.StdEncoding.EncodeToString(nm.Bytes())}
	if _, err := server.Authenticate(req); err != nil {
		t.Fatal(err)
	}
	first, _ := server.getContext("S")
	if _, err := server.Authenticate(req); err != nil {
		t.Fatal(err)
	}
	if !first.(*winbindContext).closed {
		t.Errorf("first context should have been closed when the handshake restarted")
	}
	res := runHandshake(t, server, "my_username", "x")
	if !res.Authenticated {
		t.Errorf("handshake after restart should succeed")
	}
}
