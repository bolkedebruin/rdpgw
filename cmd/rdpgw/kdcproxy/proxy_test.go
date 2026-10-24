package kdcproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	krbconfig "github.com/bolkedebruin/gokrb5/v8/config"
)

func frameKerberosMessage(payload []byte) []byte {
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(payload)))
	copy(framed[4:], payload)
	return framed
}

func newTestKerberosProxy(t *testing.T, kdcAddr string) KerberosProxy {
	t.Helper()
	krb5Conf := fmt.Sprintf(`[libdefaults]
    default_realm = TEST.REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    TEST.REALM = {
        kdc = %s
    }
`, kdcAddr)
	cfg, err := krbconfig.NewFromString(krb5Conf)
	if err != nil {
		t.Fatalf("failed to parse krb5 config: %v", err)
	}
	return KerberosProxy{krb5Config: cfg}
}

// TestAwaitReplyUDP verifies that UDP KDC replies are read from a single
// datagram without blocking for EOF, and that a 4-byte big-endian length
// prefix is prepended (even for payloads > 255 bytes).
func TestAwaitReplyUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer pc.Close()

	// Create a payload larger than 255 bytes to verify 4-byte uint32 length framing
	expectedPayload := bytes.Repeat([]byte{0xAB, 0xCD}, 200) // 400 bytes

	go func() {
		buf := make([]byte, 1024)
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(expectedPayload, addr)
	}()

	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial udp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("failed to write to udp: %v", err)
	}

	replies := make(chan []byte, 1)
	awaitReply(conn, true, replies)

	got := <-replies
	if got == nil {
		t.Fatalf("expected non-nil reply from UDP KDC")
	}
	if len(got) != 4+len(expectedPayload) {
		t.Fatalf("reply length = %d, want %d", len(got), 4+len(expectedPayload))
	}
	gotLen := binary.BigEndian.Uint32(got[:4])
	if int(gotLen) != len(expectedPayload) {
		t.Fatalf("4-byte length prefix = %d, want %d", gotLen, len(expectedPayload))
	}
	if !bytes.Equal(got[4:], expectedPayload) {
		t.Fatalf("reply payload mismatch")
	}
}

// TestAwaitReplyTCPPersistentConn verifies that TCP KDC replies are read
// using the 4-byte length prefix without waiting for the KDC to close the
// TCP connection.
func TestAwaitReplyTCPPersistentConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen tcp: %v", err)
	}
	defer ln.Close()

	expectedPayload := bytes.Repeat([]byte{0x42}, 300)
	framedReply := frameKerberosMessage(expectedPayload)
	done := make(chan struct{})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(framedReply)
		// Keep the connection open like a real KDC until the test finishes
		<-done
	}()
	defer close(done)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial tcp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	replies := make(chan []byte, 1)
	start := time.Now()
	awaitReply(conn, false, replies)
	elapsed := time.Since(start)

	if elapsed >= 1500*time.Millisecond {
		t.Fatalf("awaitReply took %v; it should return immediately after reading the framed message without waiting for EOF", elapsed)
	}

	got := <-replies
	if !bytes.Equal(got, framedReply) {
		t.Fatalf("got %x, want %x", got, framedReply)
	}
}

// TestHandlerEndToEndUDP tests the full HTTP POST /KdcProxy handler against a
// mock UDP KDC.
func TestHandlerEndToEndUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer pc.Close()

	reqKrbPayload := []byte("kerberos-as-req-payload")
	respKrbPayload := bytes.Repeat([]byte("kerberos-as-rep-"), 25) // 400 bytes

	receivedCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		receivedCh <- append([]byte(nil), buf[:n]...)
		_, _ = pc.WriteTo(respKrbPayload, addr)
	}()

	proxy := newTestKerberosProxy(t, pc.LocalAddr().String())

	// Encode MS-KKDCP request (payload has 4-byte length prefix)
	framedReq := frameKerberosMessage(reqKrbPayload)
	encodedReq, err := encode(framedReq)
	if err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	httpReq := httptest.NewRequest(http.MethodPost, "/KdcProxy", bytes.NewReader(encodedReq))
	rr := httptest.NewRecorder()

	proxy.Handler(rr, httpReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("Handler status = %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/kerberos" {
		t.Fatalf("Content-Type = %q, want application/kerberos", ct)
	}

	// Verify the UDP KDC received the payload stripped of the 4-byte length prefix
	select {
	case gotReq := <-receivedCh:
		if !bytes.Equal(gotReq, reqKrbPayload) {
			t.Fatalf("UDP KDC received %q, want %q", gotReq, reqKrbPayload)
		}
	case <-time.After(time.Second):
		t.Fatalf("UDP KDC did not receive request")
	}

	// Decode MS-KKDCP reply and verify 4-byte length prefix + payload
	decodedReply, err := decode(rr.Body.Bytes())
	if err != nil {
		t.Fatalf("failed to decode KdcProxyMsg reply: %v", err)
	}
	wantFramedResp := frameKerberosMessage(respKrbPayload)
	if !bytes.Equal(decodedReply.Message, wantFramedResp) {
		t.Fatalf("decoded reply message mismatch: got len %d, want len %d", len(decodedReply.Message), len(wantFramedResp))
	}
}

// TestForwardFallbackToTCPWhenUDPFails verifies that if the UDP KDC fails or
// is unreachable and the TCP KDC succeeds, forward() still returns the valid
// TCP reply instead of returning nil or deadlocking.
func TestForwardFallbackToTCPWhenUDPFails(t *testing.T) {
	// Start only a TCP listener (no UDP listener on this address:port)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen tcp: %v", err)
	}
	defer ln.Close()

	reqPayload := []byte("krb5-tcp-req")
	respPayload := []byte("krb5-tcp-rep-success")
	framedResp := frameKerberosMessage(respPayload)
	done := make(chan struct{})
	defer close(done)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write(framedResp)
		<-done
	}()

	proxy := newTestKerberosProxy(t, ln.Addr().String())
	got, err := proxy.forward("TEST.REALM", frameKerberosMessage(reqPayload))
	if err != nil {
		t.Fatalf("forward failed: %v", err)
	}
	if !bytes.Equal(got, framedResp) {
		t.Fatalf("forward reply = %x, want %x", got, framedResp)
	}
}

// TestEnsureDefaultPort verifies that KDC host entries without an explicit
// port get ":88" appended.
func TestEnsureDefaultPort(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"dc1.corp.example.com", "dc1.corp.example.com:88"},
		{"dc1.corp.example.com:88", "dc1.corp.example.com:88"},
		{"192.168.0.11", "192.168.0.11:88"},
		{"192.168.0.11:88", "192.168.0.11:88"},
		{"[2001:db8::1]:88", "[2001:db8::1]:88"},
		{"2001:db8::1", "[2001:db8::1]:88"},
	}
	for _, tc := range tests {
		if got := ensureDefaultPort(tc.in); got != tc.want {
			t.Errorf("ensureDefaultPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
