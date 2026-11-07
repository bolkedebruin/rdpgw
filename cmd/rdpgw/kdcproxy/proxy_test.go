package kdcproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	krbconfig "github.com/bolkedebruin/gokrb5/v8/config"
	"github.com/jcmturner/gofork/encoding/asn1"
)

// frame adds the 4-byte big-endian length that MS-KKDCP and Kerberos over TCP use.
func frame(msg []byte) []byte {
	out := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(out, uint32(len(msg)))
	copy(out[4:], msg)
	return out
}

// tcpKdc answers one framed request with reply and, like a real KDC, keeps the
// connection open afterwards. It records what it received.
func tcpKdc(t *testing.T, reply []byte, got chan<- []byte) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				var prefix [4]byte
				if _, err := io.ReadFull(c, prefix[:]); err != nil {
					c.Close()
					return
				}
				msg := make([]byte, binary.BigEndian.Uint32(prefix[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					c.Close()
					return
				}
				got <- msg
				c.Write(frame(reply))
				// hold the connection open until the client closes it
				io.Copy(io.Discard, c)
				c.Close()
			}(c)
		}
	}()
	return l.Addr().String()
}

// udpKdc answers one unframed datagram with reply.
func udpKdc(t *testing.T, reply []byte, got chan<- []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			got <- append([]byte(nil), buf[:n]...)
			pc.WriteTo(reply, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func proxyFor(t *testing.T, kdcs ...string) KerberosProxy {
	t.Helper()
	conf := "[libdefaults]\n default_realm = EXAMPLE.TEST\n dns_lookup_kdc = false\n" +
		"[realms]\n EXAMPLE.TEST = {\n"
	for _, k := range kdcs {
		conf += fmt.Sprintf("  kdc = %s\n", k)
	}
	conf += " }\n"
	cfg, err := krbconfig.NewFromString(conf)
	if err != nil {
		t.Fatal(err)
	}
	return KerberosProxy{krb5Config: cfg}
}

func post(t *testing.T, k KerberosProxy, realm string, msg []byte) []byte {
	t.Helper()
	req, err := asn1.Marshal(KdcProxyMsg{Message: frame(msg), Realm: realm})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/KdcProxy", bytes.NewReader(req))
	k.Handler(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	resp, err := decode(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return resp.Message
}

// A realm with one KDC gets it over both UDP and TCP from gokrb5, numbered from 1. The
// proxy used to index a slice with those numbers and panic.
func TestForwardOneKdcOverTCP(t *testing.T) {
	got := make(chan []byte, 4)
	addr := tcpKdc(t, []byte("as-rep"), got)
	k := proxyFor(t, addr)

	resp := post(t, k, "EXAMPLE.TEST", []byte("as-req"))
	if !bytes.Equal(resp, frame([]byte("as-rep"))) {
		t.Fatalf("reply %q", resp)
	}
	if m := <-got; string(m) != "as-req" {
		t.Fatalf("kdc received %q", m)
	}
}

// The KDC keeps TCP open after its reply, so the proxy must not wait for EOF.
func TestForwardDoesNotWaitForClose(t *testing.T) {
	got := make(chan []byte, 4)
	k := proxyFor(t, tcpKdc(t, []byte("reply"), got))
	done := make(chan []byte)
	go func() { done <- post(t, k, "", []byte("request")) }()
	select {
	case resp := <-done:
		if !bytes.Equal(resp, frame([]byte("reply"))) {
			t.Fatalf("reply %q", resp)
		}
	case <-time.After(timeout / 2):
		t.Fatal("proxy waited for the KDC to close the connection")
	}
}

// UDP carries the bare message, and the reply gets a full 4-byte length prefix back.
func TestForwardOverUDP(t *testing.T) {
	long := bytes.Repeat([]byte("x"), 300) // longer than a 1-byte length can hold
	got := make(chan []byte, 4)
	k := proxyFor(t, udpKdc(t, long, got))
	// gokrb5 lists the same address for tcp; nothing listens there, so udp answers.
	resp := post(t, k, "EXAMPLE.TEST", []byte("tgs-req"))
	if !bytes.Equal(resp, frame(long)) {
		t.Fatalf("reply has %d bytes, prefix %x", len(resp), resp[:4])
	}
	if m := <-got; string(m) != "tgs-req" {
		t.Fatalf("kdc received %q", m)
	}
}

// A dead KDC is skipped.
func TestForwardSkipsDeadKdc(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()
	got := make(chan []byte, 4)
	k := proxyFor(t, deadAddr, tcpKdc(t, []byte("ok"), got))
	if resp := post(t, k, "EXAMPLE.TEST", []byte("req")); !bytes.Equal(resp, frame([]byte("ok"))) {
		t.Fatalf("reply %q", resp)
	}
}

func TestForwardRejectsBadLength(t *testing.T) {
	k := proxyFor(t, "127.0.0.1:1")
	if _, err := k.forward("EXAMPLE.TEST", []byte{0, 0, 0, 9, 1}); err == nil {
		t.Fatal("accepted a message whose length prefix is wrong")
	}
}

// The realm comes from an unauthenticated client. Only the default realm and
// the realms in krb5.conf are served; for any other realm the proxy must not
// look up KDCs, even with dns_lookup_kdc enabled.
func TestForwardOnlyServesConfiguredRealms(t *testing.T) {
	got := make(chan []byte, 4)
	addr := tcpKdc(t, []byte("rep"), got)
	cfg, err := krbconfig.NewFromString(fmt.Sprintf("[libdefaults]\n default_realm = EXAMPLE.TEST\n dns_lookup_kdc = true\n"+
		"[realms]\n EXAMPLE.TEST = {\n  kdc = %s\n }\n CHILD.EXAMPLE.TEST = {\n  kdc = %s\n }\n", addr, addr))
	if err != nil {
		t.Fatal(err)
	}
	k := KerberosProxy{krb5Config: cfg}

	for _, realm := range []string{"", "EXAMPLE.TEST", "CHILD.EXAMPLE.TEST"} {
		if resp := post(t, k, realm, []byte("req")); !bytes.Equal(resp, frame([]byte("rep"))) {
			t.Errorf("realm %q: reply %q", realm, resp)
		}
	}

	for _, realm := range []string{"ATTACKER.TEST", "example.test", "EXAMPLE.TEST.ATTACKER.TEST"} {
		if _, err := k.forward(realm, frame([]byte("req"))); !errors.Is(err, errRealmNotServed) {
			t.Errorf("realm %q: err = %v, want errRealmNotServed", realm, err)
		}
		req, _ := asn1.Marshal(KdcProxyMsg{Message: frame([]byte("req")), Realm: realm})
		w := httptest.NewRecorder()
		k.Handler(w, httptest.NewRequest(http.MethodPost, "/KdcProxy", bytes.NewReader(req)))
		if w.Code != http.StatusForbidden {
			t.Errorf("realm %q: status %d, want %d", realm, w.Code, http.StatusForbidden)
		}
	}
}
