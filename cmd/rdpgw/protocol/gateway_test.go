package protocol

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

func TestHeaderHasToken(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		token  string
		want   bool
	}{
		{"exact match", []string{"upgrade"}, "upgrade", true},
		{"case insensitive value", []string{"Upgrade"}, "upgrade", true},
		{"case insensitive token", []string{"upgrade"}, "UPGRADE", true},
		{"token inside comma list", []string{"keep-alive, Upgrade"}, "upgrade", true},
		{"token with surrounding whitespace", []string{" keep-alive ,\tupgrade\t"}, "upgrade", true},
		{"not present", []string{"keep-alive"}, "upgrade", false},
		{"empty header", nil, "upgrade", false},
		{"substring must not match", []string{"upgrader"}, "upgrade", false},
		{"multiple header values", []string{"keep-alive", "Upgrade"}, "upgrade", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tc.values {
				h.Add("X-Test", v)
			}
			if got := headerHasToken(h, "X-Test", tc.token); got != tc.want {
				t.Errorf("headerHasToken(%v, %q) = %v, want %v", tc.values, tc.token, got, tc.want)
			}
		})
	}
}

// newGatewayTestServer starts an httptest server that injects a minimal
// identity into the request context so HandleGatewayProtocol's downstream
// code can run without panicking.
func newGatewayTestServer(t *testing.T, gw *Gateway) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.NewUser()
		id.SetAttribute(identity.AttrRemoteAddr, "127.0.0.1:0")
		id.SetAttribute(identity.AttrClientIp, "127.0.0.1")
		r = identity.AddToRequestCtx(id, r)
		gw.HandleGatewayProtocol(w, r)
	})
	return httptest.NewServer(handler)
}

// TestHandleGatewayProtocolRouting drives HandleGatewayProtocol over a real
// TCP connection to verify the Connection/Upgrade header detection picks
// the right sub-handler. Using raw TCP is necessary because the legacy
// branch hijacks the connection and the websocket branch speaks 101
// Switching Protocols, neither of which plays nicely with net/http's
// standard client.
func TestHandleGatewayProtocolRouting(t *testing.T) {
	srv := newGatewayTestServer(t, &Gateway{})
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")

	cases := []struct {
		name           string
		request        string
		wantStatusLine string
	}{
		{
			name: "RDG_OUT_DATA without upgrade headers routes to legacy",
			request: "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n" +
				"Host: " + addr + "\r\n" +
				"Rdg-Connection-Id: test-legacy\r\n" +
				"\r\n",
			wantStatusLine: "HTTP/1.1 200 OK",
		},
		{
			name: "RDG_OUT_DATA with upgrade headers routes to websocket",
			request: "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n" +
				"Host: " + addr + "\r\n" +
				"Rdg-Connection-Id: test-ws\r\n" +
				"Connection: Upgrade\r\n" +
				"Upgrade: websocket\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"\r\n",
			wantStatusLine: "HTTP/1.1 101 Switching Protocols",
		},
		{
			name: "RDG_OUT_DATA with Connection token list still routes to websocket",
			request: "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n" +
				"Host: " + addr + "\r\n" +
				"Rdg-Connection-Id: test-ws-list\r\n" +
				"Connection: keep-alive, Upgrade\r\n" +
				"Upgrade: websocket\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"\r\n",
			wantStatusLine: "HTTP/1.1 101 Switching Protocols",
		},
		{
			name: "RDG_OUT_DATA with partially matching headers routes to legacy",
			request: "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n" +
				"Host: " + addr + "\r\n" +
				"Rdg-Connection-Id: test-partial\r\n" +
				"Connection: Upgrade\r\n" +
				"\r\n",
			wantStatusLine: "HTTP/1.1 200 OK",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			if _, err := conn.Write([]byte(tc.request)); err != nil {
				t.Fatalf("write: %v", err)
			}

			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Fatalf("read status line: %v", err)
			}
			line = strings.TrimRight(line, "\r\n")
			if line != tc.wantStatusLine {
				t.Errorf("status line = %q, want %q", line, tc.wantStatusLine)
			}
		})
	}
}
