package protocol

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/transport"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/patrickmn/go-cache"
)

const (
	rdgConnectionIdKey = "Rdg-Connection-Id"
	MethodRDGIN        = "RDG_IN_DATA"
	MethodRDGOUT       = "RDG_OUT_DATA"
)

type CheckPAACookieFunc func(context.Context, string) (bool, error)
type CheckClientNameFunc func(context.Context, string) (bool, error)
type CheckHostFunc func(context.Context, string) (bool, error)

type Gateway struct {
	// CheckPAACookie verifies if the PAA cookie sent by the client is valid
	CheckPAACookie CheckPAACookieFunc

	// CheckClientName verifies if the client name is allowed to connect
	CheckClientName CheckClientNameFunc

	// CheckHost verifies if the client is allowed to connect to the remote host
	CheckHost CheckHostFunc

	// RedirectFlags sets what devices the client is allowed to redirect to the remote host
	RedirectFlags RedirectFlags

	// IdleTimeOut is used to determine when to disconnect clients that have been idle
	IdleTimeout int

	// SmartCardAuth sets whether to use smart card based authentication
	SmartCardAuth bool

	// TokenAuth sets whether to use token/cookie based authentication
	TokenAuth bool

	ReceiveBuf int
	SendBuf    int
}

var upgrader = websocket.Upgrader{}
var c = cache.New(5*time.Minute, 10*time.Minute)

func (g *Gateway) HandleGatewayProtocol(w http.ResponseWriter, r *http.Request) {
	connectionCache.Set(float64(c.ItemCount()))

	var t *Tunnel

	ctx := r.Context()
	id := identity.FromRequestCtx(r)

	connId := r.Header.Get(rdgConnectionIdKey)
	x, found := c.Get(connId)
	if !found {
		t = &Tunnel{
			RDGId:      connId,
			RemoteAddr: id.GetAttribute(identity.AttrRemoteAddr).(string),
			User:       id,
		}
	} else {
		t = x.(*Tunnel)
		if !tunnelOwnerMatches(t, id) {
			log.Printf("rejecting reuse of Rdg-Connection-Id %q from a different identity", connId)
			http.Error(w, "Tunnel is owned by a different session", http.StatusUnauthorized)
			return
		}
	}
	ctx = context.WithValue(ctx, CtxTunnel, t)

	if r.Method == MethodRDGOUT {
		if headerHasToken(r.Header, "Connection", "upgrade") && headerHasToken(r.Header, "Upgrade", "websocket") {
			r.Method = "GET" // upgrader requires GET
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				// Upgrade has already written an HTTP error response on the
				// wire, so we cannot transparently fall back to the legacy
				// protocol here. The header pre-check above handles the
				// real-world fallback case: clients or reverse proxies that
				// don't send the Upgrade/Connection tokens route to legacy
				// without ever touching the upgrader.
				log.Printf("cannot upgrade connection to websocket: %v", err)
				return
			}
			defer conn.Close()

			if err := g.setSendReceiveBuffers(conn.UnderlyingConn()); err != nil {
				log.Printf("cannot set send/receive buffers: %v", err)
			}
			g.handleWebsocketProtocol(ctx, conn, t)
			return
		}
		g.handleLegacyProtocol(w, r.WithContext(ctx), t)
	} else if r.Method == MethodRDGIN {
		g.handleLegacyProtocol(w, r.WithContext(ctx), t)
	}
}

// tunnelOwnerMatches reports whether the cached tunnel was opened by the same
// identity making the current request. The Rdg-Connection-Id is a client-
// chosen header that pairs the two halves of a session; without this check
// any caller who learns or guesses one can attach to another user's tunnel.
func tunnelOwnerMatches(t *Tunnel, id identity.Identity) bool {
	if t == nil || t.User == nil || id == nil {
		return false
	}
	if t.User.UserName() == "" || t.User.UserName() != id.UserName() {
		return false
	}
	cachedIp, _ := t.User.GetAttribute(identity.AttrClientIp).(string)
	reqIp, _ := id.GetAttribute(identity.AttrClientIp).(string)
	if cachedIp == "" {
		return false
	}
	return cachedIp == reqIp
}

// headerHasToken reports whether the HTTP header named by name contains
// token, matched case-insensitively against comma-separated tokens.
// Fields like Connection carry a list (e.g. "keep-alive, Upgrade") so a
// plain equality check on the raw value misses legitimate clients and
// well-behaved reverse proxies.
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

func (g *Gateway) setSendReceiveBuffers(conn net.Conn) error {
	if g.SendBuf < 1 && g.ReceiveBuf < 1 {
		return nil
	}

	// conn == tls.Tunnel
	ptr := reflect.ValueOf(conn)
	val := reflect.Indirect(ptr)

	if val.Kind() != reflect.Struct {
		return errors.New("didn't get a struct from conn")
	}

	// this gets net.Tunnel -> *net.TCPConn -> net.TCPConn
	ptrConn := val.FieldByName("conn")
	valConn := reflect.Indirect(ptrConn)
	if !valConn.IsValid() {
		return errors.New("cannot find conn field")
	}
	valConn = valConn.Elem().Elem()

	// net.FD
	ptrNetFd := valConn.FieldByName("fd")
	valNetFd := reflect.Indirect(ptrNetFd)
	if !valNetFd.IsValid() {
		return errors.New("cannot find fd field")
	}

	// pfd member
	ptrPfd := valNetFd.FieldByName("pfd")
	valPfd := reflect.Indirect(ptrPfd)
	if !valPfd.IsValid() {
		return errors.New("cannot find pfd field")
	}

	// finally the exported Sysfd
	ptrSysFd := valPfd.FieldByName("Sysfd")
	if !ptrSysFd.IsValid() {
		return errors.New("cannot find Sysfd field")
	}
	fd := int64ToFd(ptrSysFd.Int())

	if g.ReceiveBuf > 0 {
		err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, g.ReceiveBuf)
		if err != nil {
			return wrapSyscallError("setsockopt", err)
		}
	}

	if g.SendBuf > 0 {
		err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, g.SendBuf)
		if err != nil {
			return wrapSyscallError("setsockopt", err)
		}
	}

	return nil
}

func (g *Gateway) handleWebsocketProtocol(ctx context.Context, c *websocket.Conn, t *Tunnel) {
	websocketConnections.Inc()
	defer websocketConnections.Dec()

	inout, _ := transport.NewWS(c)
	defer inout.Close()

	t.Id = uuid.New().String()
	t.transportOut = inout
	t.transportIn = inout
	t.ConnectedOn = time.Now()

	handler := NewProcessor(g, t)
	RegisterTunnel(t, handler)
	defer RemoveTunnel(t)
	handler.Process(ctx)
}

// The legacy protocol (no websockets) uses an RDG_IN_DATA for client -> server
// and RDG_OUT_DATA for server -> client data. The handshakeRequest procedure is a bit different
// to ensure the connections do not get cached or terminated by a proxy prematurely.
func (g *Gateway) handleLegacyProtocol(w http.ResponseWriter, r *http.Request, t *Tunnel) {
	log.Printf("Session %s, %t, %t", t.RDGId, t.transportOut != nil, t.transportIn != nil)

	id := identity.FromRequestCtx(r)
	if r.Method == MethodRDGOUT {
		out, err := transport.NewLegacy(w)
		if err != nil {
			log.Printf("cannot hijack connection to support RDG OUT data channel: %s", err)
			return
		}
		log.Printf("Opening RDGOUT for client %s", id.GetAttribute(identity.AttrClientIp))

		t.transportOut = out
		out.SendAccept(true)

		c.Set(t.RDGId, t, cache.DefaultExpiration)
	} else if r.Method == MethodRDGIN {
		legacyConnections.Inc()
		defer legacyConnections.Dec()

		in, err := transport.NewLegacy(w)
		if err != nil {
			log.Printf("cannot hijack connection to support RDG IN data channel: %s", err)
			return
		}
		defer in.Close()

		if t.transportIn == nil {
			t.Id = uuid.New().String()
			t.transportIn = in
			c.Set(t.RDGId, t, cache.DefaultExpiration)

			log.Printf("Opening RDGIN for client %s", id.GetAttribute(identity.AttrClientIp))
			in.SendAccept(false)

			// read some initial data
			in.Drain()

			log.Printf("Legacy handshakeRequest done for client %s", id.GetAttribute(identity.AttrClientIp))
			handler := NewProcessor(g, t)
			RegisterTunnel(t, handler)
			defer RemoveTunnel(t)
			handler.Process(r.Context())
		}
	}
}
