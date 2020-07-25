package protocol

import (
	"context"
	"github.com/bolkedebruin/rdpgw/transport"
	"github.com/gorilla/websocket"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"log"
	"net/http"
	"time"
)

const (
	rdgConnectionIdKey = "Rdg-Connection-Id"
	MethodRDGIN        = "RDG_IN_DATA"
	MethodRDGOUT       = "RDG_OUT_DATA"
)

var (
	connectionCache = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "rdpgw",
			Name:      "connection_cache",
			Help:      "The amount of connections in the cache",
		})

	websocketConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "rdpgw",
			Name:      "websocket_connections",
			Help:      "The count of websocket connections",
		})

	legacyConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "rdpgw",
			Name:      "legacy_connections",
			Help:      "The count of legacy https connections",
		})
)

type Gateway struct {
	HandlerConf *HandlerConf
}

type SessionInfo struct {
	ConnId           string
	CorrelationId    string
	ClientGeneration string
	TransportIn      transport.Transport
	TransportOut     transport.Transport
	RemoteAddress	 string
	ProxyAddresses	 string
	UserName		 string
}

var upgrader = websocket.Upgrader{}
var c = cache.New(5*time.Minute, 10*time.Minute)

func init() {
	prometheus.MustRegister(connectionCache)
	prometheus.MustRegister(legacyConnections)
	prometheus.MustRegister(websocketConnections)
}

func (g *Gateway) HandleGatewayProtocol(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connectionCache.Set(float64(c.ItemCount()))

	var s *SessionInfo

	connId := r.Header.Get(rdgConnectionIdKey)
	x, found := c.Get(connId)
	if !found {
		s = &SessionInfo{ConnId: connId}
	} else {
		s = x.(*SessionInfo)
	}

	if r.Method == MethodRDGOUT {
		if r.Header.Get("Connection") != "upgrade" && r.Header.Get("Upgrade") != "websocket" {
			g.handleLegacyProtocol(w, r.WithContext(ctx), s)
			return
		}
		r.Method = "GET" // force
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Cannot upgrade falling back to old protocol: %s", err)
			return
		}
		defer conn.Close()

		g.handleWebsocketProtocol(ctx, conn, s)
	} else if r.Method == MethodRDGIN {
		g.handleLegacyProtocol(w, r.WithContext(ctx), s)
	}
}

func (g *Gateway) handleWebsocketProtocol(ctx context.Context, c *websocket.Conn, s *SessionInfo) {
	websocketConnections.Inc()
	defer websocketConnections.Dec()

	inout, _ := transport.NewWS(c)
	s.TransportOut = inout
	s.TransportIn = inout
	handler := NewHandler(s, g.HandlerConf)
	handler.Process(ctx)
}

// The legacy protocol (no websockets) uses an RDG_IN_DATA for client -> server
// and RDG_OUT_DATA for server -> client data. The handshake procedure is a bit different
// to ensure the connections do not get cached or terminated by a proxy prematurely.
func (g *Gateway) handleLegacyProtocol(w http.ResponseWriter, r *http.Request, s *SessionInfo) {
	log.Printf("Session %s, %t, %t", s.ConnId, s.TransportOut != nil, s.TransportIn != nil)

	if r.Method == MethodRDGOUT {
		out, err := transport.NewLegacy(w)
		if err != nil {
			log.Printf("cannot hijack connection to support RDG OUT data channel: %s", err)
			return
		}
		log.Printf("Opening RDGOUT for client %s", out.Conn.RemoteAddr().String())

		s.TransportOut = out
		out.SendAccept(true)

		c.Set(s.ConnId, s, cache.DefaultExpiration)
	} else if r.Method == MethodRDGIN {
		legacyConnections.Inc()
		defer legacyConnections.Dec()

		in, err := transport.NewLegacy(w)
		if err != nil {
			log.Printf("cannot hijack connection to support RDG IN data channel: %s", err)
			return
		}
		defer in.Close()

		if s.TransportIn == nil {
			s.TransportIn = in
			c.Set(s.ConnId, s, cache.DefaultExpiration)

			log.Printf("Opening RDGIN for client %s", in.Conn.RemoteAddr().String())
			in.SendAccept(false)

			// read some initial data
			in.Drain()

			log.Printf("Legacy handshake done for client %s", in.Conn.RemoteAddr().String())
			handler := NewHandler(s, g.HandlerConf)
			handler.Process(r.Context())
		}
	}
}
