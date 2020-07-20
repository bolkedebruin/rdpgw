package protocol

import (
	"github.com/bolkedebruin/rdpgw/transport"
	"github.com/gorilla/websocket"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

const (
	rdgConnectionIdKey = "Rdg-Connection-Id"
	MethodRDGIN  = "RDG_IN_DATA"
	MethodRDGOUT = "RDG_OUT_DATA"
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

// HandshakeHeader is the interface that writes both upgrade request or
// response headers into a given io.Writer.
type HandshakeHeader interface {
	io.WriterTo
}

type RdgSession struct {
	ConnId        string
	CorrelationId string
	UserId        string
	TransportIn   transport.Transport
	TransportOut  transport.Transport
	StateIn       int
	StateOut      int
	Remote        net.Conn
}

var DefaultSession RdgSession

var upgrader = websocket.Upgrader{}
var c = cache.New(5*time.Minute, 10*time.Minute)

func init() {
	prometheus.MustRegister(connectionCache)
	prometheus.MustRegister(legacyConnections)
	prometheus.MustRegister(websocketConnections)
}

func HandleGatewayProtocol(w http.ResponseWriter, r *http.Request) {
	connectionCache.Set(float64(c.ItemCount()))
	if r.Method == MethodRDGOUT {
		if r.Header.Get("Connection") != "upgrade" && r.Header.Get("Upgrade") != "websocket" {
			handleLegacyProtocol(w, r)
			return
		}
		r.Method = "GET" // force
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Cannot upgrade falling back to old protocol: %s", err)
			return
		}
		defer conn.Close()

		handleWebsocketProtocol(conn)
	} else if r.Method == MethodRDGIN {
		handleLegacyProtocol(w, r)
	}
}

func handleWebsocketProtocol(c *websocket.Conn) {
	websocketConnections.Inc()
	defer websocketConnections.Dec()

	inout, _ := transport.NewWS(c)
	handler := NewHandler(inout, inout)
	handler.Process()
}

// The legacy protocol (no websockets) uses an RDG_IN_DATA for client -> server
// and RDG_OUT_DATA for server -> client data. The handshake procedure is a bit different
// to ensure the connections do not get cached or terminated by a proxy prematurely.
func handleLegacyProtocol(w http.ResponseWriter, r *http.Request) {
	var s RdgSession

	connId := r.Header.Get(rdgConnectionIdKey)
	x, found := c.Get(connId)
	if !found {
		s = RdgSession{ConnId: connId, StateIn: 0, StateOut: 0}
	} else {
		s = x.(RdgSession)
	}

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

		c.Set(connId, s, cache.DefaultExpiration)
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
			c.Set(connId, s, cache.DefaultExpiration)

			log.Printf("Opening RDGIN for client %s", in.Conn.RemoteAddr().String())
			in.SendAccept(false)

			// read some initial data
			in.Drain()

			log.Printf("Legacy handshake done for client %s", in.Conn.RemoteAddr().String())
			handler := NewHandler(in, s.TransportOut)
			handler.Process()
		}
	}
}