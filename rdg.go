package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	crlf               = "\r\n"
	rdgConnectionIdKey = "Rdg-Connection-Id"
)

const (
	PKT_TYPE_HANDSHAKE_REQUEST      = 0x1
	PKT_TYPE_HANDSHAKE_RESPONSE     = 0x2
	PKT_TYPE_EXTENDED_AUTH_MSG      = 0x3
	PKT_TYPE_TUNNEL_CREATE          = 0x4
	PKT_TYPE_TUNNEL_RESPONSE        = 0x5
	PKT_TYPE_TUNNEL_AUTH            = 0x6
	PKT_TYPE_TUNNEL_AUTH_RESPONSE   = 0x7
	PKT_TYPE_CHANNEL_CREATE         = 0x8
	PKT_TYPE_CHANNEL_RESPONSE       = 0x9
	PKT_TYPE_DATA                   = 0xA
	PKT_TYPE_SERVICE_MESSAGE        = 0xB
	PKT_TYPE_REAUTH_MESSAGE         = 0xC
	PKT_TYPE_KEEPALIVE              = 0xD
	PKT_TYPE_CLOSE_CHANNEL          = 0x10
	PKT_TYPE_CLOSE_CHANNEL_RESPONSE = 0x11
)

const (
	HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID   = 0x01
	HTTP_TUNNEL_RESPONSE_FIELD_CAPS        = 0x02
	HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ     = 0x04
	HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG = 0x10
)

const (
	HTTP_EXTENDED_AUTH_NONE      = 0x0
	HTTP_EXTENDED_AUTH_SC        = 0x1  /* Smart card authentication. */
	HTTP_EXTENDED_AUTH_PAA       = 0x02 /* Pluggable authentication. */
	HTTP_EXTENDED_AUTH_SSPI_NTLM = 0x04 /* NTLM extended authentication. */
)

const (
	HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS  = 0x01
	HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT = 0x02
	HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE = 0x04
)

const (
	HTTP_TUNNEL_REDIR_ENABLE_ALL        = 0x80000000
	HTTP_TUNNEL_REDIR_DISABLE_ALL       = 0x40000000
	HTTP_TUNNEL_REDIR_DISABLE_DRIVE     = 0x01
	HTTP_TUNNEL_REDIR_DISABLE_PRINTER   = 0x02
	HTTP_TUNNEL_REDIR_DISABLE_PORT      = 0x03
	HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD = 0x08
	HTTP_TUNNEL_REDIR_DISABLE_PNP       = 0x10
)

const (
	HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID   = 0x01
	HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE = 0x02
	HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT     = 0x04
)

const (
	HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE = 0x1
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
	ConnIn        net.Conn
	ConnOut       net.Conn
	StateIn       int
	StateOut      int
	Remote        net.Conn
}

// ErrNotHijacker is an error returned when http.ResponseWriter does not
// implement http.Hijacker interface.
var ErrNotHijacker = RejectConnectionError(
	RejectionStatus(http.StatusInternalServerError),
	RejectionReason("given http.ResponseWriter is not a http.Hijacker"),
)

var DefaultSession RdgSession

func Accept(w http.ResponseWriter) (conn net.Conn, rw *bufio.ReadWriter, err error) {
	log.Print("Accept connection")
	hj, ok := w.(http.Hijacker)
	if ok {
		return hj.Hijack()
	} else {
		err = ErrNotHijacker
	}
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return nil, nil, err
	}
	return
}

var upgrader = websocket.Upgrader{}
var c = cache.New(5*time.Minute, 10*time.Minute)

func handleGatewayProtocol(w http.ResponseWriter, r *http.Request) {
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

func handleWebsocketProtocol(conn *websocket.Conn) {
	fragment := false
	buf := make([]byte, 4096)
	index := 0

	var remote net.Conn

	websocketConnections.Inc()
	defer websocketConnections.Dec()

	var host string
	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Error read: %s", err)
			break
		}

		// check for fragments
		var pt uint16
		var sz uint32
		var pkt []byte

		if !fragment {
			pt, sz, pkt, err = readHeader(msg)
			if err != nil {
				// fragment received
				// log.Printf("Received non websocket fragment")
				fragment = true
				index = copy(buf, msg)
				continue
			}
			index = 0
		} else {
			//log.Printf("Dealing with fragment")
			fragment = false
			pt, sz, pkt, _ = readHeader(append(buf[:index], msg...))
		}

		switch pt {
		case PKT_TYPE_HANDSHAKE_REQUEST:
			major, minor, _, auth := readHandshake(pkt)
			msg := handshakeResponse(major, minor, auth)
			log.Printf("Handshake response: %x", msg)
			conn.WriteMessage(mt, msg)
		case PKT_TYPE_TUNNEL_CREATE:
			_, cookie := readCreateTunnelRequest(pkt)
			data, found := tokens.Get(cookie)
			if found == false {
				log.Printf("Invalid PAA cookie: %s from %s", cookie, conn.RemoteAddr())
				return
			}
			host = strings.Replace(conf.Server.HostTemplate, "%%", data.(string), 1)
			msg := createTunnelResponse()
			log.Printf("Create tunnel response: %x", msg)
			conn.WriteMessage(mt, msg)
		case PKT_TYPE_TUNNEL_AUTH:
			readTunnelAuthRequest(pkt)
			msg := createTunnelAuthResponse()
			log.Printf("Create tunnel auth response: %x", msg)
			conn.WriteMessage(mt, msg)
		case PKT_TYPE_CHANNEL_CREATE:
			server, port := readChannelCreateRequest(pkt)
			if conf.Server.EnableOverride == true {
				log.Printf("Override allowed")
				host = net.JoinHostPort(server, strconv.Itoa(int(port)))
			}
			log.Printf("Establishing connection to RDP server: %s", host)
			remote, err = net.DialTimeout(
				"tcp",
				host,
				time.Second * 30)
			if err != nil {
				log.Printf("Error connecting to %s", host)
				return
			}
			log.Printf("Connection established")
			msg := createChannelCreateResponse()
			log.Printf("Create channel create response: %x", msg)
			conn.WriteMessage(mt, msg)
			go handleWebsocketData(remote, mt, conn)
		case PKT_TYPE_DATA:
			forwardDataPacket(remote, pkt)
		case PKT_TYPE_KEEPALIVE:
			// do not write to make sure we do not create concurrency issues
			// conn.WriteMessage(mt, createPacket(PKT_TYPE_KEEPALIVE, []byte{}))
		case PKT_TYPE_CLOSE_CHANNEL:
			break
		default:
			log.Printf("Unknown packet type: %d (size: %d), %x", pt, sz, pkt)
		}
	}
}

// The legacy protocol (no websockets) uses an RDG_IN_DATA for client -> server
// and RDG_OUT_DATA for server -> client data. The handshake procedure is a bit different
// to ensure the connections do not get cached or terminated by a proxy prematurely.
func handleLegacyProtocol(w http.ResponseWriter, r *http.Request) {
	var s RdgSession

	connId := r.Header.Get(rdgConnectionIdKey)
	x, found := c.Get(connId)
	if !found {
		log.Printf("No cached session found")
		s = RdgSession{ConnId: connId, StateIn: 0, StateOut: 0}
	} else {
		log.Printf("Found cached session")
		s = x.(RdgSession)
	}

	log.Printf("Session %s, %t, %t", s.ConnId, s.ConnOut != nil, s.ConnIn != nil)

	if r.Method == MethodRDGOUT {
		conn, rw, err := Accept(w)
		if err != nil {
			log.Printf("cannot hijack connection to support RDG OUT data channel: %s", err)
			return
		}
		log.Printf("Opening RDGOUT for client %s", conn.RemoteAddr().String())

		s.ConnOut = conn
		WriteAcceptSeed(rw.Writer, true)

		c.Set(connId, s, cache.DefaultExpiration)
	} else if r.Method == MethodRDGIN {
		legacyConnections.Inc()
		defer legacyConnections.Dec()

		var remote net.Conn

		conn, rw, err := Accept(w)
		if err != nil {
			log.Printf("cannot hijack connection to support RDG IN data channel: %s", err)
			return
		}
		defer conn.Close()

		if s.ConnIn == nil {
			fragment := false
			index := 0
			buf := make([]byte, 4096)

			s.ConnIn = conn
			c.Set(connId, s, cache.DefaultExpiration)
			log.Printf("Opening RDGIN for client %s", conn.RemoteAddr().String())
			WriteAcceptSeed(rw.Writer, false)
			p := make([]byte, 32767)
			rw.Reader.Read(p)

			log.Printf("Reading packet from client %s", conn.RemoteAddr().String())
			chunkScanner := httputil.NewChunkedReader(rw.Reader)
			msg := make([]byte, 4096) // bufio.defaultBufSize

			for {
				n, err := chunkScanner.Read(msg)
				if err == io.EOF || n == 0 {
					break
				}

				// check for fragments
				var pt uint16
				var sz uint32
				var pkt []byte

				if !fragment {
					pt, sz, pkt, err = readHeader(msg[:n])
					if err != nil {
						// fragment received
						fragment = true
						index = copy(buf, msg[:n])
						continue
					}
					index = 0
				} else {
					fragment = false
					pt, sz, pkt, _ = readHeader(append(buf[:index], msg[:n]...))
				}

				switch pt {
				case PKT_TYPE_HANDSHAKE_REQUEST:
					major, minor, _, auth := readHandshake(pkt)
					msg := handshakeResponse(major, minor, auth)
					s.ConnOut.Write(msg)
				case PKT_TYPE_TUNNEL_CREATE:
					_, cookie := readCreateTunnelRequest(pkt)
					if _, found := tokens.Get(cookie); found == false {
						log.Printf("Invalid PAA cookie: %s from %s", cookie, conn.RemoteAddr())
						return
					}
					msg := createTunnelResponse()
					s.ConnOut.Write(msg)
				case PKT_TYPE_TUNNEL_AUTH:
					readTunnelAuthRequest(pkt)
					msg := createTunnelAuthResponse()
					s.ConnOut.Write(msg)
				case PKT_TYPE_CHANNEL_CREATE:
					server, port := readChannelCreateRequest(pkt)
					log.Printf("Establishing connection to RDP server: %s on port %d (%x)", server, port, server)
					remote, err = net.DialTimeout(
						"tcp",
						net.JoinHostPort(server, strconv.Itoa(int(port))),
						time.Second * 15)
					if err != nil {
						log.Printf("Error connecting to %s, %d, %s", server, port, err)
						return
					}
					log.Printf("Connection established")
					msg := createChannelCreateResponse()
					s.ConnOut.Write(msg)

					// Make sure to start the flow from the RDP server first otherwise connections
					// might hang eventually
					go sendDataPacket(remote, s.ConnOut)
				case PKT_TYPE_DATA:
					forwardDataPacket(remote, pkt)
				case PKT_TYPE_KEEPALIVE:
					// avoid concurrency issues
					// s.ConnOut.Write(createPacket(PKT_TYPE_KEEPALIVE, []byte{}))
				case PKT_TYPE_CLOSE_CHANNEL:
					s.ConnIn.Close()
					s.ConnOut.Close()
					break
				default:
					log.Printf("Unknown packet (size %d): %x", sz, pkt[:n])
				}
			}
		}
	}
}

// [MS-TSGU]: Terminal Services Gateway Server Protocol version 39.0
// The server sends back the final status code 200 OK, and also a random entity body of limited size (100 bytes).
// This enables a reverse proxy to start allowing data from the RDG server to the RDG client. The RDG server does
// not specify an entity length in its response. It uses HTTP 1.0 semantics to send the entity body and closes the
// connection after the last byte is sent.
func WriteAcceptSeed(bw *bufio.Writer, doSeed bool) {
	log.Printf("Writing accept")
	bw.WriteString(HttpOK)
	bw.WriteString("Date: " + time.Now().Format(time.RFC1123) + crlf)
	if !doSeed {
		bw.WriteString("Content-Length: 0" + crlf)
	}
	bw.WriteString(crlf)

	if doSeed {
		seed := make([]byte, 10)
		rand.Read(seed)
		// docs say it's a seed but 2019 responds with ab cd * 5
		bw.Write(seed)
	}
	bw.Flush()
}

func readHeader(data []byte) (packetType uint16, size uint32, packet []byte, err error) {
	// header needs to be 8 min
	if len(data) < 8 {
		return 0, 0, nil, errors.New("header too short, fragment likely")
	}
	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &packetType)
	r.Seek(4, io.SeekStart)
	binary.Read(r, binary.LittleEndian, &size)
	if len(data) < int(size) {
		return packetType, size, data[8:], errors.New("data incomplete, fragment received")
	}
	return packetType, size, data[8:], nil
}

// Creates a packet the is a response to a handshake request
// HTTP_EXTENDED_AUTH_SSPI_NTLM is not supported in Linux
// but could be in Windows. However the NTLM protocol is insecure
func handshakeResponse(major byte, minor byte, auth uint16) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // error_code
	buf.Write([]byte{major, minor})
	binary.Write(buf, binary.LittleEndian, uint16(0))                                            // server version
	binary.Write(buf, binary.LittleEndian, uint16(HTTP_EXTENDED_AUTH_PAA|HTTP_EXTENDED_AUTH_SC)) // extended auth

	return createPacket(PKT_TYPE_HANDSHAKE_RESPONSE, buf.Bytes())
}

func readHandshake(data []byte) (major byte, minor byte, version uint16, extAuth uint16) {
	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &major)
	binary.Read(r, binary.LittleEndian, &minor)
	binary.Read(r, binary.LittleEndian, &version)
	binary.Read(r, binary.LittleEndian, &extAuth)

	log.Printf("major: %d, minor: %d, version: %d, ext auth: %d", major, minor, version, extAuth)
	return
}

func readCreateTunnelRequest(data []byte) (caps uint32, cookie string) {
	var fields uint16

	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &caps)
	binary.Read(r, binary.LittleEndian, &fields)
	r.Seek(2, io.SeekCurrent)

	if fields == HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE {
		var size uint16
		binary.Read(r, binary.LittleEndian, &size)
		cookieB := make([]byte, size)
		r.Read(cookieB)
		cookie, _ = DecodeUTF16(cookieB)
	}
	log.Printf("Create tunnel caps: %d, cookie: %s", caps, cookie)
	return
}

func createTunnelResponse() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                    // server version
	binary.Write(buf, binary.LittleEndian, uint32(0))                                                                    // error code
	binary.Write(buf, binary.LittleEndian, uint16(HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID|HTTP_TUNNEL_RESPONSE_FIELD_CAPS)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                    // reserved
	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                    // reserved

	// tunnel id ?
	binary.Write(buf, binary.LittleEndian, uint32(15))
	// caps ?
	binary.Write(buf, binary.LittleEndian, uint32(2))

	return createPacket(PKT_TYPE_TUNNEL_RESPONSE, buf.Bytes())
}

func readTunnelAuthRequest(data []byte) {
	buf := bytes.NewReader(data)

	var size uint16
	binary.Read(buf, binary.LittleEndian, &size)
	clData := make([]byte, size)
	binary.Read(buf, binary.LittleEndian, &clData)
	clientName, _ := DecodeUTF16(clData)
	log.Printf("Client: %s", clientName)
}

func createTunnelAuthResponse() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(0))                                                                                        // error code
	binary.Write(buf, binary.LittleEndian, uint16(HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS|HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                                        // reserved

	// flags
	binary.Write(buf, binary.LittleEndian, uint32(HTTP_TUNNEL_REDIR_ENABLE_ALL)) // redir flags
	binary.Write(buf, binary.LittleEndian, uint32(0))                            // timeout in minutes

	return createPacket(PKT_TYPE_TUNNEL_AUTH_RESPONSE, buf.Bytes())
}

func readChannelCreateRequest(data []byte) (server string, port uint16) {
	buf := bytes.NewReader(data)

	var resourcesSize byte
	var alternative byte
	var protocol uint16
	var nameSize uint16

	binary.Read(buf, binary.LittleEndian, &resourcesSize)
	binary.Read(buf, binary.LittleEndian, &alternative)
	binary.Read(buf, binary.LittleEndian, &port)
	binary.Read(buf, binary.LittleEndian, &protocol)
	binary.Read(buf, binary.LittleEndian, &nameSize)

	nameData := make([]byte, nameSize)
	binary.Read(buf, binary.LittleEndian, &nameData)

	log.Printf("Name data %q", nameData)
	server, _ = DecodeUTF16(nameData)

	log.Printf("Should connect to %s on port %d", server, port)
	return
}

func createChannelCreateResponse() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(0)) // error code
	//binary.Write(buf, binary.LittleEndian, uint16(HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID | HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE | HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0)) // fields
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved

	// optional fields
	// channel id uint32 (4)
	// udp port uint16 (2)
	// udp auth cookie 1 byte for side channel
	// length uint16

	return createPacket(PKT_TYPE_CHANNEL_RESPONSE, buf.Bytes())
}

func createPacket(pktType uint16, data []byte) (packet []byte) {
	size := len(data) + 8
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(pktType))
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(buf, binary.LittleEndian, uint32(size))
	buf.Write(data)

	return buf.Bytes()
}

func forwardDataPacket(conn net.Conn, data []byte) {
	buf := bytes.NewReader(data)

	var cblen uint16
	binary.Read(buf, binary.LittleEndian, &cblen)
	//log.Printf("Received PKT_DATA %d", cblen)
	pkt := make([]byte, cblen)
	binary.Read(buf, binary.LittleEndian, &pkt)
	//n, _ := buf.Read(pkt)
	//log.Printf("CBLEN: %d, N: %d", cblen, n)
	//log.Printf("DATA FROM CLIENT %q", pkt)
	conn.Write(pkt)
}

func handleWebsocketData(rdp net.Conn, mt int, conn *websocket.Conn) {
	defer rdp.Close()
	b1 := new(bytes.Buffer)
	buf := make([]byte, 4086)

	for {
		n, err := rdp.Read(buf)
		binary.Write(b1, binary.LittleEndian, uint16(n))
		if err != nil {
			log.Printf("Error reading from conn %s", err)
			break
		}
		b1.Write(buf[:n])
		conn.WriteMessage(mt, createPacket(PKT_TYPE_DATA, b1.Bytes()))
		b1.Reset()
	}
}

func sendDataPacket(connIn net.Conn, connOut net.Conn) {
	defer connIn.Close()
	b1 := new(bytes.Buffer)
	buf := make([]byte, 4086)
	for {
		n, err := connIn.Read(buf)
		binary.Write(b1, binary.LittleEndian, uint16(n))
		log.Printf("RDP SIZE: %d", n)
		if err != nil {
			log.Printf("Error reading from conn %s", err)
			break
		}
		b1.Write(buf[:n])
		connOut.Write(createPacket(PKT_TYPE_DATA, b1.Bytes()))
		b1.Reset()
	}
}

func DecodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("must have even length byte slice")
	}

	u16s := make([]uint16, 1)
	ret := &bytes.Buffer{}
	b8buf := make([]byte, 4)

	lb := len(b)
	for i := 0; i < lb; i += 2 {
		u16s[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		r := utf16.Decode(u16s)
		n := utf8.EncodeRune(b8buf, r[0])
		ret.Write(b8buf[:n])
	}

	bret := ret.Bytes()
	if len(bret) > 0 && bret[len(bret)-1] == '\x00' {
		bret = bret[:len(bret)-1]
	}
	return string(bret), nil
}

// UTF-16 endian byte order
const (
	unknownEndian = iota
	bigEndian
	littleEndian
)

// dropCREndian drops a terminal \r from the endian data.
func dropCREndian(data []byte, t1, t2 byte) []byte {
	if len(data) > 1 {
		if data[len(data)-2] == t1 && data[len(data)-1] == t2 {
			return data[0 : len(data)-2]
		}
	}
	return data
}

// dropCRBE drops a terminal \r from the big endian data.
func dropCRBE(data []byte) []byte {
	return dropCREndian(data, '\x00', '\r')
}

// dropCRLE drops a terminal \r from the little endian data.
func dropCRLE(data []byte) []byte {
	return dropCREndian(data, '\r', '\x00')
}

// dropCR drops a terminal \r from the data.
func dropCR(data []byte) ([]byte, int) {
	var endian = unknownEndian
	switch ld := len(data); {
	case ld != len(dropCRLE(data)):
		endian = littleEndian
	case ld != len(dropCRBE(data)):
		endian = bigEndian
	}
	return data, endian
}
