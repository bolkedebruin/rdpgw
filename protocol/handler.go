package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/bolkedebruin/rdpgw/transport"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

type VerifyTunnelCreate func(*SessionInfo, string) (bool, error)
type VerifyTunnelAuthFunc func(*SessionInfo, string) (bool, error)
type VerifyServerFunc func(*SessionInfo, string) (bool, error)

type RedirectFlags struct {
	Clipboard  bool
	Port       bool
	Drive      bool
	Printer    bool
	Pnp        bool
	DisableAll bool
	EnableAll  bool
}

type Handler struct {
	Session              *SessionInfo
	TransportIn          transport.Transport
	TransportOut         transport.Transport
	VerifyTunnelCreate   VerifyTunnelCreate
	VerifyTunnelAuthFunc VerifyTunnelAuthFunc
	VerifyServerFunc     VerifyServerFunc
	RedirectFlags        int
	IdleTimeout          int
	SmartCardAuth        bool
	TokenAuth            bool
	ClientName           string
	Remote               net.Conn
	State                int
}

type HandlerConf struct {
	VerifyTunnelCreate   VerifyTunnelCreate
	VerifyTunnelAuthFunc VerifyTunnelAuthFunc
	VerifyServerFunc     VerifyServerFunc
	RedirectFlags        RedirectFlags
	IdleTimeout          int
	SmartCardAuth        bool
	TokenAuth            bool
}

func NewHandler(s *SessionInfo, conf *HandlerConf) *Handler {
	h := &Handler{
		Session:              s,
		TransportIn:          s.TransportIn,
		TransportOut:         s.TransportOut,
		State:                SERVER_STATE_INITIAL,
		RedirectFlags:        makeRedirectFlags(conf.RedirectFlags),
		IdleTimeout:          conf.IdleTimeout,
		SmartCardAuth:        conf.SmartCardAuth,
		TokenAuth:            conf.TokenAuth,
		VerifyTunnelCreate:   conf.VerifyTunnelCreate,
		VerifyServerFunc:     conf.VerifyServerFunc,
		VerifyTunnelAuthFunc: conf.VerifyTunnelAuthFunc,
	}
	return h
}

func (h *Handler) Process() error {
	for {
		pt, sz, pkt, err := h.ReadMessage()
		if err != nil {
			log.Printf("Cannot read message from stream %s", err)
			return err
		}

		switch pt {
		case PKT_TYPE_HANDSHAKE_REQUEST:
			if h.State != SERVER_STATE_INITIAL {
				log.Printf("Handshake attempted while in wrong state %d != %d", h.State, SERVER_STATE_INITIAL)
				return errors.New("wrong state")
			}
			major, minor, _, _ := readHandshake(pkt) // todo check if auth matches what the handler can do
			msg := h.handshakeResponse(major, minor)
			h.TransportOut.WritePacket(msg)
			h.State = SERVER_STATE_HANDSHAKE
		case PKT_TYPE_TUNNEL_CREATE:
			if h.State != SERVER_STATE_HANDSHAKE {
				log.Printf("Tunnel create attempted while in wrong state %d != %d",
					h.State, SERVER_STATE_HANDSHAKE)
				return errors.New("wrong state")
			}
			_, cookie := readCreateTunnelRequest(pkt)
			if h.VerifyTunnelCreate != nil {
				if ok, _ := h.VerifyTunnelCreate(h.Session, cookie); !ok {
					log.Printf("Invalid PAA cookie: %s", cookie)
					return errors.New("invalid PAA cookie")
				}
			}
			msg := createTunnelResponse()
			h.TransportOut.WritePacket(msg)
			h.State = SERVER_STATE_TUNNEL_CREATE
		case PKT_TYPE_TUNNEL_AUTH:
			if h.State != SERVER_STATE_TUNNEL_CREATE {
				log.Printf("Tunnel auth attempted while in wrong state %d != %d",
					h.State, SERVER_STATE_TUNNEL_CREATE)
				return errors.New("wrong state")
			}
			client := h.readTunnelAuthRequest(pkt)
			if h.VerifyTunnelAuthFunc != nil {
				if ok, _ := h.VerifyTunnelAuthFunc(h.Session, client); !ok {
					log.Printf("Invalid client name: %s", client)
					return errors.New("invalid client name")
				}
			}
			msg := h.createTunnelAuthResponse()
			h.TransportOut.WritePacket(msg)
			h.State = SERVER_STATE_TUNNEL_AUTHORIZE
		case PKT_TYPE_CHANNEL_CREATE:
			if h.State != SERVER_STATE_TUNNEL_AUTHORIZE {
				log.Printf("Channel create attempted while in wrong state %d != %d",
					h.State, SERVER_STATE_TUNNEL_AUTHORIZE)
				return errors.New("wrong state")
			}
			server, port := readChannelCreateRequest(pkt)
			host := net.JoinHostPort(server, strconv.Itoa(int(port)))
			if h.VerifyServerFunc != nil {
				if ok, _ := h.VerifyServerFunc(h.Session, host); !ok {
					log.Printf("Not allowed to connect to %s by policy handler", host)
				}
			}
			log.Printf("Establishing connection to RDP server: %s", host)
			h.Remote, err = net.DialTimeout("tcp", host, time.Second*15)
			if err != nil {
				log.Printf("Error connecting to %s, %s", host, err)
				return err
			}
			log.Printf("Connection established")
			msg := createChannelCreateResponse()
			h.TransportOut.WritePacket(msg)

			// Make sure to start the flow from the RDP server first otherwise connections
			// might hang eventually
			go h.sendDataPacket()
			h.State = SERVER_STATE_CHANNEL_CREATE
		case PKT_TYPE_DATA:
			if h.State < SERVER_STATE_CHANNEL_CREATE {
				log.Printf("Data received while in wrong state %d != %d", h.State, SERVER_STATE_CHANNEL_CREATE)
				return errors.New("wrong state")
			}
			h.State = SERVER_STATE_OPENED
			h.forwardDataPacket(pkt)
		case PKT_TYPE_KEEPALIVE:
			// keepalives can be received while the channel is not open yet
			if h.State < SERVER_STATE_CHANNEL_CREATE {
				log.Printf("Keepalive received while in wrong state %d != %d", h.State, SERVER_STATE_CHANNEL_CREATE)
				return errors.New("wrong state")
			}

			// avoid concurrency issues
			// p.TransportIn.Write(createPacket(PKT_TYPE_KEEPALIVE, []byte{}))
		case PKT_TYPE_CLOSE_CHANNEL:
			if h.State != SERVER_STATE_OPENED {
				log.Printf("Channel closed while in wrong state %d != %d", h.State, SERVER_STATE_OPENED)
				return errors.New("wrong state")
			}
			h.TransportIn.Close()
			h.TransportOut.Close()
			h.State = SERVER_STATE_CLOSED
		default:
			log.Printf("Unknown packet (size %d): %x", sz, pkt)
		}
	}
}

func (h *Handler) ReadMessage() (pt int, n int, msg []byte, err error) {
	fragment := false
	index := 0
	buf := make([]byte, 4096)

	for {
		size, pkt, err := h.TransportIn.ReadPacket()
		if err != nil {
			return 0, 0, []byte{0, 0}, err
		}

		// check for fragments
		var pt uint16
		var sz uint32
		var msg []byte

		if !fragment {
			pt, sz, msg, err = readHeader(pkt[:size])
			if err != nil {
				fragment = true
				index = copy(buf, pkt[:size])
				continue
			}
			index = 0
		} else {
			fragment = false
			pt, sz, msg, err = readHeader(append(buf[:index], pkt[:size]...))
			// header is corrupted even after defragmenting
			if err != nil {
				return 0, 0, []byte{0, 0}, err
			}
		}
		if !fragment {
			return int(pt), int(sz), msg, nil
		}
	}
}

// Creates a packet the is a response to a handshake request
// HTTP_EXTENDED_AUTH_SSPI_NTLM is not supported in Linux
// but could be in Windows. However the NTLM protocol is insecure
func (h *Handler) handshakeResponse(major byte, minor byte) []byte {
	var caps uint16
	if h.SmartCardAuth {
		caps = caps | HTTP_EXTENDED_AUTH_PAA
	}
	if h.TokenAuth {
		caps = caps | HTTP_EXTENDED_AUTH_PAA
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // error_code
	buf.Write([]byte{major, minor})
	binary.Write(buf, binary.LittleEndian, uint16(0))    // server version
	binary.Write(buf, binary.LittleEndian, uint16(caps)) // extended auth

	return createPacket(PKT_TYPE_HANDSHAKE_RESPONSE, buf.Bytes())
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

func (h *Handler) readTunnelAuthRequest(data []byte) string {
	buf := bytes.NewReader(data)

	var size uint16
	binary.Read(buf, binary.LittleEndian, &size)
	clData := make([]byte, size)
	binary.Read(buf, binary.LittleEndian, &clData)
	clientName, _ := DecodeUTF16(clData)

	return clientName
}

func (h *Handler) createTunnelAuthResponse() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(0))                                                                                        // error code
	binary.Write(buf, binary.LittleEndian, uint16(HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS|HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                                        // reserved

	// idle timeout
	if h.IdleTimeout < 0 {
		h.IdleTimeout = 0
	}

	binary.Write(buf, binary.LittleEndian, uint32(h.RedirectFlags)) // redir flags
	binary.Write(buf, binary.LittleEndian, uint32(h.IdleTimeout))   // timeout in minutes

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

	server, _ = DecodeUTF16(nameData)

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

func (h *Handler) forwardDataPacket(data []byte) {
	buf := bytes.NewReader(data)

	var cblen uint16
	binary.Read(buf, binary.LittleEndian, &cblen)
	pkt := make([]byte, cblen)
	binary.Read(buf, binary.LittleEndian, &pkt)

	h.Remote.Write(pkt)
}

func (h *Handler) sendDataPacket() {
	defer h.Remote.Close()
	b1 := new(bytes.Buffer)
	buf := make([]byte, 4086)
	for {
		n, err := h.Remote.Read(buf)
		binary.Write(b1, binary.LittleEndian, uint16(n))
		if err != nil {
			log.Printf("Error reading from conn %s", err)
			break
		}
		b1.Write(buf[:n])
		h.TransportOut.WritePacket(createPacket(PKT_TYPE_DATA, b1.Bytes()))
		b1.Reset()
	}
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

func makeRedirectFlags(flags RedirectFlags) int {
	var redir = 0

	if flags.DisableAll {
		return HTTP_TUNNEL_REDIR_DISABLE_ALL
	}
	if flags.EnableAll {
		return HTTP_TUNNEL_REDIR_ENABLE_ALL
	}

	if !flags.Port {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_PORT
	}
	if !flags.Clipboard {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD
	}
	if !flags.Drive {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_DRIVE
	}
	if !flags.Pnp {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_PNP
	}
	if !flags.Printer {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_PRINTER
	}
	return redir
}
