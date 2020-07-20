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

// When should the client disconnect when idle in minutes
var IdleTimeout = 0

type VerifyPAACookieFunc func(string) (bool, error)
type VerifyTunnelAuthFunc func(string) (bool, error)
type VerifyServerFunc func(string) (bool, error)

type Handler struct {
	Transport            transport.Transport
	VerifyPAACookieFunc  VerifyPAACookieFunc
	VerifyTunnelAuthFunc VerifyTunnelAuthFunc
	VerifyServerFunc     VerifyServerFunc
	SmartCardAuth        bool
	TokenAuth            bool
	ClientName           string
	Remote				 net.Conn
}

func NewHandler(t transport.Transport) *Handler {
	h := &Handler{
		Transport: t,
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
			major, minor, _, auth := readHandshake(pkt)
			msg := h.handshakeResponse(major, minor, auth)
			h.Transport.WritePacket(msg)
		case PKT_TYPE_TUNNEL_CREATE:
			_, cookie := readCreateTunnelRequest(pkt)
			if h.VerifyPAACookieFunc != nil {
				if ok, _ := h.VerifyPAACookieFunc(cookie); ok == false {
					log.Printf("Invalid PAA cookie: %s", cookie)
					return errors.New("invalid PAA cookie")
				}
			}
			msg := createTunnelResponse()
			h.Transport.WritePacket(msg)
		case PKT_TYPE_TUNNEL_AUTH:
			h.readTunnelAuthRequest(pkt)
			msg := h.createTunnelAuthResponse()
			h.Transport.WritePacket(msg)
		case PKT_TYPE_CHANNEL_CREATE:
			server, port := readChannelCreateRequest(pkt)
			log.Printf("Establishing connection to RDP server: %s on port %d (%x)", server, port, server)
			h.Remote, err = net.DialTimeout(
				"tcp",
				net.JoinHostPort(server, strconv.Itoa(int(port))),
				time.Second*15)
			if err != nil {
				log.Printf("Error connecting to %s, %d, %s", server, port, err)
				return err
			}
			log.Printf("Connection established")
			msg := createChannelCreateResponse()
			h.Transport.WritePacket(msg)

			// Make sure to start the flow from the RDP server first otherwise connections
			// might hang eventually
			go h.sendDataPacket()
		case PKT_TYPE_DATA:
			h.forwardDataPacket(pkt)
		case PKT_TYPE_KEEPALIVE:
			// avoid concurrency issues
			// p.Transport.Write(createPacket(PKT_TYPE_KEEPALIVE, []byte{}))
		case PKT_TYPE_CLOSE_CHANNEL:
			h.Transport.Close()
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
		size, pkt, err := h.Transport.ReadPacket()
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
func (h *Handler) handshakeResponse(major byte, minor byte, auth uint16) []byte {
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

func (h *Handler) readTunnelAuthRequest(data []byte) {
	buf := bytes.NewReader(data)

	var size uint16
	binary.Read(buf, binary.LittleEndian, &size)
	clData := make([]byte, size)
	binary.Read(buf, binary.LittleEndian, &clData)
	clientName, _ := DecodeUTF16(clData)
	log.Printf("Client: %s", clientName)
}

func (h *Handler) createTunnelAuthResponse() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(0))                                                                                        // error code
	binary.Write(buf, binary.LittleEndian, uint16(HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS|HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                                        // reserved

	// flags
	var redir uint32
	/*
		if conf.Caps.RedirectAll {
			redir = HTTP_TUNNEL_REDIR_ENABLE_ALL
		} else if conf.Caps.DisableRedirect {
			redir = HTTP_TUNNEL_REDIR_DISABLE_ALL
		} else {
			if conf.Caps.DisableClipboard {
				redir = redir | HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD
			}
			if conf.Caps.DisableDrive {
				redir = redir | HTTP_TUNNEL_REDIR_DISABLE_DRIVE
			}
			if conf.Caps.DisablePnp {
				redir = redir | HTTP_TUNNEL_REDIR_DISABLE_PNP
			}
			if conf.Caps.DisablePrinter {
				redir = redir | HTTP_TUNNEL_REDIR_DISABLE_PRINTER
			}
			if conf.Caps.DisablePort {
				redir = redir | HTTP_TUNNEL_REDIR_DISABLE_PORT
			}
		}
	*/
	redir = HTTP_TUNNEL_REDIR_ENABLE_ALL

	// idle timeout
	if IdleTimeout < 0 {
		IdleTimeout = 0
	}

	binary.Write(buf, binary.LittleEndian, uint32(redir))       // redir flags
	binary.Write(buf, binary.LittleEndian, uint32(IdleTimeout)) // timeout in minutes

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
		h.Transport.WritePacket(createPacket(PKT_TYPE_DATA, b1.Bytes()))
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
