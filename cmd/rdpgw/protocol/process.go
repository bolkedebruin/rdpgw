package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

type Processor struct {
	// gw is the gateway instance on which the connection arrived
	// Immutable; never nil.
	gw *Gateway

	// state is the internal state of the processor
	state int

	// tunnel is the underlying connection with the client
	tunnel *Tunnel

	// ctl is a channel to control the processor in case of events
	ctl chan int
}

func NewProcessor(gw *Gateway, tunnel *Tunnel) *Processor {
	h := &Processor{
		gw:     gw,
		state:  SERVER_STATE_INITIALIZED,
		tunnel: tunnel,
		ctl:    make(chan int),
	}
	return h
}

const tunnelId = 10

func (p *Processor) Process(ctx context.Context) error {
	for {
		//pt, sz, pkt, err := p.tunnel.Read()
		messages, err := p.tunnel.Read()
		if err != nil {
			log.Printf("Cannot read message from stream %p", err)
			return err
		}

		for _, message := range messages {
			if message.err != nil {
				log.Printf("Cannot read message from stream %p", err)
				continue
			}
			switch message.packetType {
			case PKT_TYPE_HANDSHAKE_REQUEST:
				log.Printf("Client handshakeRequest from %s", p.tunnel.User.GetAttribute(identity.AttrClientIp))
				if p.state != SERVER_STATE_INITIALIZED {
					log.Printf("Handshake attempted while in wrong state %d != %d", p.state, SERVER_STATE_INITIALIZED)
					msg := p.handshakeResponse(0x0, 0x0, 0, E_PROXY_INTERNALERROR)
					p.tunnel.Write(msg)
					return fmt.Errorf("%x: wrong state", E_PROXY_INTERNALERROR)
				}
				major, minor, _, reqAuth := p.handshakeRequest(message.msg)
				caps, err := p.matchAuth(reqAuth)
				if err != nil {
					log.Println(err)
					msg := p.handshakeResponse(0x0, 0x0, 0, E_PROXY_CAPABILITYMISMATCH)
					p.tunnel.Write(msg)
					return err
				}
				msg := p.handshakeResponse(major, minor, caps, ERROR_SUCCESS)
				p.tunnel.Write(msg)
				p.state = SERVER_STATE_HANDSHAKE
			case PKT_TYPE_TUNNEL_CREATE:
				log.Printf("Tunnel create")
				if p.state != SERVER_STATE_HANDSHAKE {
					log.Printf("Tunnel create attempted while in wrong state %d != %d",
						p.state, SERVER_STATE_HANDSHAKE)
					msg := p.tunnelResponse(E_PROXY_INTERNALERROR)
					p.tunnel.Write(msg)
					return fmt.Errorf("%x: PAA cookie rejected, wrong state", E_PROXY_INTERNALERROR)
				}
				_, cookie := p.tunnelRequest(message.msg)
				if p.gw.CheckPAACookie != nil {
					if ok, _ := p.gw.CheckPAACookie(ctx, cookie); !ok {
						log.Printf("Invalid PAA cookie received from client %s", p.tunnel.User.GetAttribute(identity.AttrClientIp))
						msg := p.tunnelResponse(E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED)
						p.tunnel.Write(msg)
						return fmt.Errorf("%x: invalid PAA cookie", E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED)
					}
				}
				msg := p.tunnelResponse(ERROR_SUCCESS)
				p.tunnel.Write(msg)
				p.state = SERVER_STATE_TUNNEL_CREATE
			case PKT_TYPE_TUNNEL_AUTH:
				log.Printf("Tunnel auth")
				if p.state != SERVER_STATE_TUNNEL_CREATE {
					log.Printf("Tunnel auth attempted while in wrong state %d != %d",
						p.state, SERVER_STATE_TUNNEL_CREATE)
					msg := p.tunnelAuthResponse(E_PROXY_INTERNALERROR)
					p.tunnel.Write(msg)
					return fmt.Errorf("%x: Tunnel auth rejected, wrong state", E_PROXY_INTERNALERROR)
				}
				client := p.tunnelAuthRequest(message.msg)
				if p.gw.CheckClientName != nil {
					if ok, _ := p.gw.CheckClientName(ctx, client); !ok {
						log.Printf("Invalid client name: %s", client)
						msg := p.tunnelAuthResponse(ERROR_ACCESS_DENIED)
						p.tunnel.Write(msg)
						return fmt.Errorf("%x: Tunnel auth rejected, invalid client name", ERROR_ACCESS_DENIED)
					}
				}
				msg := p.tunnelAuthResponse(ERROR_SUCCESS)
				p.tunnel.Write(msg)
				p.state = SERVER_STATE_TUNNEL_AUTHORIZE
			case PKT_TYPE_CHANNEL_CREATE:
				log.Printf("Channel create")
				if p.state != SERVER_STATE_TUNNEL_AUTHORIZE {
					log.Printf("Channel create attempted while in wrong state %d != %d",
						p.state, SERVER_STATE_TUNNEL_AUTHORIZE)
					msg := p.channelResponse(E_PROXY_INTERNALERROR)
					p.tunnel.Write(msg)
					return fmt.Errorf("%x: Channel create rejected, wrong state", E_PROXY_INTERNALERROR)
				}
				server, port := p.channelRequest(message.msg)
				host := net.JoinHostPort(server, strconv.Itoa(int(port)))
				if p.gw.CheckHost != nil {
					log.Printf("Verifying %s host connection", host)
					if ok, _ := p.gw.CheckHost(ctx, host); !ok {
						log.Printf("Not allowed to connect to %s by policy handler", host)
						msg := p.channelResponse(E_PROXY_RAP_ACCESSDENIED)
						p.tunnel.Write(msg)
						return fmt.Errorf("%x: denied by security policy", E_PROXY_RAP_ACCESSDENIED)
					}
				}
				log.Printf("Establishing connection to RDP server: %s", host)
				p.tunnel.rwc, err = net.DialTimeout("tcp", host, time.Second*15)
				if err != nil {
					log.Printf("Error connecting to %s, %s", host, err)
					msg := p.channelResponse(E_PROXY_INTERNALERROR)
					p.tunnel.Write(msg)
					return err
				}
				p.tunnel.TargetServer = host
				log.Printf("Connection established")
				msg := p.channelResponse(ERROR_SUCCESS)
				p.tunnel.Write(msg)

				// Make sure to start the flow from the RDP server first otherwise connections
				// might hang eventually
				go forward(p.tunnel.rwc, p.tunnel)
				p.state = SERVER_STATE_CHANNEL_CREATE
			case PKT_TYPE_DATA:
				if p.state < SERVER_STATE_CHANNEL_CREATE {
					log.Printf("Data received while in wrong state %d != %d", p.state, SERVER_STATE_CHANNEL_CREATE)
					return errors.New("wrong state")
				}
				p.state = SERVER_STATE_OPENED
				receive(message.msg, p.tunnel.rwc)
			case PKT_TYPE_KEEPALIVE:
				// keepalives can be received while the channel is not open yet
				if p.state < SERVER_STATE_CHANNEL_CREATE {
					log.Printf("Keepalive received while in wrong state %d != %d", p.state, SERVER_STATE_CHANNEL_CREATE)
					return errors.New("wrong state")
				}

				// avoid concurrency issues
				// p.transportIn.Write(createPacket(PKT_TYPE_KEEPALIVE, []byte{}))
			case PKT_TYPE_CLOSE_CHANNEL:
				log.Printf("Close channel")
				if p.state != SERVER_STATE_OPENED {
					log.Printf("Channel closed while in wrong state %d != %d", p.state, SERVER_STATE_OPENED)
					return errors.New("wrong state")
				}
				msg := p.channelCloseResponse(ERROR_SUCCESS)
				p.tunnel.Write(msg)
				p.state = SERVER_STATE_CLOSED
				return nil
			default:
				log.Printf("Unknown packet (size %d): %x", message.length, message.msg)
			}
		}
	}
}

// Creates a packet and is a response to a handshakeRequest request
// HTTP_EXTENDED_AUTH_SSPI_NTLM is not supported in Linux
// but could be in Windows. However, the NTLM protocol is insecure
func (p *Processor) handshakeResponse(major byte, minor byte, caps uint16, errorCode int) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(errorCode)) // error_code
	buf.Write([]byte{major, minor})
	binary.Write(buf, binary.LittleEndian, uint16(0))    // server version
	binary.Write(buf, binary.LittleEndian, uint16(caps)) // extended auth

	return createPacket(PKT_TYPE_HANDSHAKE_RESPONSE, buf.Bytes())
}

func (p *Processor) handshakeRequest(data []byte) (major byte, minor byte, version uint16, extAuth uint16) {
	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &major)
	binary.Read(r, binary.LittleEndian, &minor)
	binary.Read(r, binary.LittleEndian, &version)
	binary.Read(r, binary.LittleEndian, &extAuth)

	log.Printf("major: %d, minor: %d, version: %d, ext auth: %d", major, minor, version, extAuth)
	return
}

func (p *Processor) matchAuth(clientAuthCaps uint16) (caps uint16, err error) {
	if p.gw.SmartCardAuth {
		caps = caps | HTTP_EXTENDED_AUTH_SC
	}
	if p.gw.TokenAuth {
		caps = caps | HTTP_EXTENDED_AUTH_PAA
	}

	if caps&clientAuthCaps == 0 && clientAuthCaps > 0 {
		return 0, fmt.Errorf("%x has no matching capability configured (%x). Did you configure caps? ", clientAuthCaps, caps)
	}

	if caps > 0 && clientAuthCaps == 0 {
		return 0, fmt.Errorf("%d caps are required by the server, but the client does not support them", caps)
	}
	return caps, nil
}

func (p *Processor) tunnelRequest(data []byte) (caps uint32, cookie string) {
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
	return
}

func (p *Processor) tunnelResponse(errorCode int) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                    // server version
	binary.Write(buf, binary.LittleEndian, uint32(errorCode))                                                            // error code
	binary.Write(buf, binary.LittleEndian, uint16(HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID|HTTP_TUNNEL_RESPONSE_FIELD_CAPS)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                    // reserved

	// tunnel id (when is it used?)
	binary.Write(buf, binary.LittleEndian, uint32(tunnelId))

	binary.Write(buf, binary.LittleEndian, uint32(HTTP_CAPABILITY_IDLE_TIMEOUT))

	return createPacket(PKT_TYPE_TUNNEL_RESPONSE, buf.Bytes())
}

func (p *Processor) tunnelAuthRequest(data []byte) string {
	buf := bytes.NewReader(data)

	var size uint16
	binary.Read(buf, binary.LittleEndian, &size)
	clData := make([]byte, size)
	binary.Read(buf, binary.LittleEndian, &clData)
	clientName, _ := DecodeUTF16(clData)

	return clientName
}

func (p *Processor) tunnelAuthResponse(errorCode int) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(errorCode))                                                                                // error code
	binary.Write(buf, binary.LittleEndian, uint16(HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS|HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                                        // reserved

	// idle timeout
	if p.gw.IdleTimeout < 0 {
		p.gw.IdleTimeout = 0
	}

	binary.Write(buf, binary.LittleEndian, uint32(makeRedirectFlags(p.gw.RedirectFlags))) // redir flags
	binary.Write(buf, binary.LittleEndian, uint32(p.gw.IdleTimeout))                      // timeout in minutes

	return createPacket(PKT_TYPE_TUNNEL_AUTH_RESPONSE, buf.Bytes())
}

func (p *Processor) channelRequest(data []byte) (server string, port uint16) {
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

func (p *Processor) channelResponse(errorCode int) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(errorCode))                             // error code
	binary.Write(buf, binary.LittleEndian, uint16(HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0))                                     // reserved

	// channel id is required for Windows clients
	binary.Write(buf, binary.LittleEndian, uint32(1)) // channel id

	// optional fields
	// channel id uint32 (4)
	// udp port uint16 (2)
	// udp auth cookie 1 byte for side channel
	// length uint16

	return createPacket(PKT_TYPE_CHANNEL_RESPONSE, buf.Bytes())
}

func (p *Processor) channelCloseResponse(errorCode int) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(errorCode))                             // error code
	binary.Write(buf, binary.LittleEndian, uint16(HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0))                                     // reserved

	// channel id is required for Windows clients
	binary.Write(buf, binary.LittleEndian, uint32(1)) // channel id

	// optional fields
	// channel id uint32 (4)
	// udp port uint16 (2)
	// udp auth cookie 1 byte for side channel
	// length uint16

	return createPacket(PKT_TYPE_CLOSE_CHANNEL_RESPONSE, buf.Bytes())
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
