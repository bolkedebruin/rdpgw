package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

const (
	MajorVersion = 0x0
	MinorVersion = 0x0
	Version      = 0x00
)

type ClientConfig struct {
	SmartCardAuth bool
	PAAToken      string
	NTLMAuth      bool
	Session       *Tunnel
	LocalConn     net.Conn
	Server        string
	Port          int
	Name          string
}

func (c *ClientConfig) ConnectAndForward() error {
	c.Session.TransportOut.WritePacket(c.handshakeRequest())

	for {
		pt, sz, pkt, err := readMessage(c.Session.TransportIn)
		if err != nil {
			log.Printf("Cannot read message from stream %s", err)
			return err
		}

		switch pt {
		case PKT_TYPE_HANDSHAKE_RESPONSE:
			caps, err := c.handshakeResponse(pkt)
			if err != nil {
				log.Printf("Cannot connect to %s due to %s", c.Server, err)
				return err
			}
			log.Printf("Handshake response received. Caps: %d", caps)
			c.Session.TransportOut.WritePacket(c.tunnelRequest())
		case PKT_TYPE_TUNNEL_RESPONSE:
			tid, caps, err := c.tunnelResponse(pkt)
			if err != nil {
				log.Printf("Cannot setup tunnel due to %s", err)
				return err
			}
			log.Printf("Tunnel creation succesful. Tunnel id: %d and caps %d", tid, caps)
			c.Session.TransportOut.WritePacket(c.tunnelAuthRequest())
		case PKT_TYPE_TUNNEL_AUTH_RESPONSE:
			flags, timeout, err := c.tunnelAuthResponse(pkt)
			if err != nil {
				log.Printf("Cannot do tunnel auth due to %s", err)
				return err
			}
			log.Printf("Tunnel auth succesful. Flags: %d and timeout %d", flags, timeout)
			c.Session.TransportOut.WritePacket(c.channelRequest())
		case PKT_TYPE_CHANNEL_RESPONSE:
			cid, err := c.channelResponse(pkt)
			if err != nil {
				log.Printf("Cannot do tunnel auth due to %s", err)
				return err
			}
			if cid < 1 {
				log.Printf("Channel id (%d) is smaller than 1. This doesnt work for Windows clients", cid)
			}
			log.Printf("Channel creation succesful. Channel id: %d", cid)
			go forward(c.LocalConn, c.Session.TransportOut)
		case PKT_TYPE_DATA:
			receive(pkt, c.LocalConn)
		default:
			log.Printf("Unknown packet type received: %d size %d", pt, sz)
		}
	}
}

func (c *ClientConfig) handshakeRequest() []byte {
	var caps uint16

	if c.SmartCardAuth {
		caps = caps | HTTP_EXTENDED_AUTH_SC
	}

	if len(c.PAAToken) > 0 {
		caps = caps | HTTP_EXTENDED_AUTH_PAA
	}

	if c.NTLMAuth {
		caps = caps | HTTP_EXTENDED_AUTH_SSPI_NTLM
	}

	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, byte(MajorVersion))
	binary.Write(buf, binary.LittleEndian, byte(MinorVersion))
	binary.Write(buf, binary.LittleEndian, uint16(Version))

	binary.Write(buf, binary.LittleEndian, uint16(caps))

	return createPacket(PKT_TYPE_HANDSHAKE_REQUEST, buf.Bytes())
}

func (c *ClientConfig) handshakeResponse(data []byte) (caps uint16, err error) {
	var errorCode int32
	var major byte
	var minor byte
	var version uint16

	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &errorCode)
	binary.Read(r, binary.LittleEndian, &major)
	binary.Read(r, binary.LittleEndian, &minor)
	binary.Read(r, binary.LittleEndian, &version)
	binary.Read(r, binary.LittleEndian, &caps)

	if errorCode > 0 {
		return 0, fmt.Errorf("error code: %d", errorCode)
	}

	return caps, nil
}

func (c *ClientConfig) tunnelRequest() []byte {
	buf := new(bytes.Buffer)
	var caps uint32
	var size uint16
	var fields uint16

	if len(c.PAAToken) > 0 {
		fields = fields | HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE
	}

	caps = caps | HTTP_CAPABILITY_IDLE_TIMEOUT

	binary.Write(buf, binary.LittleEndian, caps)
	binary.Write(buf, binary.LittleEndian, fields)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved

	if len(c.PAAToken) > 0 {
		utf16Token := EncodeUTF16(c.PAAToken)
		size = uint16(len(utf16Token))
		binary.Write(buf, binary.LittleEndian, size)
		buf.Write(utf16Token)
	}

	return createPacket(PKT_TYPE_TUNNEL_CREATE, buf.Bytes())
}

func (c *ClientConfig) tunnelResponse(data []byte) (tunnelId uint32, caps uint32, err error) {
	var version uint16
	var errorCode uint32
	var fields uint16

	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &version)
	binary.Read(r, binary.LittleEndian, &errorCode)
	binary.Read(r, binary.LittleEndian, &fields)
	r.Seek(2, io.SeekCurrent)
	if (fields & HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID) == HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID {
		binary.Read(r, binary.LittleEndian, &tunnelId)
	}
	if (fields & HTTP_TUNNEL_RESPONSE_FIELD_CAPS) == HTTP_TUNNEL_RESPONSE_FIELD_CAPS {
		binary.Read(r, binary.LittleEndian, &caps)
	}

	if errorCode != 0 {
		err = fmt.Errorf("tunnel error %d", errorCode)
	}

	return
}

func (c *ClientConfig) tunnelAuthRequest() []byte {
	utf16name := EncodeUTF16(c.Name)
	size := uint16(len(utf16name))

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, size)
	buf.Write(utf16name)

	return createPacket(PKT_TYPE_TUNNEL_AUTH, buf.Bytes())
}

func (c *ClientConfig) tunnelAuthResponse(data []byte) (flags uint32, timeout uint32, err error) {
	var errorCode uint32
	var fields uint16

	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &errorCode)
	binary.Read(r, binary.LittleEndian, &fields)
	r.Seek(2, io.SeekCurrent)

	if (fields & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS) == HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS {
		binary.Read(r, binary.LittleEndian, &flags)
	}
	if (fields & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT) == HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT {
		binary.Read(r, binary.LittleEndian, &timeout)
	}

	if errorCode > 0 {
		return 0, 0, fmt.Errorf("tunnel auth error %d", errorCode)
	}

	return
}

func (c *ClientConfig) channelRequest() []byte {
	utf16server := EncodeUTF16(c.Server)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, []byte{0x01}) // amount of server names
	binary.Write(buf, binary.LittleEndian, []byte{0x00}) // amount of alternate server names (range 0-3)
	binary.Write(buf, binary.LittleEndian, uint16(c.Port))
	binary.Write(buf, binary.LittleEndian, uint16(3)) // protocol, must be 3

	binary.Write(buf, binary.LittleEndian, uint16(len(utf16server)))
	buf.Write(utf16server)

	return createPacket(PKT_TYPE_CHANNEL_CREATE, buf.Bytes())
}

func (c *ClientConfig) channelResponse(data []byte) (channelId uint32, err error) {
	var errorCode uint32
	var fields uint16

	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &errorCode)
	binary.Read(r, binary.LittleEndian, &fields)
	r.Seek(2, io.SeekCurrent)

	if (fields & HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID) == HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID {
		binary.Read(r, binary.LittleEndian, &channelId)
	}

	if errorCode > 0 {
		return 0, fmt.Errorf("channel response error %d", errorCode)
	}

	return channelId, nil
}
