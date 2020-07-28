package protocol

import (
	"bytes"
	"encoding/binary"
)

const (
	MajorVersion = 0x0
	MinorVersion = 0x0
	Version      = 0x00
)

type ClientConfig struct {
	SmartCardAuth bool
	PAAToken	  string
	NTLMAuth	  bool
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

func (c *ClientConfig) readServerHandshakeResponse(data []byte) ()
