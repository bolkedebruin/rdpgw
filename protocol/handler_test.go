package protocol

import (
	"fmt"
	"log"
	"testing"
)

const (
	HeaderLen = 8
	HandshakeRequestLen = HeaderLen + 6
	HandshakeResponseLen = HeaderLen + 10
	TunnelCreateRequestLen = HeaderLen + 8 // + dynamic
	TunnelCreateResponseLen = HeaderLen + 18
)

func verifyPacketHeader(data []byte , expPt uint16, expSize uint32) (uint16, uint32, []byte, error) {
	pt, size, pkt, err := readHeader(data)

	if pt != expPt {
		return 0,0, []byte{}, fmt.Errorf("readHeader failed, expected packet type %d got %d", expPt, pt)
	}

	if size != expSize {
		return 0, 0, []byte{}, fmt.Errorf("readHeader failed, expected size %d, got %d", expSize, size)
	}

	if err != nil {
		return 0, 0, []byte{}, err
	}

	return pt, size, pkt, nil
}

func TestHandshake(t *testing.T) {
	client := ClientConfig{
		PAAToken: "abab",
	}

	data := client.handshakeRequest()

	_, _, pkt, err := verifyPacketHeader(data, PKT_TYPE_HANDSHAKE_REQUEST, HandshakeRequestLen)

	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}

	log.Printf("pkt: %x", pkt)

	major, minor, version, extAuth := readHandshake(pkt)
	if major != MajorVersion || minor != MinorVersion || version != Version {
		t.Fatalf("readHandshake failed got version %d.%d protocol %d, expected %d.%d protocol %d",
			major, minor, version, MajorVersion, MinorVersion, Version)
	}

	if !((extAuth & HTTP_EXTENDED_AUTH_PAA) == HTTP_EXTENDED_AUTH_PAA) {
		t.Fatalf("readHandshake failed got ext auth %d, expected %d", extAuth, extAuth | HTTP_EXTENDED_AUTH_PAA)
	}

	s := &SessionInfo{}
	hc := &HandlerConf{
		TokenAuth: true,
	}

	h := NewHandler(s, hc)

	data = h.handshakeResponse(0x0, 0x0)
	_, _, pkt, err = verifyPacketHeader(data, PKT_TYPE_HANDSHAKE_RESPONSE, HandshakeResponseLen)
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}
	log.Printf("pkt: %x", pkt)

	caps, err := client.handshakeResponse(pkt)
	if !((caps & HTTP_EXTENDED_AUTH_PAA) == HTTP_EXTENDED_AUTH_PAA) {
		t.Fatalf("handshakeResponse failed got caps %d, expected %d", caps, caps | HTTP_EXTENDED_AUTH_PAA)
	}
}

func TestTunnelCreation(t *testing.T) {
	client := ClientConfig{
		PAAToken: "abab",
	}

	data := client.tunnelRequest()
	_, _, pkt, err := verifyPacketHeader(data, PKT_TYPE_TUNNEL_CREATE,
		uint32(TunnelCreateRequestLen + 2 + len(client.PAAToken)*2))
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}

	caps, token := readCreateTunnelRequest(pkt)
	if !((caps & HTTP_CAPABILITY_IDLE_TIMEOUT) == HTTP_CAPABILITY_IDLE_TIMEOUT) {
		t.Fatalf("readCreateTunnelRequest failed got caps %d, expected %d", caps, caps | HTTP_CAPABILITY_IDLE_TIMEOUT)
	}
	if token != client.PAAToken {
		t.Fatalf("readCreateTunnelRequest failed got token %s, expected %s", token, client.PAAToken)
	}

	data = createTunnelResponse()
	_, _, pkt, err = verifyPacketHeader(data, PKT_TYPE_TUNNEL_RESPONSE, TunnelCreateResponseLen)
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}

	tid, caps, err := client.tunnelResponse(pkt)
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	if tid != tunnelId {
		t.Fatalf("tunnelResponse failed tunnel id %d, expected %d", tid, tunnelId)
	}
	if !((caps & HTTP_CAPABILITY_IDLE_TIMEOUT) == HTTP_CAPABILITY_IDLE_TIMEOUT) {
		t.Fatalf("tunnelResponse failed got caps %d, expected %d", caps, caps | HTTP_CAPABILITY_IDLE_TIMEOUT)
	}
}