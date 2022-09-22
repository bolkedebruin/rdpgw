package protocol

import (
	"fmt"
	"log"
	"testing"
)

const (
	HeaderLen               = 8
	HandshakeRequestLen     = HeaderLen + 6
	HandshakeResponseLen    = HeaderLen + 10
	TunnelCreateRequestLen  = HeaderLen + 8 // + dynamic
	TunnelCreateResponseLen = HeaderLen + 18
	TunnelAuthLen           = HeaderLen + 2 // + dynamic
	TunnelAuthResponseLen   = HeaderLen + 16
	ChannelCreateLen        = HeaderLen + 8 // + dynamic
	ChannelResponseLen      = HeaderLen + 12
)

func verifyPacketHeader(data []byte, expPt uint16, expSize uint32) (uint16, uint32, []byte, error) {
	pt, size, pkt, err := readHeader(data)

	if pt != expPt {
		return 0, 0, []byte{}, fmt.Errorf("readHeader failed, expected packet type %d got %d", expPt, pt)
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
	s := &SessionInfo{}
	hc := &ProcessorConf{
		TokenAuth: true,
	}
	h := NewProcessor(s, hc)

	data := client.handshakeRequest()

	_, _, pkt, err := verifyPacketHeader(data, PKT_TYPE_HANDSHAKE_REQUEST, HandshakeRequestLen)

	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}

	log.Printf("pkt: %x", pkt)

	major, minor, version, extAuth := h.handshakeRequest(pkt)
	if major != MajorVersion || minor != MinorVersion || version != Version {
		t.Fatalf("handshakeRequest failed got version %d.%d protocol %d, expected %d.%d protocol %d",
			major, minor, version, MajorVersion, MinorVersion, Version)
	}

	if !((extAuth & HTTP_EXTENDED_AUTH_PAA) == HTTP_EXTENDED_AUTH_PAA) {
		t.Fatalf("handshakeRequest failed got ext auth %d, expected %d", extAuth, extAuth|HTTP_EXTENDED_AUTH_PAA)
	}

	data = h.handshakeResponse(0x0, 0x0, HTTP_EXTENDED_AUTH_PAA, ERROR_SUCCESS)
	_, _, pkt, err = verifyPacketHeader(data, PKT_TYPE_HANDSHAKE_RESPONSE, HandshakeResponseLen)
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}
	log.Printf("pkt: %x", pkt)

	caps, err := client.handshakeResponse(pkt)
	if !((caps & HTTP_EXTENDED_AUTH_PAA) == HTTP_EXTENDED_AUTH_PAA) {
		t.Fatalf("handshakeResponse failed got caps %d, expected %d", caps, caps|HTTP_EXTENDED_AUTH_PAA)
	}
}

func capsHelper(h Processor) uint16 {
	var caps uint16
	if h.TokenAuth {
		caps = caps | HTTP_EXTENDED_AUTH_PAA
	}
	if h.SmartCardAuth {
		caps = caps | HTTP_EXTENDED_AUTH_SC
	}
	return caps
}

func TestMatchAuth(t *testing.T) {
	s := &SessionInfo{}
	hc := &ProcessorConf{
		TokenAuth:     false,
		SmartCardAuth: false,
	}

	h := NewProcessor(s, hc)

	in := uint16(0)
	caps, err := h.matchAuth(in)
	if err != nil {
		t.Fatalf("in caps: %x <= server caps %x, but %s", in, capsHelper(*h), err)
	}
	if caps > in {
		t.Fatalf("returned server caps %x > client cpas %x", capsHelper(*h), in)
	}

	in = HTTP_EXTENDED_AUTH_PAA
	caps, err = h.matchAuth(in)
	if err == nil {
		t.Fatalf("server cannot satisfy client caps %x but error is nil (server caps %x)", in, caps)
	} else {
		t.Logf("(SUCCESS) server cannot satisfy client caps : %s", err)
	}

	h.SmartCardAuth = true
	caps, err = h.matchAuth(in)
	if err == nil {
		t.Fatalf("server cannot satisfy client caps %x but error is nil (server caps %x)", in, caps)
	} else {
		t.Logf("(SUCCESS) server cannot satisfy client caps : %s", err)
	}

	h.TokenAuth = true
	caps, err = h.matchAuth(in)
	if err != nil {
		t.Fatalf("server caps %x (orig: %x) should match client request %x, %s", caps, capsHelper(*h), in, err)
	}
}

func TestTunnelCreation(t *testing.T) {
	client := ClientConfig{
		PAAToken: "abab",
	}
	s := &SessionInfo{}
	hc := &ProcessorConf{
		TokenAuth: true,
	}
	h := NewProcessor(s, hc)

	data := client.tunnelRequest()
	_, _, pkt, err := verifyPacketHeader(data, PKT_TYPE_TUNNEL_CREATE,
		uint32(TunnelCreateRequestLen+2+len(client.PAAToken)*2))
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}

	caps, token := h.tunnelRequest(pkt)
	if !((caps & HTTP_CAPABILITY_IDLE_TIMEOUT) == HTTP_CAPABILITY_IDLE_TIMEOUT) {
		t.Fatalf("tunnelRequest failed got caps %d, expected %d", caps, caps|HTTP_CAPABILITY_IDLE_TIMEOUT)
	}
	if token != client.PAAToken {
		t.Fatalf("tunnelRequest failed got token %s, expected %s", token, client.PAAToken)
	}

	data = h.tunnelResponse(ERROR_SUCCESS)
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
		t.Fatalf("tunnelResponse failed got caps %d, expected %d", caps, caps|HTTP_CAPABILITY_IDLE_TIMEOUT)
	}
}

func TestTunnelAuth(t *testing.T) {
	name := "test_name"
	client := ClientConfig{
		Name: name,
	}
	s := &SessionInfo{}
	hc := &ProcessorConf{
		TokenAuth:   true,
		IdleTimeout: 10,
		RedirectFlags: RedirectFlags{
			Clipboard: true,
		},
	}
	h := NewProcessor(s, hc)

	data := client.tunnelAuthRequest()
	_, _, pkt, err := verifyPacketHeader(data, PKT_TYPE_TUNNEL_AUTH, uint32(TunnelAuthLen+len(name)*2))
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}

	n := h.tunnelAuthRequest(pkt)
	if n != name {
		t.Fatalf("tunnelAuthRequest failed got name %s, expected %s", n, name)
	}

	data = h.tunnelAuthResponse(ERROR_SUCCESS)
	_, _, pkt, err = verifyPacketHeader(data, PKT_TYPE_TUNNEL_AUTH_RESPONSE, TunnelAuthResponseLen)
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}
	flags, timeout, err := client.tunnelAuthResponse(pkt)
	if err != nil {
		t.Fatalf("tunnel auth error %s", err)
	}
	if (flags & HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD) == HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD {
		t.Fatalf("tunnelAuthResponse failed got flags %d, expected %d",
			flags, flags|HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD)
	}
	if int(timeout) != hc.IdleTimeout {
		t.Fatalf("tunnelAuthResponse failed got timeout %d, expected %d",
			timeout, hc.IdleTimeout)
	}
}

func TestChannelCreation(t *testing.T) {
	server := "test_server"
	client := ClientConfig{
		Server: server,
		Port:   3389,
	}
	s := &SessionInfo{}
	hc := &ProcessorConf{
		TokenAuth:   true,
		IdleTimeout: 10,
		RedirectFlags: RedirectFlags{
			Clipboard: true,
		},
	}
	h := NewProcessor(s, hc)

	data := client.channelRequest()
	_, _, pkt, err := verifyPacketHeader(data, PKT_TYPE_CHANNEL_CREATE, uint32(ChannelCreateLen+len(server)*2))
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}
	hServer, hPort := h.channelRequest(pkt)
	if hServer != server {
		t.Fatalf("channelRequest failed got server %s, expected %s", hServer, server)
	}
	if int(hPort) != client.Port {
		t.Fatalf("channelRequest failed got port %d, expected %d", hPort, client.Port)
	}

	data = h.channelResponse(ERROR_SUCCESS)
	_, _, pkt, err = verifyPacketHeader(data, PKT_TYPE_CHANNEL_RESPONSE, uint32(ChannelResponseLen))
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}
	channelId, err := client.channelResponse(pkt)
	if err != nil {
		t.Fatalf("channelResponse failed: %s", err)
	}
	if channelId < 1 {
		t.Fatalf("channelResponse failed got channeld id %d, expected > 0", channelId)
	}
}
