package protocol

import (
	"log"
	"testing"
)

const (
	HeaderLen = 8
	HandshakeRequestLen = HeaderLen + 6
)

func TestHandshake(t *testing.T) {
	client := ClientConfig{
		PAAToken: "abab",
	}

	data := client.handshakeRequest()
	pt, size, pkt, err := readHeader(data)

	if pt != PKT_TYPE_HANDSHAKE_REQUEST {
		t.Fatalf("readHeader failed, expected packet type %d got %d", PKT_TYPE_HANDSHAKE_REQUEST, pt)
	}

	if size != HandshakeRequestLen {
		t.Fatalf("readHeader failed, expected size %d, got %d", HandshakeRequestLen, size)
	}

	if err != nil {
		t.Fatalf("readHeader failed got error %s", err)
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
}
