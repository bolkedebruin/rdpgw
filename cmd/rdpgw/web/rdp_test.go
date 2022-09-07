package web

import (
	"log"
	"strings"
	"testing"
)

const (
	GatewayHostName = "my.yahoo.com"
)

func TestRdpBuilder(t *testing.T) {
	builder := NewRdp()
	builder.Connection.GatewayHostname = "my.yahoo.com"
	builder.Session.AutoReconnectionEnabled = true
	builder.Display.SmartSizing = true

	s := builder.String()
	if !strings.Contains(s, "gatewayhostname:s:"+GatewayHostName+crlf) {
		t.Fatalf("%s does not contain `gatewayhostname:s:%s", s, GatewayHostName)
	}
	if strings.Contains(s, "autoreconnectionenabled") {
		t.Fatalf("autoreconnectionenabled is in %s, but is default value", s)
	}
	if !strings.Contains(s, "smart sizing:i:1"+crlf) {
		t.Fatalf("%s does not contain smart sizing:i:1", s)

	}
	log.Printf(builder.String())
}

func TestInitStruct(t *testing.T) {
	conn := RdpConnection{}
	initStruct(&conn)

	if conn.PromptCredentialsOnce != true {
		t.Fatalf("conn.PromptCredentialsOnce != true")
	}
}
