package protocol

import (
	"net"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/transport"
)

const (
	CtxTunnel = "github.com/bolkedebruin/rdpgw/tunnel"
)

type Tunnel struct {
	// Id identifies the connection in the server
	Id string
	// The connection-id (RDG-ConnID) as reported by the client
	RDGId string
	// The underlying incoming transport being either websocket or legacy http
	// in case of websocket transportOut will equal transportIn
	transportIn transport.Transport
	// The underlying outgoing transport being either websocket or legacy http
	// in case of websocket transportOut will equal transportOut
	transportOut transport.Transport
	// The remote desktop server (rdp, vnc etc) the clients intends to connect to
	TargetServer string
	// The obtained client ip address
	RemoteAddr string
	// User
	User identity.Identity

	// rwc is the underlying connection to the remote desktop server.
	// It is of the type *net.TCPConn
	rwc net.Conn

	// BytesSent is the total amount of bytes sent by the server to the client minus tunnel overhead
	BytesSent int64

	// BytesReceived is the total amount of bytes received by the server from the client minus tunnel overhad
	BytesReceived int64

	// ConnectedOn is when the client connected to the server
	ConnectedOn time.Time

	// LastSeen is when the server received the last packet from the client
	LastSeen time.Time
}

type message struct {
	packetType int
	length     int
	msg        []byte
	err        error
}

// Write puts the packet on the transport and updates the statistics for bytes sent
func (t *Tunnel) Write(pkt []byte) {
	n, _ := t.transportOut.WritePacket(pkt)
	t.BytesSent += int64(n)
}

// Read picks up a packet from the transport and returns the packet type
// packet, with the header removed, and the packet size. It updates the
// statistics for bytes received
func (t *Tunnel) Read() ([]*message, error) {
	messages, err := readMessage(t.transportIn)
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		t.BytesReceived += int64(message.length)
		t.LastSeen = time.Now()
	}
	return messages, err
}
