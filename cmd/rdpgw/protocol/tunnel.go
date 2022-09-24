package protocol

import (
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/transport"
	"net"
	"time"
)

type Tunnel struct {
	// The connection-id (RDG-ConnID) as reported by the client
	RDGId string
	// The underlying incoming transport being either websocket or legacy http
	// in case of websocket TransportOut will equal TransportIn
	TransportIn transport.Transport
	// The underlying outgoing transport being either websocket or legacy http
	// in case of websocket TransportOut will equal TransportOut
	TransportOut transport.Transport
	// The remote desktop server (rdp, vnc etc) the clients intends to connect to
	TargetServer string
	// The obtained client ip address
	RemoteAddr string
	// User
	UserName string

	// rwc is the underlying connection to the remote desktop server.
	// It is of the type *net.TCPConn
	rwc net.Conn

	ByteSent      int64
	BytesReceived int64

	ConnectedOn time.Time
	LastSeen    time.Time
}

func (t *Tunnel) Write(pkt []byte) {
	n, _ := t.TransportOut.WritePacket(pkt)
	t.ByteSent += int64(n)
}

func (t *Tunnel) Read() (pt int, size int, pkt []byte, err error) {
	pt, size, pkt, err = readMessage(t.TransportIn)
	t.BytesReceived += int64(size)
	t.LastSeen = time.Now()

	return pt, size, pkt, err
}
