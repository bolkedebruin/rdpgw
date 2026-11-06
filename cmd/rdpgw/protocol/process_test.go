package protocol

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// When Process returns, the connection to the RDP server must be closed,
// otherwise the server keeps waiting on it (e.g. after the client closes a
// probe channel before the RDP connection sequence is complete).
func TestProcessClosesServerConn(t *testing.T) {
	cases := map[string]struct {
		packets [][]byte
		wantErr bool
	}{
		"close channel": {packets: [][]byte{createPacket(PKT_TYPE_CLOSE_CHANNEL, make([]byte, 4))}},
		// transportMock fails the read once it has no packets left
		"read error": {wantErr: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			server, gateway := net.Pipe()
			defer server.Close()
			in := newTransportMock()
			for _, b := range c.packets {
				p := newPacketMock()
				p.addBytes(b)
				in.addPacket(p)
			}
			tunnel := &Tunnel{transportIn: in, transportOut: in, rwc: gateway}
			h := NewProcessor(&Gateway{}, tunnel)
			h.state = SERVER_STATE_OPENED

			err := h.Process(context.Background())
			if c.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			server.SetReadDeadline(time.Now().Add(time.Second))
			_, err = server.Read(make([]byte, 1))
			assert.ErrorIs(t, err, io.EOF)
		})
	}
}
