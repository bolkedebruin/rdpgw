package protocol

import "github.com/bolkedebruin/rdpgw/cmd/rdpgw/transport"

type packetReader struct {
	in      transport.Transport
	size    int
	pkt     []byte
	err     error
	readPtr int
}

func newTransportPacket(in transport.Transport) *packetReader {
	return &packetReader{in: in}
}

func (t *packetReader) hasMoreData() bool {
	return t.readPtr < t.size
}

func (t *packetReader) getPtr() []byte {
	return t.pkt[t.readPtr:]
}

func (t *packetReader) incrementPtr(size int) {
	t.readPtr += size
}

func (t *packetReader) read() error {
	size, pkt, err := t.in.ReadPacket()
	if err != nil {
		t.size = 0
	} else {
		t.size = size
	}
	t.pkt = pkt
	t.err = err
	t.readPtr = 0
	return err
}
