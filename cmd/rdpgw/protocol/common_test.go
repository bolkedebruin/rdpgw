package protocol

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

type messageMock struct {
	buffer    []byte
	msgBuffer []byte
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randBytes(message []byte) {
	for index := range message {
		message[index] = letterBytes[rand.Intn(len(letterBytes))]
	}
}

func newMessageMock(packetType uint16, message []byte) *messageMock {
	randBytes(message)
	buf := createPacket(packetType, message)
	return &messageMock{msgBuffer: buf[8:], buffer: buf}
}

type packetMock struct {
	bytes []byte
	err   error
}

func newPacketMock() *packetMock {
	return &packetMock{bytes: make([]byte, 0)}
}

func (p *packetMock) addBytes(b []byte) {
	p.bytes = append(p.bytes, b...)
}

func (p *packetMock) GetPacket() (int, []byte, error) {
	return len(p.bytes), p.bytes, p.err
}

type transportMock struct {
	lock      sync.Mutex
	packets   []*packetMock
	packetPtr int
}

func newTransportMock() *transportMock {
	return &transportMock{packets: make([]*packetMock, 0)}
}

func (t *transportMock) addPacket(p *packetMock) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.packets = append(t.packets, p)
}

func (t *transportMock) ReadPacket() (n int, p []byte, err error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.packetPtr >= len(t.packets) {
		return 0, nil, fmt.Errorf("no packets available")
	}
	packet := t.packets[t.packetPtr]
	t.packetPtr++
	return packet.GetPacket()
}

func (t *transportMock) WritePacket(b []byte) (n int, err error) {
	return 0, fmt.Errorf("not tested")
}

func (t *transportMock) Close() error {
	return nil
}

func TestSimplePacket(t *testing.T) {
	transport := newTransportMock()
	m := newMessageMock(6, make([]byte, 10))
	p := newPacketMock()
	p.addBytes(m.buffer)
	transport.addPacket(p)

	messages, err := readMessage(transport)
	assert.Nil(t, err)
	assert.NotNil(t, messages)
	assert.Len(t, messages, 1)
	assert.Equal(t, 6, messages[0].packetType)
	assert.Equal(t, 18, messages[0].length)
	assert.Equal(t, m.msgBuffer, messages[0].msg)
}

func TestMultiMessageInPacket(t *testing.T) {
	transport := newTransportMock()
	p := newPacketMock()

	m := newMessageMock(6, make([]byte, 10))
	p.addBytes(m.buffer)

	m2 := newMessageMock(8, make([]byte, 12))
	p.addBytes(m2.buffer)

	m3 := newMessageMock(8, make([]byte, 12))
	p.addBytes(m3.buffer)

	transport.addPacket(p)

	messages, err := readMessage(transport)
	assert.Nil(t, err)
	assert.NotNil(t, messages)
	assert.Len(t, messages, 3)
	assert.Nil(t, messages[0].err)
	assert.Equal(t, 6, messages[0].packetType)
	assert.Equal(t, 18, messages[0].length)
	assert.Equal(t, m.msgBuffer, messages[0].msg)

	assert.Nil(t, messages[1].err)
	assert.Equal(t, 8, messages[1].packetType)
	assert.Equal(t, 20, messages[1].length)
	assert.Equal(t, m2.msgBuffer, messages[1].msg)

	assert.Nil(t, messages[2].err)
	assert.Equal(t, 8, messages[2].packetType)
	assert.Equal(t, 20, messages[2].length)
	assert.Equal(t, m3.msgBuffer, messages[2].msg)
}

func TestFragment(t *testing.T) {
	transport := newTransportMock()
	p1 := newPacketMock()
	p2 := newPacketMock()

	m := newMessageMock(6, make([]byte, 100))
	// split the message across 2 packets
	p1.addBytes(m.buffer[0:50])
	p2.addBytes(m.buffer[50:])
	transport.addPacket(p1)
	transport.addPacket(p2)

	messages, err := readMessage(transport)
	assert.Nil(t, err)
	assert.NotNil(t, messages)
	assert.Len(t, messages, 1)
	assert.Equal(t, 6, messages[0].packetType)
	assert.Equal(t, 108, messages[0].length)
	assert.Equal(t, m.msgBuffer, messages[0].msg)

	_, err = readMessage(transport)
	// no more packets
	assert.NotNil(t, err)
}

func TestDroppedBytes(t *testing.T) {
	transport := newTransportMock()
	p1 := newPacketMock()

	m := newMessageMock(6, make([]byte, 100))
	// add only partial bytes
	p1.addBytes(m.buffer[0:50])
	transport.addPacket(p1)

	messages, err := readMessage(transport)
	assert.Nil(t, err)
	assert.Len(t, messages, 1)
	assert.NotNil(t, messages[0].err)

	_, err = readMessage(transport)
	// no more packets
	assert.NotNil(t, err)
}

func TestTooMuchData(t *testing.T) {
	transport := newTransportMock()
	p1 := newPacketMock()

	m := newMessageMock(6, make([]byte, 100))
	// add only partial bytes
	p1.addBytes(m.buffer)
	p1.addBytes([]byte{0, 0, 0})
	// add some junk bytes
	transport.addPacket(p1)

	messages, err := readMessage(transport)
	assert.Nil(t, err)
	assert.NotNil(t, messages)
	assert.Len(t, messages, 2)
	assert.Nil(t, messages[0].err)
	assert.NotNil(t, messages[1].err)

	_, err = readMessage(transport)
	// no more packets
	assert.NotNil(t, err)
}

func TestJumbo(t *testing.T) {
	transport := newTransportMock()
	p1 := newPacketMock()
	p2 := newPacketMock()

	m := newMessageMock(6, make([]byte, maxFragmentSize))
	// add only partial bytes
	p1.addBytes(m.buffer[0 : maxFragmentSize/2])
	p2.addBytes(m.buffer[maxFragmentSize/2:])
	// add some junk bytes
	transport.addPacket(p1)
	transport.addPacket(p2)

	messages, err := readMessage(transport)
	assert.Nil(t, err)
	assert.NotNil(t, messages)
	assert.Len(t, messages, 1)
	assert.Equal(t, m.msgBuffer, messages[0].msg)
}

func TestManyFragments(t *testing.T) {
	transport := newTransportMock()

	m := newMessageMock(6, make([]byte, 256))
	fragmentSize := len(m.buffer) / 5
	bufferSize := len(m.buffer)
	for fragPtr := 0; fragPtr < len(m.buffer); fragPtr += fragmentSize {
		p := newPacketMock()
		p.addBytes(m.buffer[fragPtr:min(bufferSize, fragPtr+fragmentSize)])
		transport.addPacket(p)
	}

	messages, err := readMessage(transport)
	assert.Nil(t, err)
	assert.NotNil(t, messages)
	assert.Len(t, messages, 1)
	assert.Nil(t, messages[0].err)
	assert.Equal(t, m.msgBuffer, messages[0].msg)

	messages, err = readMessage(transport)
	// no more packets
	fmt.Println(messages)
	assert.NotNil(t, err)
}

func TestFragmentTooLarge(t *testing.T) {
	transport := newTransportMock()

	m := newMessageMock(6, make([]byte, maxFragmentSize*2))
	fragmentSize := len(m.buffer) / 5
	bufferSize := len(m.buffer)
	for fragPtr := 0; fragPtr < len(m.buffer); fragPtr += fragmentSize {
		p := newPacketMock()
		p.addBytes(m.buffer[fragPtr:min(bufferSize, fragPtr+fragmentSize)])
		transport.addPacket(p)
	}

	messages, err := readMessage(transport)
	assert.Nil(t, err)
	assert.NotNil(t, messages[0].err)
	assert.Contains(t, "fragment exceeded max fragment size", messages[0].err.Error())
}

// TestReadHeaderRejectsUndersizedSize checks that readHeader rejects a
// declared size smaller than the 8-byte header itself. The reported size is
// taken from the wire, so an attacker-supplied frame with size in [0,7] must
// surface as an error rather than slicing data[8:size] with high < low.
func TestReadHeaderRejectsUndersizedSize(t *testing.T) {
	for _, size := range []uint32{0, 1, 2, 7} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			buf := make([]byte, 8)
			binary.LittleEndian.PutUint16(buf[0:2], 1)
			binary.LittleEndian.PutUint32(buf[4:8], size)

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("readHeader panicked on size=%d: %v", size, r)
				}
			}()
			_, _, _, err := readHeader(buf)
			if err == nil {
				t.Errorf("readHeader returned no error for invalid size=%d", size)
			}
		})
	}
}

// TestFragmentWithMultiMessage the first message is fragmented,
// while the second message is found whole in the final packet
func TestFragmentWithMultiMessage(t *testing.T) {
	transport := newTransportMock()
	p1 := newPacketMock()
	p2 := newPacketMock()

	m1 := newMessageMock(6, make([]byte, 100))
	m2 := newMessageMock(6, make([]byte, 10))
	// split the message across 2 packets
	p1.addBytes(m1.buffer[0:50])
	p2.addBytes(m1.buffer[50:])
	p2.addBytes(m2.buffer)
	transport.addPacket(p1)
	transport.addPacket(p2)

	messages, err := readMessage(transport)
	assert.Nil(t, err)
	assert.NotNil(t, messages)
	assert.Len(t, messages, 2)
	assert.Equal(t, 6, messages[0].packetType)
	assert.Equal(t, 108, messages[0].length)
	assert.Equal(t, m1.msgBuffer, messages[0].msg)

	assert.Equal(t, 6, messages[1].packetType)
	assert.Equal(t, 18, messages[1].length)
	assert.Equal(t, m2.msgBuffer, messages[1].msg)

	_, err = readMessage(transport)
	// no more packets
	assert.NotNil(t, err)
}
