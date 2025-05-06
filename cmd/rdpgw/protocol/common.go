package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/transport"
)

const (
	maxFragmentSize = 65536
)

type RedirectFlags struct {
	Clipboard  bool
	Port       bool
	Drive      bool
	Printer    bool
	Pnp        bool
	DisableAll bool
	EnableAll  bool
}

func handleMsgFrame(packet *packetReader) *message {
	pt, sz, msg, err := readHeader(packet.getPtr())
	if err == nil {
		packet.incrementPtr(int(sz))
		return &message{packetType: int(pt), length: int(sz), msg: msg, err: nil}
	}

	buf := make([]byte, maxFragmentSize)
	index := 0
	for {
		// keep parsing thfragment
		if len(packet.getPtr()) > len(buf[index:]) {
			return &message{packetType: int(pt), length: int(sz), msg: msg, err: fmt.Errorf("fragment exceeded max fragment size")}
		}
		index += copy(buf[index:], packet.getPtr())
		// Get a new frame
		err := packet.read()
		if err != nil {
			// Failed to make a msg
			return &message{packetType: int(pt), length: int(sz), msg: msg, err: err}
		}
		pt, sz, msg, err = readHeader(append(buf[:index], packet.getPtr()...))
		if err == nil {
			// the increment is based upon how much of the data we have used
			// in this packet. The index tells us how much is in the previous frame(s),
			// So we remove that from the size of the message.
			packet.incrementPtr(int(sz) - index)
			return &message{packetType: int(pt), length: int(sz), msg: msg, err: nil}
		}
	}
}

// readMessage parses and defragments a packet from a Transport. It returns
// at most the bytes that have been reported by the packet.
func readMessage(in transport.Transport) ([]*message, error) {
	messages := make([]*message, 0)

	packet := newTransportPacket(in)
	err := packet.read()
	if err != nil {
		return messages, err
	}

	var message *message
	for packet.hasMoreData() {
		message = handleMsgFrame(packet)
		messages = append(messages, message)
	}
	return messages, nil
}

// createPacket wraps the data into the protocol packet
func createPacket(pktType uint16, data []byte) (packet []byte) {
	size := len(data) + 8
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(pktType))
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(buf, binary.LittleEndian, uint32(size))
	buf.Write(data)

	return buf.Bytes()
}

// readHeader parses a packet and verifies its reported size
func readHeader(data []byte) (packetType uint16, size uint32, packet []byte, err error) {
	// header needs to be 8 min
	if len(data) < 8 {
		return 0, 0, nil, errors.New("header too short, fragment likely")
	}
	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &packetType)
	r.Seek(4, io.SeekStart)
	binary.Read(r, binary.LittleEndian, &size)
	if len(data) < int(size) {
		return packetType, size, data[8:], errors.New("data incomplete, fragment received")
	}
	return packetType, size, data[8:size], nil
}

// forwards data from a Connection to Transport and wraps it in the rdpgw protocol
func forward(in net.Conn, tunnel *Tunnel) {
	defer in.Close()

	b1 := new(bytes.Buffer)
	buf := make([]byte, 4086)

	for {
		n, err := in.Read(buf)
		if err != nil {
			log.Printf("Error reading from local conn %s", err)
			break
		}
		binary.Write(b1, binary.LittleEndian, uint16(n))
		b1.Write(buf[:n])
		tunnel.Write(createPacket(PKT_TYPE_DATA, b1.Bytes()))
		b1.Reset()
	}
}

// receive data received from the gateway client, unwrap and forward the remote desktop server
func receive(data []byte, out net.Conn) {
	buf := bytes.NewReader(data)

	var cblen uint16
	binary.Read(buf, binary.LittleEndian, &cblen)
	pkt := make([]byte, cblen)
	binary.Read(buf, binary.LittleEndian, &pkt)

	out.Write(pkt)
}

// wrapSyscallError takes an error and a syscall name. If the error is
// a syscall.Errno, it wraps it in a os.SyscallError using the syscall name.
func wrapSyscallError(name string, err error) error {
	if _, ok := err.(syscall.Errno); ok {
		err = os.NewSyscallError(name, err)
	}
	return err
}
