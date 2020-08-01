package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/bolkedebruin/rdpgw/transport"
	"io"
	"log"
	"net"
)

func createPacket(pktType uint16, data []byte) (packet []byte) {
	size := len(data) + 8
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(pktType))
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(buf, binary.LittleEndian, uint32(size))
	buf.Write(data)

	return buf.Bytes()
}

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
	return packetType, size, data[8:], nil
}

// sends data wrapped inside the rdpgw protocol
func forward(in net.Conn, out transport.Transport) {
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
		out.WritePacket(createPacket(PKT_TYPE_DATA, b1.Bytes()))
		b1.Reset()
	}
}

// receive data from the wire, unwrap and forward to the client
func receive(data []byte, out net.Conn) {
	buf := bytes.NewReader(data)

	var cblen uint16
	binary.Read(buf, binary.LittleEndian, &cblen)
	pkt := make([]byte, cblen)
	binary.Read(buf, binary.LittleEndian, &pkt)

	out.Write(pkt)
}

