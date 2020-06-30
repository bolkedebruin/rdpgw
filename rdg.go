package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	crlf      = "\r\n"
	rdgConnectionIdKey = "Rdg-Connection-Id"
	HANDSHAKE = 1
)

const (
	PKT_TYPE_HANDSHAKE_REQUEST      = 0x1
	PKT_TYPE_HANDSHAKE_RESPONSE     = 0x2
	PKT_TYPE_EXTENDED_AUTH_MSG      = 0x3
	PKT_TYPE_TUNNEL_CREATE          = 0x4
	PKT_TYPE_TUNNEL_RESPONSE        = 0x5
	PKT_TYPE_TUNNEL_AUTH            = 0x6
	PKT_TYPE_TUNNEL_AUTH_RESPONSE   = 0x7
	PKT_TYPE_CHANNEL_CREATE         = 0x8
	PKT_TYPE_CHANNEL_RESPONSE       = 0x9
	PKT_TYPE_DATA                   = 0xA
	PKT_TYPE_SERVICE_MESSAGE        = 0xB
	PKT_TYPE_REAUTH_MESSAGE         = 0xC
	PKT_TYPE_KEEPALIVE              = 0xD
	PKT_TYPE_CLOSE_CHANNEL          = 0x10
	PKT_TYPE_CLOSE_CHANNEL_RESPONSE = 0x11
)

const (
	HTTP_EXTENDED_AUTH_NONE      = 0x0
	HTTP_EXTENDED_AUTH_SC        = 0x1  /* Smart card authentication. */
	HTTP_EXTENDED_AUTH_PAA       = 0x02 /* Pluggable authentication. */
	HTTP_EXTENDED_AUTH_SSPI_NTLM = 0x04 /* NTLM extended authentication. */
)

const (
	HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE = 0x1
)

// HandshakeHeader is the interface that writes both upgrade request or
// response headers into a given io.Writer.
type HandshakeHeader interface {
	io.WriterTo
}

type RdgSession struct {
	ConnId        string
	CorrelationId string
	UserId        string
	ConnIn        net.Conn
	ConnOut       net.Conn
	BufOut        *bufio.Writer
	BufIn         *bufio.Reader
	State         int
	Remote 		  net.Conn
}

// ErrNotHijacker is an error returned when http.ResponseWriter does not
// implement http.Hijacker interface.
var ErrNotHijacker = RejectConnectionError(
	RejectionStatus(http.StatusInternalServerError),
	RejectionReason("given http.ResponseWriter is not a http.Hijacker"),
)

var DefaultSession RdgSession

func Upgrade(next http.Handler) http.Handler {
	return DefaultSession.RdgHandshake(next)
}

func Accept(w http.ResponseWriter) (conn net.Conn, rw *bufio.ReadWriter, err error) {
		log.Print("Accept connection")
		hj, ok := w.(http.Hijacker)
		if ok {
			return hj.Hijack()
		} else {
			err = ErrNotHijacker
		}
		if err != nil {
			httpError(w, err.Error(), http.StatusInternalServerError)
			return nil, nil, err
		}
		return
}

func (s RdgSession) RdgHandshake(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*_, _, ok := r.BasicAuth()

		if !ok && s.ConnIn == nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="rdpgw"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized.\n"))
			fmt.Println("Unauthorized")
			return
		}*/

		conn, rw, _ := Accept(w)
		if r.Method == MethodRDGOUT {
			log.Printf("Opening RDGOUT for client %s", conn.RemoteAddr().String())
			s.ConnId = r.Header.Get(rdgConnectionIdKey)
			s.ConnOut = conn
			s.BufOut = rw.Writer
			WriteAcceptSeed(rw.Writer)
			rw.Writer.Flush()
		} else if r.Method == MethodRDGIN {
			if s.ConnIn == nil {
				s.ConnIn = conn
				s.BufIn = rw.Reader
				log.Printf("Opening RDGIN for client %s", conn.RemoteAddr().String())
				WriteAcceptSeed(rw.Writer)
				rw.Writer.Flush()
				p := make([]byte, 4096)
				rw.Reader.Read(p)
				//log.Printf("Read %q", p)

				log.Printf("Reading packet from client %s", conn.RemoteAddr().String())
				scanner := bufio.NewScanner(rw.Reader)
				scanner.Split(ReadPacket)
				for scanner.Scan() {
					packet := scanner.Bytes()
					packetType, size, _, packet := readHeader(packet)
					log.Printf("Scanned packet got packet type %x size %d", packetType, size)
					switch packetType {
					case PKT_TYPE_HANDSHAKE_REQUEST:
						major, minor, _, auth := readHandshake(packet)
						sendHandshakeResponse(s.BufOut, major, minor, auth)
					case PKT_TYPE_TUNNEL_CREATE:
						readCreateTunnelRequest(packet)
						sendCreateTunnelResponse(s.BufOut)
					case PKT_TYPE_TUNNEL_AUTH:
						readTunnelAuthRequest(packet)
						sendTunnelAuthResponse(s.BufOut)
					case PKT_TYPE_CHANNEL_CREATE:
						server, port := readChannelCreateRequest(packet)
						var err error
						s.Remote, err = net.Dial("tcp", "localhost:3389")
						if err != nil {
							log.Printf("Error connecting to %s, %d, %s", server, port, err)
							return
						}
						sendChannelCreateResponse(s.BufOut)
					case PKT_TYPE_DATA:
						receiveDataPacket(s.Remote, packet)
						go sendDataPacket(s.Remote, s.BufOut)
					}
				}
			}
		}
	})
}

// [MS-TSGU]: Terminal Services Gateway Server Protocol version 39.0
// The server sends back the final status code 200 OK, and also a random entity body of limited size (100 bytes).
// This enables a reverse proxy to start allowing data from the RDG server to the RDG client. The RDG server does
// not specify an entity length in its response. It uses HTTP 1.0 semantics to send the entity body and closes the
// connection after the last byte is sent.
func WriteAcceptSeed(bw *bufio.Writer) {
	bw.WriteString(HttpOK)
	bw.WriteString("Date: " + time.Now().Format(time.RFC1123) + "\r\n")
	bw.WriteString("Content-Type: application/octet-stream\r\n")
	bw.WriteString("Content-Length: 0\r\n")
	bw.WriteString(crlf)
	seed := make([]byte, 10)
	rand.Read(seed)
	bw.Write(seed)
}

func ReadPacket(data []byte, atEOF bool) (advance int, packet []byte, err error) {
	log.Printf("Reading data len = %d", len(data))
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	if i := bytes.Index(data, []byte{'\r', '\n'}); i >= 0 {
		//log.Printf("Got rn at %d ", i)
		chunkSize, err := strconv.ParseInt(string(data[0:i]), 16, 0)
		log.Printf("chunkSize %d", chunkSize)
		if err != nil {
			return i + 2, data[0:i], err
		}
		//log.Printf("Return %d", i+2+int(chunkSize)+2)
		return i + 2 + int(chunkSize) + 2, data[i+2 : i+2+int(chunkSize)+2], nil
	}

	if atEOF {
		return len(data), data, nil
	}

	return 0, nil, nil
}

func readHeader(data []byte) (packetType uint16, size uint32, advance int, remain []byte) {
	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &packetType)
	r.Seek(4, io.SeekStart)
	binary.Read(r, binary.LittleEndian, &size)
	return packetType, size, 8, data[8:]
}

func sendHandshakeResponse(w *bufio.Writer, major byte, minor byte, auth uint16) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // error_code
	buf.Write([]byte{major, minor})
	binary.Write(buf, binary.LittleEndian, uint16(0)) // server version
	binary.Write(buf, binary.LittleEndian, uint16(2)) // PAA

	w.Write(createPacket(PKT_TYPE_HANDSHAKE_RESPONSE, buf.Bytes()))
	w.Flush()
}

func readHandshake(data []byte) (major byte, minor byte, version uint16, extAuth uint16) {
	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &major)
	binary.Read(r, binary.LittleEndian, &minor)
	binary.Read(r, binary.LittleEndian, &version)
	binary.Read(r, binary.LittleEndian, &extAuth)

	log.Printf("major: %d, minor: %d, version: %d, ext auth: %d", major, minor, version, extAuth)
	return
}

func readCreateTunnelRequest(data []byte) (caps uint32, cookie string){
	var fields uint16

	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &caps)
	binary.Read(r, binary.LittleEndian, &fields)
	r.Seek(2, io.SeekCurrent)

	if fields == HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE {
		var size uint16
		binary.Read(r, binary.LittleEndian, &size)
		// skip decoding paa for now
	}
	log.Printf("Create tunnel caps: %d", caps)
	return
}

func sendCreateTunnelResponse(w *bufio.Writer) {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(0)) // server version
	binary.Write(buf, binary.LittleEndian, uint32(0)) // error code
	binary.Write(buf, binary.LittleEndian, uint16(0)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved

	w.Write(createPacket(PKT_TYPE_TUNNEL_RESPONSE, buf.Bytes()))
	w.Flush()
}

func readTunnelAuthRequest(data []byte) {
	buf := bytes.NewReader(data)

	var size uint16
	binary.Read(buf, binary.LittleEndian, &size)
	clData := make([]byte, size)
	binary.Read(buf, binary.LittleEndian, &clData)
	clientName, _ := DecodeUTF16(clData)
	log.Printf("Client: %s", clientName)
}

func sendTunnelAuthResponse(w *bufio.Writer) {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(0)) // error code
	binary.Write(buf, binary.LittleEndian, uint16(0)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved

	w.Write(createPacket(PKT_TYPE_TUNNEL_AUTH_RESPONSE, buf.Bytes()))
	w.Flush()
}

func readChannelCreateRequest(data []byte) (server string, port uint16){
	buf := bytes.NewReader(data)

	var resourcesSize byte
	var alternative byte
	var protocol uint16
	var nameSize uint16

	binary.Read(buf, binary.LittleEndian, &resourcesSize)
	binary.Read(buf, binary.LittleEndian, &alternative)
	binary.Read(buf, binary.LittleEndian, &port)
	binary.Read(buf, binary.LittleEndian, &protocol)
	binary.Read(buf, binary.LittleEndian, &nameSize)

	nameData := make([]byte, nameSize)
	binary.Read(buf, binary.LittleEndian, &nameData)

	log.Printf("Name data %q", nameData)
	server, _ = DecodeUTF16(nameData)

	log.Printf("Should connect to %s on port %d", server, port)
	return
}

func sendChannelCreateResponse(w *bufio.Writer) {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint32(0)) // error code
	binary.Write(buf, binary.LittleEndian, uint16(0)) // fields present
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved

	w.Write(createPacket(PKT_TYPE_CHANNEL_RESPONSE, buf.Bytes()))
	w.Flush()
}

func createPacket(pktType uint16, data []byte) (packet []byte){
	size := len(data) + 8
	buf := new(bytes.Buffer)

	log.Printf("Data sent Size: %d", size)
	// http chunk size in hex string
	// fmt.Fprintf(buf,"%x\r\n", size)

	binary.Write(buf, binary.LittleEndian, uint16(pktType))
	binary.Write(buf, binary.LittleEndian, uint16(0))  // reserved
	binary.Write(buf, binary.LittleEndian, uint32(size))
	buf.Write(data)

	// http close crlf
	// buf.Write([]byte(crlf))
	// log.Printf("data sent: %q", buf.Bytes())
	return buf.Bytes()
}

func receiveDataPacket(conn net.Conn, data []byte) {
	buf := bytes.NewReader(data)

	var cblen uint16
	binary.Read(buf, binary.LittleEndian, &cblen)
	log.Printf("Received PKT_DATA %d", cblen)
	pkt := make([]byte, cblen)
	//binary.Read(buf, binary.LittleEndian, &pkt)
	buf.Read(pkt)
	//log.Printf("DATA FROM CLIENT %q", pkt)
	conn.Write(pkt)
}

func sendDataPacket(conn net.Conn, w *bufio.Writer) {
	b1 := new(bytes.Buffer)
	buf := make([]byte, 32767)
	for {
		n, err := conn.Read(buf)
		binary.Write(b1, binary.LittleEndian, uint16(n))
		log.Printf("RDP SIZE: %d", n)
		if err != nil {
			log.Printf("Error reading from conn %s", err)
			break
		}
		b1.Write(buf[:n])
		w.Write(createPacket(PKT_TYPE_DATA, b1.Bytes()))
		w.Flush()
		b1.Reset()
	}
}

func DecodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		log.Printf("Error decoding utf16")
		return "", fmt.Errorf("Must have even length byte slice")
	}

	u16s := make([]uint16, 1)
	ret := &bytes.Buffer{}
	b8buf := make([]byte, 4)

	lb := len(b)
	for i := 0; i < lb; i += 2 {
		u16s[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		r := utf16.Decode(u16s)
		n := utf8.EncodeRune(b8buf, r[0])
		ret.Write(b8buf[:n])
	}

	return ret.String(), nil
}