package transport

import (
	"bufio"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

const (
	crlf               = "\r\n"
	HttpOK = "HTTP/1.1 200 OK\r\n"
)

type LegacyPKT struct {
	Conn net.Conn
	ChunkedReader io.Reader
	Writer *bufio.Writer
}

func NewLegacy(w http.ResponseWriter) (*LegacyPKT, error) {
	hj, ok := w.(http.Hijacker)
	if ok {
		conn, rw, err := hj.Hijack()
		l := &LegacyPKT{
			Conn: conn,
			ChunkedReader: httputil.NewChunkedReader(rw.Reader),
			Writer: rw.Writer,
		}
		return l, err
	}

	return nil, errors.New("cannot hijack connection")
}

func (t *LegacyPKT) ReadPacket() (n int, p []byte, err error){
	buf := make([]byte, 4096) // bufio.defaultBufSize
	n, err = t.ChunkedReader.Read(buf)
	p = make([]byte, n)
	copy(p, buf)

	return n, p, err
}

func (t *LegacyPKT) WritePacket(b []byte) (n int, err error) {
	return t.Conn.Write(b)
}

func (t *LegacyPKT) Close() error {
	return t.Conn.Close()
}

// [MS-TSGU]: Terminal Services Gateway Server Protocol version 39.0
// The server sends back the final status code 200 OK, and also a random entity body of limited size (100 bytes).
// This enables a reverse proxy to start allowing data from the RDG server to the RDG client. The RDG server does
// not specify an entity length in its response. It uses HTTP 1.0 semantics to send the entity body and closes the
// connection after the last byte is sent.
func (t *LegacyPKT) SendAccept(doSeed bool) {
	t.Writer.WriteString(HttpOK)
	t.Writer.WriteString("Date: " + time.Now().Format(time.RFC1123) + crlf)
	if !doSeed {
		t.Writer.WriteString("Content-Length: 0" + crlf)
	}
	t.Writer.WriteString(crlf)

	if doSeed {
		seed := make([]byte, 10)
		rand.Read(seed)
		// docs say it's a seed but 2019 responds with ab cd * 5
		t.Writer.Write(seed)
	}
	t.Writer.Flush()
}

func (t *LegacyPKT) Drain() {
	p := make([]byte, 32767)
	t.Conn.Read(p)
}
