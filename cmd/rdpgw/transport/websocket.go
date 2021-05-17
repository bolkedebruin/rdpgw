package transport

import (
	"errors"
	"github.com/gorilla/websocket"
)

type WSPKT struct {
	Conn *websocket.Conn
}

func NewWS(c *websocket.Conn) (*WSPKT, error) {
	w := &WSPKT{Conn: c}
	return w, nil
}

func (t *WSPKT) ReadPacket() (n int, b []byte, err error) {
	mt, msg, err := t.Conn.ReadMessage()
	if err != nil {
		return 0, []byte{0, 0}, err
	}

	if mt == websocket.BinaryMessage {
		return len(msg), msg, nil
	}

	return len(msg), msg, errors.New("not a binary packet")
}

func (t *WSPKT) WritePacket(b []byte) (n int, err error) {
	err = t.Conn.WriteMessage(websocket.BinaryMessage, b)

	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (t *WSPKT) Close() error {
	return t.Conn.Close()
}