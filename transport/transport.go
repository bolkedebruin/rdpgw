package transport

type HttpLayer interface {
	ReadPacket() (n int, p []byte, err error)
	WritePacket(b []byte) (n int, err error)
	Close() error
}

