// +build windows

package protocol

import (
	"errors"
	"net"
	"reflect"
	"syscall"
)

func (g *Gateway) setSendReceiveBuffers(conn net.Conn) error {
	if g.SendBuf < 1 && g.ReceiveBuf < 1 {
		return nil
	}

	// conn == tls.Tunnel
	ptr := reflect.ValueOf(conn)
	val := reflect.Indirect(ptr)

	if val.Kind() != reflect.Struct {
		return errors.New("didn't get a struct from conn")
	}

	// this gets net.Tunnel -> *net.TCPConn -> net.TCPConn
	ptrConn := val.FieldByName("conn")
	valConn := reflect.Indirect(ptrConn)
	if !valConn.IsValid() {
		return errors.New("cannot find conn field")
	}
	valConn = valConn.Elem().Elem()

	// net.FD
	ptrNetFd := valConn.FieldByName("fd")
	valNetFd := reflect.Indirect(ptrNetFd)
	if !valNetFd.IsValid() {
		return errors.New("cannot find fd field")
	}

	// pfd member
	ptrPfd := valNetFd.FieldByName("pfd")
	valPfd := reflect.Indirect(ptrPfd)
	if !valPfd.IsValid() {
		return errors.New("cannot find pfd field")
	}

	// finally the exported Sysfd
	ptrSysFd := valPfd.FieldByName("Sysfd")
	if !ptrSysFd.IsValid() {
		return errors.New("cannot find Sysfd field")
	}
	fd := int(ptrSysFd.Int())

	if g.ReceiveBuf > 0 {
		err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, g.ReceiveBuf)
		if err != nil {
			return wrapSyscallError("setsockopt", err)
		}
	}

	if g.SendBuf > 0 {
		err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, g.SendBuf)
		if err != nil {
			return wrapSyscallError("setsockopt", err)
		}
	}

	return nil
}
