package protocol

import (
	"syscall"
)

// the fd arg to syscall.SetsockoptInt on Windows is of type syscall.Handle
func int64ToFd(n int64) syscall.Handle {
	return syscall.Handle(n)
}