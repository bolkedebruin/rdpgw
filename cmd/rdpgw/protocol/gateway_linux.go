package protocol

// the fd arg to syscall.SetsockoptInt on Linix is of type int
func int64ToFd(n int64) int {
	return int(n)
}
