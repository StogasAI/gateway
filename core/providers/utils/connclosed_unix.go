//go:build unix

package utils

import (
	"net"
	"syscall"
)

// connClosed reports whether the peer closed or reset a pooled connection, or
// sent data on it, while it sat idle. Any of these leaves it unusable. It reads
// one byte from the socket without waiting, as urllib3 checks a pooled
// connection and go-sql-driver/mysql checks one before reuse. A byte that it
// consumes is lost with the connection, which is closed anyway. A TLS
// connection is checked below TLS, where a close_notify alert counts as data.
func connClosed(conn net.Conn) bool {
	if tlsConn, ok := conn.(interface{ NetConn() net.Conn }); ok {
		conn = tlsConn.NetConn()
	}
	socket, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return true
	}
	closed := true
	if err := raw.Read(func(fd uintptr) bool {
		var b [1]byte
		// The runtime keeps sockets non-blocking, so an idle one reports EAGAIN.
		_, err := syscall.Read(int(fd), b[:])
		closed = err != syscall.EAGAIN && err != syscall.EWOULDBLOCK
		return true
	}); err != nil {
		return true
	}
	return closed
}
