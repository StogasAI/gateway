//go:build !unix

package utils

import "net"

// connClosed cannot check a socket on this platform, so a pooled connection
// is used as fasthttp hands it out.
func connClosed(net.Conn) bool { return false }
