// Package http2health closes outbound HTTP/2 connections that stop answering.
package http2health

import (
	"net/http"
	"time"
)

const (
	// A connection that has received nothing for this long is sent a ping.
	quietTime = 5 * time.Second
	// Servers answer a ping before other frames (RFC 9113, section 6.7), so a
	// live server answers within one round trip. Five seconds is several times
	// the slowest one, about 0.6 seconds over a geostationary satellite, and
	// leaves time for TCP to resend a lost packet.
	answerTime = 5 * time.Second
)

// Config is for every pooled HTTP/2 client. After a request on an HTTP/2
// connection times out, Go keeps the connection and sends new requests over it
// until timed-out requests fill the server's stream limit. Without a health
// check, a connection that stopped answering takes retries and later requests
// until the kernel gives up on it, about 15 minutes later
// (https://go.dev/issue/59690). With the check, it closes within ten seconds
// of its last frame, so a retry of an export delivery, which waits ten seconds
// for an answer, always gets a new connection.
func Config() *http.HTTP2Config {
	return &http.HTTP2Config{SendPingTimeout: quietTime, PingTimeout: answerTime}
}
