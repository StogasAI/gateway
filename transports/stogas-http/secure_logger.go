package stogashttp

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const httpLogInterval = time.Minute

var httpLogLine = []byte("{\"event\":\"http_connection_error\",\"reasonCode\":\"request_parse_or_connection_failure\",\"severity\":\"warn\"}\n")

// The standard server's error text can contain peer addresses, request data
// and panic values. Discard it before writing one bounded fixed event.
type secureHTTPLogWriter struct {
	errors      atomic.Uint64
	mu          sync.Mutex
	nextAllowed time.Time
	now         func() time.Time
	output      io.Writer
}

func newSecureHTTPLogWriter(output io.Writer) *secureHTTPLogWriter {
	return &secureHTTPLogWriter{now: time.Now, output: output}
}

func (logger *secureHTTPLogWriter) Write(raw []byte) (int, error) {
	logger.errors.Add(1)
	logger.mu.Lock()
	defer logger.mu.Unlock()

	now := logger.now()
	if now.Before(logger.nextAllowed) {
		return len(raw), nil
	}
	logger.nextAllowed = now.Add(httpLogInterval)
	_, err := logger.output.Write(httpLogLine)
	return len(raw), err
}
