package stogashttp

import (
	"io"
	"sync"
	"time"
)

const fastHTTPLogInterval = time.Minute

var fastHTTPLogLine = []byte("{\"event\":\"http_connection_error\",\"reasonCode\":\"request_parse_or_connection_failure\",\"severity\":\"warn\"}\n")

// secureFastHTTPLogger drops fasthttp's format string and arguments because
// parser errors can contain raw request bytes and peer addresses.
type secureFastHTTPLogger struct {
	mu          sync.Mutex
	nextAllowed time.Time
	now         func() time.Time
	output      io.Writer
}

func newSecureFastHTTPLogger(output io.Writer) *secureFastHTTPLogger {
	return &secureFastHTTPLogger{now: time.Now, output: output}
}

func (logger *secureFastHTTPLogger) Printf(_ string, _ ...any) {
	logger.mu.Lock()
	defer logger.mu.Unlock()

	now := logger.now()
	if now.Before(logger.nextAllowed) {
		return
	}
	logger.nextAllowed = now.Add(fastHTTPLogInterval)
	_, _ = logger.output.Write(fastHTTPLogLine)
}
