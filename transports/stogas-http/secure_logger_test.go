package stogashttp

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSecureFastHTTPLoggerDropsInputAndBoundsEvents(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	logger := newSecureFastHTTPLogger(&output)
	logger.now = func() time.Time { return now }

	logger.Printf("error when serving connection %q: %v", "secret-address", "SECRET malformed request body")
	logger.Printf("%s", "SECOND_SECRET")

	first := output.String()
	if first != string(fastHTTPLogLine) {
		t.Fatalf("first log = %q, want one fixed event", first)
	}
	for _, forbidden := range []string{"secret-address", "SECRET", "malformed request body"} {
		if strings.Contains(first, forbidden) {
			t.Fatalf("safe log contains %q: %s", forbidden, first)
		}
	}

	now = now.Add(fastHTTPLogInterval)
	logger.Printf("%s", "THIRD_SECRET")
	if output.String() != string(fastHTTPLogLine)+string(fastHTTPLogLine) {
		t.Fatalf("log throttle did not reopen after %s: %q", fastHTTPLogInterval, output.String())
	}
}
