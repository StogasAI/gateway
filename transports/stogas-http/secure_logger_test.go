package stogashttp

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestSecureHTTPLoggerDropsInputAndBoundsEvents(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	logger := newSecureHTTPLogWriter(&output)
	logger.now = func() time.Time { return now }

	log.New(logger, "", 0).Printf("error when serving connection %q: %v", "secret-address", "SECRET malformed request body")
	log.New(logger, "", 0).Printf("%s", "SECOND_SECRET")

	first := output.String()
	if logger.errors.Load() != 2 {
		t.Fatal("suppressed server errors were not counted")
	}
	if first != string(httpLogLine) {
		t.Fatalf("first log = %q, want one fixed event", first)
	}
	for _, forbidden := range []string{"secret-address", "SECRET", "malformed request body"} {
		if strings.Contains(first, forbidden) {
			t.Fatalf("safe log contains %q: %s", forbidden, first)
		}
	}

	now = now.Add(httpLogInterval)
	log.New(logger, "", 0).Printf("%s", "THIRD_SECRET")
	if output.String() != string(httpLogLine)+string(httpLogLine) {
		t.Fatalf("log throttle did not reopen after %s: %q", httpLogInterval, output.String())
	}
}
