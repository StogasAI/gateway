package stogas

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

func TestOperationalLogStormRetainsCountsWithoutRequestCardinality(t *testing.T) {
	var tracker operationalLogTracker
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	var workers sync.WaitGroup
	for i := range 1000 {
		workers.Go(func() {
			tracker.record(operationalLogEvent{
				Event: "billing_final_price_failed", Severity: "error", RequestID: fmt.Sprintf("request-%d", i),
			}, now)
		})
	}
	workers.Wait()
	series := tracker.snapshot()
	if len(series) != 1 || series[0].Occurrences != 1000 || series[0].Suppressed != 999 || !series[0].LastObserved.Equal(now) {
		t.Fatalf("storm counters = %#v", series)
	}
	encoded, err := json.Marshal(series)
	if err != nil || strings.Contains(string(encoded), "request-") || strings.Contains(string(encoded), "requestId") {
		t.Fatalf("snapshot retained request data: %s, %v", encoded, err)
	}
	series[0].Occurrences = 0
	if tracker.snapshot()[0].Occurrences != 1000 {
		t.Fatal("snapshot aliases tracker state")
	}
	event, emit := tracker.record(operationalLogEvent{Event: "billing_final_price_failed", Severity: "error"}, now.Add(time.Minute))
	if !emit || event.Suppressed != 999 {
		t.Fatalf("next emission must summarize suppressed events: %#v, %t", event, emit)
	}
	if _, emit := tracker.record(operationalLogEvent{Event: "billing_final_price_failed", Severity: "error", ReasonCode: "another_reason"}, now); !emit {
		t.Fatal("independent operational failure was suppressed")
	}
}

func TestOperationalLogSeriesCapacityUsesOneOverflowBucket(t *testing.T) {
	var tracker operationalLogTracker
	now := time.Now()
	emissions := 0
	for i := range 1000 {
		event, emit := tracker.record(operationalLogEvent{Event: fmt.Sprintf("event_%d", i), Severity: "warn"}, now)
		if emit {
			emissions++
			if i >= operationalLogSeriesLimit && (event.Event != "operational_log_overflow" || event.Severity != "error") {
				t.Fatalf("overflow must have fixed labels: %#v", event)
			}
		}
	}
	series := tracker.snapshot()
	if len(series) != operationalLogSeriesLimit+1 || emissions != operationalLogSeriesLimit+1 {
		t.Fatalf("unbounded series/emissions: %d/%d", len(series), emissions)
	}
	var occurrences, suppressed uint64
	for _, item := range series {
		occurrences += item.Occurrences
		suppressed += item.Suppressed
	}
	if occurrences != 1000 || suppressed != 1000-uint64(emissions) {
		t.Fatalf("overflow lost counters: %d/%d", occurrences, suppressed)
	}
	if event, emit := tracker.record(operationalLogEvent{Event: "provider_runtime_fatal", Severity: "error"}, now); !emit || event.Event != "provider_runtime_fatal" {
		t.Fatal("a full warning tracker suppressed the final event before exit")
	}
}

type forbiddenLogStringer struct{}

func (forbiddenLogStringer) String() string { panic("provider arguments must never be formatted") }

func TestProviderLibraryLoggerDiscardsAllUntrustedContent(t *testing.T) {
	var events []operationalLogEvent
	logger := providerLibraryLogger{emit: func(event operationalLogEvent) { events = append(events, event) }}
	logger.SetLevel(schemas.LogLevelDebug)
	logger.SetOutputType(schemas.LoggerOutputTypePretty)
	logger.Debug("SECRET debug %s", forbiddenLogStringer{})
	logger.Info("SECRET info %s", forbiddenLogStringer{})
	logger.Warn("SECRET response %s", forbiddenLogStringer{})
	logger.Error("SECRET error %s", forbiddenLogStringer{})
	logger.LogHTTPRequest(schemas.LogLevelError, "SECRET access").Str("body", "SECRET").Int("id", 1).Int64("id", 2).Send()
	encoded, err := json.Marshal(events)
	if err != nil || strings.Contains(string(encoded), "SECRET") {
		t.Fatalf("provider content escaped: %s, %v", encoded, err)
	}
	if len(events) != 2 || events[0].Event != "provider_runtime_warning" || events[1].Event != "provider_runtime_error" {
		t.Fatalf("expected only fixed warning/error events: %#v", events)
	}
	for _, event := range events {
		if !strings.HasPrefix(event.Source, "stogas/operational_log_test.go:") || strings.Count(event.Source, "/") != 1 {
			t.Fatalf("wrong caller or absolute build path in source: %q", event.Source)
		}
	}
}

func TestProviderLibraryWarningsKeepDistinctCodeLocations(t *testing.T) {
	var tracker operationalLogTracker
	now := time.Now()
	var emitted []operationalLogEvent
	logger := providerLibraryLogger{emit: func(event operationalLogEvent) {
		if event, emit := tracker.record(event, now); emit {
			emitted = append(emitted, event)
		}
	}}
	// One real Bifrost helper raises two different warnings from the same file.
	// Changing untrusted certificate text must not create new warning groups.
	for i := range 1000 {
		providerUtils.ConfigureTLS(&fasthttp.Client{}, schemas.NetworkConfig{
			InsecureSkipVerify: true,
			CACertPEM:          schemas.NewSecretVar(fmt.Sprintf("SECRET-%d", i)),
		}, logger)
	}
	series := tracker.snapshot()
	if len(series) != 2 || len(emitted) != 2 || series[0].Source == series[1].Source {
		t.Fatalf("different Bifrost faults must stay distinct: %#v", series)
	}
	for _, item := range series {
		if !strings.HasPrefix(item.Source, "utils/utils.go:") || item.Occurrences != 1000 || item.Suppressed != 999 {
			t.Fatalf("wrong caller or warning counts: %#v", item)
		}
	}
	encoded, err := json.Marshal(emitted)
	if err != nil || strings.Contains(string(encoded), "SECRET") {
		t.Fatalf("provider content escaped: %s, %v", encoded, err)
	}
}

func TestProviderLibraryFatalPreservesExitWithoutContent(t *testing.T) {
	const childFlag = "STOGAS_TEST_PROVIDER_LOGGER_FATAL"
	if os.Getenv(childFlag) == "1" {
		providerLibraryLogger{emit: writeOperationalLog}.Fatal("SECRET fatal %s", forbiddenLogStringer{})
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestProviderLibraryFatalPreservesExitWithoutContent$")
	command.Env = append(os.Environ(), childFlag+"=1")
	output, err := command.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		t.Fatalf("fatal exit = %v, output %s", err, output)
	}
	var event operationalLogEvent
	if err := json.Unmarshal(output, &event); err != nil || event.Event != "provider_runtime_fatal" || event.Severity != "error" ||
		!strings.HasPrefix(event.Source, "stogas/operational_log_test.go:") || strings.Contains(string(output), "SECRET") {
		t.Fatalf("fatal output must be one content-free event: %s", output)
	}
}
