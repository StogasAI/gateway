package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

type operationalLogEvent struct {
	Environment string `json:"environment,omitempty"`
	ErrorType   string `json:"errorType,omitempty"`
	Event       string `json:"event"`
	ReasonCode  string `json:"reasonCode,omitempty"`
	RequestID   string `json:"requestId,omitempty"`
	Severity    string `json:"severity"`
	Source      string `json:"source,omitempty"`
	Suppressed  uint64 `json:"suppressed,omitempty"`
}

// Covers the library's current warning/error call sites plus owned events.
const operationalLogSeriesLimit = 256

type OperationalLogSeries struct {
	Event        string    `json:"event"`
	ReasonCode   string    `json:"reasonCode,omitempty"`
	ErrorType    string    `json:"errorType,omitempty"`
	Severity     string    `json:"severity"`
	Source       string    `json:"source,omitempty"`
	Occurrences  uint64    `json:"occurrences"`
	Suppressed   uint64    `json:"suppressed"`
	LastObserved time.Time `json:"lastObserved"`
}

type operationalLogKey struct {
	event, reason, errorType, severity, source string
}

type operationalLogState struct {
	OperationalLogSeries
	nextAllowed time.Time
	pending     uint64
}

type operationalLogTracker struct {
	mu     sync.Mutex
	series map[operationalLogKey]*operationalLogState
}

var operationalLogs operationalLogTracker

// Only code-owned labels and source locations enter this tracker. Request IDs
// are emission samples, never keys or retained state. Overflow bounds new callers.
func (tracker *operationalLogTracker) record(event operationalLogEvent, now time.Time) (operationalLogEvent, bool) {
	// The final message before exit must survive a full tracker.
	if event.Event == "provider_runtime_fatal" {
		return event, true
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.series == nil {
		tracker.series = make(map[operationalLogKey]*operationalLogState)
	}
	key := operationalLogKey{event.Event, event.ReasonCode, event.ErrorType, event.Severity, event.Source}
	state := tracker.series[key]
	if state == nil {
		if len(tracker.series) >= operationalLogSeriesLimit {
			key = operationalLogKey{event: "operational_log_overflow", severity: "error"}
			event = operationalLogEvent{Event: key.event, Severity: key.severity}
			state = tracker.series[key]
		}
		if state == nil {
			state = &operationalLogState{OperationalLogSeries: OperationalLogSeries{
				Event: key.event, ReasonCode: key.reason, ErrorType: key.errorType, Severity: key.severity, Source: key.source,
			}}
			tracker.series[key] = state
		}
	}
	state.Occurrences++
	state.LastObserved = now.UTC()
	if now.Before(state.nextAllowed) {
		state.Suppressed++
		state.pending++
		return operationalLogEvent{}, false
	}
	state.nextAllowed = now.Add(time.Minute)
	event.Suppressed = state.pending
	state.pending = 0
	return event, true
}

func (tracker *operationalLogTracker) snapshot() []OperationalLogSeries {
	tracker.mu.Lock()
	result := make([]OperationalLogSeries, 0, len(tracker.series))
	for _, state := range tracker.series {
		result = append(result, state.OperationalLogSeries)
	}
	tracker.mu.Unlock()
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.Event != b.Event {
			return a.Event < b.Event
		}
		if a.ReasonCode != b.ReasonCode {
			return a.ReasonCode < b.ReasonCode
		}
		if a.ErrorType != b.ErrorType {
			return a.ErrorType < b.ErrorType
		}
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		return a.Source < b.Source
	})
	return result
}

// OperationalLogDiagnostics returns process-lifetime counters without request data.
func OperationalLogDiagnostics() []OperationalLogSeries {
	return operationalLogs.snapshot()
}

func writeOperationalLog(event operationalLogEvent) {
	event, emit := operationalLogs.record(event, time.Now())
	if !emit {
		return
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	output := os.Stdout
	if event.Severity == "error" {
		output = os.Stderr
	}
	_, _ = fmt.Fprintln(output, string(payload))
}

func safeOperationalErrorType(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "DeadlineExceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "Canceled"
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return "NetworkError"
	}
	return "Error"
}

func infisicalSecretFailureReason(secretName string) string {
	switch secretName {
	case "API_KEY_PEPPER":
		return "api_key_pepper_unavailable"
	case "BYOK_ENCRYPTION_SECRET":
		return "byok_encryption_secret_unavailable"
	case "CHUTES_API_KEY":
		return "chutes_api_key_unavailable"
	case "DATABASE_SCHEMA":
		return "database_schema_unavailable"
	case "DATABASE_URL":
		return "database_url_unavailable"
	case "INFERENCE_TOKEN_PUBLIC_KEY":
		return "inference_token_public_key_unavailable"
	default:
		return "required_secret_unavailable"
	}
}
