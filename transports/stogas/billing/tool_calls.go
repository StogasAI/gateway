package billing

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// MaxLoggedToolCalls is how many tool calls, and how many answered calls, a request log keeps.
// Responses rarely have more, and the meters still count every call.
const MaxLoggedToolCalls = 32

// ToolCall is one tool call of the response in its request log. The log keeps no names,
// arguments or results: only the call's Responses item type, when it started and how long it
// took on the request clock, and a hash of the ID that the client's result names.
type ToolCall struct {
	Type string `json:"type"`
	// StartMS is null for a call that arrived in a whole response. LatencyMS is null also for a
	// streamed call that never finished.
	StartMS    *uint32 `json:"start_ms"`
	LatencyMS  *uint32 `json:"latency_ms"`
	CallIDHash string  `json:"call_id_hash,omitempty"`
}

// ToolCallInput is one tool call as the gateway observed it. CallID is empty for a call that the
// provider runs. StartedAt is zero for a call that arrived in a whole response, and DoneAt for one
// that did not finish.
type ToolCallInput struct {
	Type      string
	CallID    string
	StartedAt time.Time
	DoneAt    time.Time
}

// ToolCallIDHash identifies a call ID in a request log: the first 16 hex digits of the SHA-256 of
// its bytes. A client computes it from the IDs it holds, so it finds the logs of its calls although
// no log keeps their IDs.
func ToolCallIDHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:8])
}

// requestToolCalls keeps the first calls in output order, placed on the request clock.
func requestToolCalls(calls []ToolCallInput, startedAt time.Time, totalMS uint32) []ToolCall {
	calls = calls[:min(len(calls), MaxLoggedToolCalls)]
	if len(calls) == 0 {
		return nil
	}
	logged := make([]ToolCall, len(calls))
	for index, call := range calls {
		logged[index].Type = call.Type
		if call.CallID != "" {
			logged[index].CallIDHash = ToolCallIDHash(call.CallID)
		}
		if call.StartedAt.IsZero() || call.StartedAt.Before(startedAt) {
			continue
		}
		start := min(uint32Duration(call.StartedAt.Sub(startedAt)), totalMS)
		logged[index].StartMS = &start
		if !call.DoneAt.IsZero() && !call.DoneAt.Before(call.StartedAt) {
			latency := min(uint32Duration(call.DoneAt.Sub(call.StartedAt)), totalMS-start)
			logged[index].LatencyMS = &latency
		}
	}
	return logged
}

// requestAnsweredCalls keeps the last results, which answer the latest calls.
func requestAnsweredCalls(callIDs []string) []string {
	callIDs = callIDs[max(len(callIDs)-MaxLoggedToolCalls, 0):]
	if len(callIDs) == 0 {
		return nil
	}
	hashes := make([]string, len(callIDs))
	for index, id := range callIDs {
		hashes[index] = ToolCallIDHash(id)
	}
	return hashes
}
