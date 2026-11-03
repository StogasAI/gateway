package billing

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestToolCallIDHashIsTheStartOfItsSHA256(t *testing.T) {
	// Pinned against `printf %s ID | sha256sum | cut -c1-16`, which the docs give clients.
	for id, want := range map[string]string{
		"call_1":                        "74196fe72e4cdc13",
		"toolu_01A09q90qw90lq917835lq9": "5163f0072184f895",
		"mcpr_1":                        "27eecee3bcc71568",
	} {
		if got := ToolCallIDHash(id); got != want {
			t.Errorf("ToolCallIDHash(%q) = %s, want %s", id, got, want)
		}
	}
}

func TestRequestLogPlacesToolCallsOnTheRequestClock(t *testing.T) {
	start := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return start.Add(time.Duration(ms) * time.Millisecond) }
	ms := func(value uint32) *uint32 { return &value }
	logged := requestToolCalls([]ToolCallInput{
		{Type: "web_search_call", StartedAt: at(100), DoneAt: at(600)},
		{Type: "function_call", CallID: "call_1", StartedAt: at(700), DoneAt: at(750)},
		// A whole response has no times.
		{Type: "function_call", CallID: "call_2"},
		// A call that never finished keeps its start.
		{Type: "mcp_call", StartedAt: at(800)},
		// A time before the request cannot be placed.
		{Type: "mcp_list_tools", StartedAt: at(-5), DoneAt: at(10)},
		// The clock ends with the request.
		{Type: "web_fetch_call", StartedAt: at(900), DoneAt: at(5000)},
		{Type: "mcp_approval_request", CallID: "mcpr_1", StartedAt: at(5000), DoneAt: at(6000)},
	}, start, 1000)
	want := []ToolCall{
		{Type: "web_search_call", StartMS: ms(100), LatencyMS: ms(500)},
		{Type: "function_call", StartMS: ms(700), LatencyMS: ms(50), CallIDHash: "74196fe72e4cdc13"},
		{Type: "function_call", CallIDHash: ToolCallIDHash("call_2")},
		{Type: "mcp_call", StartMS: ms(800)},
		{Type: "mcp_list_tools"},
		{Type: "web_fetch_call", StartMS: ms(900), LatencyMS: ms(100)},
		{Type: "mcp_approval_request", StartMS: ms(1000), LatencyMS: ms(0), CallIDHash: "27eecee3bcc71568"},
	}
	if !slices.EqualFunc(logged, want, func(a, b ToolCall) bool {
		return a.Type == b.Type && a.CallIDHash == b.CallIDHash && equalMS(a.StartMS, b.StartMS) && equalMS(a.LatencyMS, b.LatencyMS)
	}) {
		t.Fatalf("logged calls = %s, want %s", formatToolCalls(logged), formatToolCalls(want))
	}
	if requestToolCalls(nil, start, 1000) != nil || requestAnsweredCalls(nil) != nil {
		t.Fatal("a request without calls logs no lists, so its record leaves them out")
	}

	var calls []ToolCallInput
	var ids []string
	for index := range MaxLoggedToolCalls + 8 {
		calls = append(calls, ToolCallInput{Type: "function_call", CallID: fmt.Sprint(index)})
		ids = append(ids, fmt.Sprint(index))
	}
	if kept := requestToolCalls(calls, start, 1000); len(kept) != MaxLoggedToolCalls || kept[0].CallIDHash != ToolCallIDHash("0") {
		t.Fatalf("kept %d calls from %s, want the first %d", len(kept), kept[0].CallIDHash, MaxLoggedToolCalls)
	}
	// The last results answer the latest calls, which no earlier request answered.
	if kept := requestAnsweredCalls(ids); len(kept) != MaxLoggedToolCalls || kept[0] != ToolCallIDHash("8") || kept[MaxLoggedToolCalls-1] != ToolCallIDHash(fmt.Sprint(MaxLoggedToolCalls+7)) {
		t.Fatalf("kept %v, want the last %d results", kept, MaxLoggedToolCalls)
	}
}

func equalMS(a, b *uint32) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func formatToolCalls(calls []ToolCall) string {
	text := ""
	for _, call := range calls {
		value := func(ms *uint32) string {
			if ms == nil {
				return "null"
			}
			return fmt.Sprint(*ms)
		}
		text += fmt.Sprintf("{%s %s %s %s} ", call.Type, value(call.StartMS), value(call.LatencyMS), call.CallIDHash)
	}
	return text
}
