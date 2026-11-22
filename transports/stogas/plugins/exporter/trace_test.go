package exporter

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
)

// The reader below decodes the Protobuf wire format on its own, so that the
// tests check the encoder against the format and not against itself.
type wireField struct {
	number int
	varint uint64
	data   []byte
}

func wireFields(t *testing.T, data []byte) []wireField {
	t.Helper()
	var fields []wireField
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			t.Fatal("invalid tag")
		}
		data = data[n:]
		field := wireField{number: int(tag >> 3)}
		switch tag & 7 {
		case 0:
			if field.varint, n = binary.Uvarint(data); n <= 0 {
				t.Fatal("invalid varint")
			}
			data = data[n:]
		case 1:
			field.varint, data = binary.LittleEndian.Uint64(data), data[8:]
		case 2:
			size, n := binary.Uvarint(data)
			if n <= 0 || uint64(len(data)-n) < size {
				t.Fatal("invalid length")
			}
			field.data, data = data[n:n+int(size)], data[n+int(size):]
		default:
			t.Fatalf("unexpected wire type %d", tag&7)
		}
		fields = append(fields, field)
	}
	return fields
}

func wireValue(t *testing.T, data []byte) any {
	t.Helper()
	fields := wireFields(t, data)
	if len(fields) == 0 {
		return nil
	}
	if len(fields) != 1 {
		t.Fatalf("AnyValue has %d fields", len(fields))
	}
	switch field := fields[0]; field.number {
	case 1:
		return string(field.data)
	case 2:
		return field.varint == 1
	case 3:
		return int64(field.varint)
	case 4:
		return math.Float64frombits(field.varint)
	case 5:
		list := []any{}
		for _, element := range wireFields(t, field.data) {
			list = append(list, wireValue(t, element.data))
		}
		return list
	case 6:
		return wireAttributes(t, wireFields(t, field.data), 1)
	}
	t.Fatal("unexpected AnyValue field")
	return nil
}

func wireAttributes(t *testing.T, fields []wireField, number int) map[string]any {
	t.Helper()
	attributes := map[string]any{}
	for _, field := range fields {
		if field.number != number {
			continue
		}
		pair := wireFields(t, field.data)
		if len(pair) != 2 || pair[0].number != 1 || pair[1].number != 2 {
			t.Fatal("invalid KeyValue")
		}
		key := string(pair[0].data)
		if _, repeated := attributes[key]; repeated {
			t.Fatalf("attribute %s repeated", key)
		}
		attributes[key] = wireValue(t, pair[1].data)
	}
	return attributes
}

type wireSpan struct {
	traceID, spanID, parentID, name, statusMessage string
	kind, statusCode                               uint64
	start, end                                     time.Time
	attributes                                     map[string]any
}

type wireTrace struct {
	resource           map[string]any
	scope              string
	schemaURLs         []string
	spans              []wireSpan
	resourceSpansCount int
}

func decodeTrace(t *testing.T, data []byte) wireTrace {
	t.Helper()
	var trace wireTrace
	for _, resourceSpans := range wireFields(t, data) {
		if resourceSpans.number != 1 {
			t.Fatalf("unexpected export field %d", resourceSpans.number)
		}
		trace.resourceSpansCount++
		for _, field := range wireFields(t, resourceSpans.data) {
			switch field.number {
			case 1:
				trace.resource = wireAttributes(t, wireFields(t, field.data), 1)
			case 2:
				for _, scoped := range wireFields(t, field.data) {
					switch scoped.number {
					case 1:
						trace.scope = string(wireFields(t, scoped.data)[0].data)
					case 2:
						trace.spans = append(trace.spans, decodeSpan(t, scoped.data))
					case 3:
						trace.schemaURLs = append(trace.schemaURLs, string(scoped.data))
					}
				}
			case 3:
				trace.schemaURLs = append(trace.schemaURLs, string(field.data))
			}
		}
	}
	return trace
}

func decodeSpan(t *testing.T, data []byte) wireSpan {
	t.Helper()
	fields := wireFields(t, data)
	span := wireSpan{attributes: wireAttributes(t, fields, 9)}
	for _, field := range fields {
		switch field.number {
		case 1:
			span.traceID = hex.EncodeToString(field.data)
		case 2:
			span.spanID = hex.EncodeToString(field.data)
		case 4:
			span.parentID = hex.EncodeToString(field.data)
		case 5:
			span.name = string(field.data)
		case 6:
			span.kind = field.varint
		case 7:
			span.start = time.Unix(0, int64(field.varint)).UTC()
		case 8:
			span.end = time.Unix(0, int64(field.varint)).UTC()
		case 15:
			for _, status := range wireFields(t, field.data) {
				if status.number == 2 {
					span.statusMessage = string(status.data)
				} else if status.number == 3 {
					span.statusCode = status.varint
				}
			}
		}
	}
	return span
}

const (
	testTraceID  = "4bf92f3577b34da6a3ce929d0e0e4736"
	testParentID = "00f067aa0ba902b7"
)

func pointer[T any](value T) *T { return &value }

// traceEvent is a streamed request that a second provider served after the
// first failed.
func traceEvent() *billing.RequestEvent {
	chat, stream := billing.RequestShape(string(schemas.ChatCompletionStreamRequest))
	return &billing.RequestEvent{
		SchemaVersion: billing.RequestLogSchemaVersion, RequestID: "req_trace", CreatedAt: "2026-11-20T10:00:00.250Z", LastRequestAt: "2026-11-20T10:00:00.250Z",
		RequestCount: 1, APIKeyID: "key_1", MemberID: "member_1", OrganizationID: "org_1", Interface: chat, Stream: stream,
		RequestSettings: billing.RequestSettings{MaxOutputTokens: pointer(512), Temperature: pointer(0.5), TopK: pointer(40), Seed: pointer(7), ResponseFormat: "json_schema", HostedTools: []string{"web_search"}},
		SessionID:       "session-1", TraceID: testTraceID, Metadata: map[string]string{"team": "search"}, Transport: "http/2",
		ProviderAttempts: []billing.ProviderAttempt{
			{Provider: "azure", Status: "rate_limited", StatusCode: pointer(429), ErrorCode: "rate_limit_exceeded", StartMS: 5, LatencyMS: 40},
			{Provider: "openai", Status: "success", StatusCode: pointer(200), StartMS: 50, LatencyMS: 900, ProviderResponseID: "chatcmpl-1", ProviderModel: "gpt-5.6-sol-2026-05-01", FinishReason: "tool_calls"},
		},
		Performance: billing.RequestPerformance{TotalMS: 1000, TTFTMS: pointer(uint32(250))},
		Usage: billing.RequestUsage{UpstreamCostUSD: "0.01", BilledCostUSD: "0.0123", Meters: billing.EventMeters{
			"total_input_tokens": {Quantity: "120"}, "cached_input_tokens": {Quantity: "100"}, "total_cache_write_tokens": {Quantity: "8"},
			"total_output_tokens": {Quantity: "60"}, "reasoning_tokens": {Quantity: "20", USD: pointer("0.001")},
		}},
		GatewayVersion: "v1.2.3",
	}
}

func encodeTrace(t *testing.T, v conventions, event any, metadata string, trace Trace, bodies *traceBodies) wireTrace {
	t.Helper()
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	data, err := traceExport(encoded, []byte(metadata), trace, bodies, v)
	if err != nil {
		t.Fatal(err)
	}
	return decodeTrace(t, data)
}

func TestTraceExportDescribesTheRequestAndItsAttempts(t *testing.T) {
	metadata := `{"request_id":"req_trace","catalog":{"version":22,"chain_hash":"abc","selection_ids":["a","b"]},"policy_versions_sha512":"feed","usage":{"billed_cost_usd":"9"},"node_id":"node-1","receipt":{"schema":"stogas.receipt.v1","signature":"sig"}}`
	trace := encodeTrace(t, conventions141, traceEvent(), metadata, Trace{Model: "gpt-5.6-sol", TraceID: testTraceID, ParentSpanID: testParentID}, nil)
	if trace.resourceSpansCount != 1 || trace.scope != "stogas.gateway.export" || !reflect.DeepEqual(trace.schemaURLs, []string{"https://opentelemetry.io/schemas/1.41.0", "https://opentelemetry.io/schemas/1.41.0"}) {
		t.Fatalf("unexpected envelope: %+v", trace)
	}
	if want := map[string]any{"service.name": "stogas-gateway", "service.version": "v1.2.3"}; !reflect.DeepEqual(trace.resource, want) {
		t.Fatalf("resource = %v", trace.resource)
	}
	if len(trace.spans) != 3 {
		t.Fatalf("got %d spans", len(trace.spans))
	}
	root, failed, served := trace.spans[0], trace.spans[1], trace.spans[2]
	start := time.Date(2026, 11, 20, 10, 0, 0, 250e6, time.UTC)
	if root.traceID != testTraceID || root.parentID != testParentID || len(root.spanID) != 16 || root.name != "chat gpt-5.6-sol" || root.kind != 3 ||
		!root.start.Equal(start) || !root.end.Equal(start.Add(time.Second)) || root.statusCode != 0 {
		t.Fatalf("unexpected request span: %+v", root)
	}
	for key, want := range map[string]any{
		"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai", "gen_ai.conversation.id": "session-1",
		"gen_ai.request.model": "gpt-5.6-sol", "gen_ai.output.type": "json", "gen_ai.request.max_tokens": int64(512),
		"gen_ai.request.temperature": 0.5, "gen_ai.request.top_k": int64(40), "gen_ai.request.seed": int64(7), "gen_ai.request.stream": true,
		"gen_ai.response.finish_reasons": []any{"tool_call"}, "gen_ai.response.id": "chatcmpl-1", "gen_ai.response.model": "gpt-5.6-sol-2026-05-01",
		"gen_ai.response.time_to_first_chunk": 0.25, "gen_ai.usage.input_tokens": int64(120), "gen_ai.usage.cache_read.input_tokens": int64(100),
		"gen_ai.usage.cache_creation.input_tokens": int64(8), "gen_ai.usage.output_tokens": int64(60), "gen_ai.usage.reasoning.output_tokens": int64(20),
		// Every other field of the record, named by its path.
		"stogas.request_id": "req_trace", "stogas.organization_id": "org_1", "stogas.metadata.team": "search", "stogas.stream": true,
		"stogas.request_settings.hosted_tools": []any{"web_search"}, "stogas.usage.billed_cost_usd": "0.0123",
		"stogas.usage.meters.reasoning_tokens.usd": "0.001", "stogas.performance.total_ms": int64(1000), "stogas.schema_version": int64(1),
		// The metadata's own fields. Its usage repeats the record's.
		"stogas.catalog.version": int64(22), "stogas.catalog.selection_ids": []any{"a", "b"}, "stogas.policy_versions_sha512": "feed", "stogas.receipt.signature": "sig",
	} {
		if got := root.attributes[key]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", key, got, want)
		}
	}
	for _, absent := range []string{"error.type", "stogas.trace_id", "stogas.session_id", "stogas.provider_attempts", "stogas.gateway_error", "stogas.grant_id", "stogas.app_title", "gen_ai.request.top_p", "gen_ai.input.messages"} {
		if _, ok := root.attributes[absent]; ok {
			t.Errorf("%s is present", absent)
		}
	}
	if failed.traceID != testTraceID || failed.parentID != root.spanID || failed.name != "provider_attempt azure" || failed.statusCode != 2 || failed.statusMessage != "rate_limited" ||
		!failed.start.Equal(start.Add(5*time.Millisecond)) || !failed.end.Equal(start.Add(45*time.Millisecond)) ||
		failed.attributes["error.type"] != "rate_limited" || failed.attributes["http.response.status_code"] != int64(429) || failed.attributes["stogas.attempt.error_code"] != "rate_limit_exceeded" {
		t.Fatalf("unexpected failed attempt: %+v", failed)
	}
	if served.parentID != root.spanID || served.name != "provider_attempt openai" || served.statusCode != 0 || served.spanID == failed.spanID || served.spanID == root.spanID ||
		served.attributes["stogas.attempt.provider_model"] != "gpt-5.6-sol-2026-05-01" || served.attributes["error.type"] != nil {
		t.Fatalf("unexpected served attempt: %+v", served)
	}
	// A request's usage is the whole request's, so no attempt repeats it.
	for key := range served.attributes {
		if strings.HasPrefix(key, "gen_ai.") {
			t.Errorf("attempt holds %s", key)
		}
	}
}

// Each version of the conventions names its own schemas and attributes.
func TestTraceExportFollowsTheConventionsItNames(t *testing.T) {
	event := traceEvent()
	event.RequestSettings.ReasoningEffort = "high"
	for _, tc := range []struct {
		v                 conventions
		schemas           []string
		present, absent   string
		reasoningRecorded bool
	}{
		{conventions141, []string{"https://opentelemetry.io/schemas/1.41.0", "https://opentelemetry.io/schemas/1.41.0"},
			"gen_ai.usage.cache_creation.input_tokens", "gen_ai.usage.cache_write.input_tokens", false},
		{conventions01, []string{"https://opentelemetry.io/schemas/semconv-genai-dev/0.1.0-dev", "https://opentelemetry.io/schemas/1.45.0"},
			"gen_ai.usage.cache_write.input_tokens", "gen_ai.usage.cache_creation.input_tokens", true},
	} {
		trace := encodeTrace(t, tc.v, event, `{}`, Trace{Model: "gpt-5.6-sol"}, nil)
		root := trace.spans[0]
		if !reflect.DeepEqual(trace.schemaURLs, tc.schemas) || root.attributes[tc.present] != int64(8) || root.attributes[tc.absent] != nil {
			t.Errorf("%v: schemas %v, attributes %v", tc.v, trace.schemaURLs, root.attributes)
		}
		if level, recorded := root.attributes["gen_ai.request.reasoning.level"]; recorded != tc.reasoningRecorded || recorded && level != "high" {
			t.Errorf("%v: reasoning level %v", tc.v, level)
		}
	}
	// A cache or reasoning count of zero is left out, and a total stays.
	event.Usage.Meters["cached_input_tokens"] = billing.EventMeter{Quantity: "0"}
	event.Usage.Meters["total_output_tokens"] = billing.EventMeter{Quantity: "0"}
	attributes := encodeTrace(t, conventions01, event, `{}`, Trace{}, nil).spans[0].attributes
	if _, ok := attributes["gen_ai.usage.cache_read.input_tokens"]; ok || attributes["gen_ai.usage.output_tokens"] != int64(0) {
		t.Errorf("zero counts: %v", attributes)
	}
}

// A structured value keeps each JSON value's type and text.
func TestStructuredValuesKeepEveryJSONType(t *testing.T) {
	var p protobuf
	p.structuredAttribute(9, "list", []byte(`[{"s":"line\nnext \u00e9 \ud83d\ude00 \"q\" <b>","i":-42,"big":18446744073709551616,`+
		`"f":0.5,"huge":1e400,"t":true,"no":false,"n":null,"o":{},"a":[],"nested":[[1,"x"]]}]`))
	want := []any{map[string]any{
		"s": "line\nnext é 😀 \"q\" <b>", "i": int64(-42), "big": 1.8446744073709552e19, "f": 0.5, "huge": math.Inf(1),
		"t": true, "no": false, "n": nil, "o": map[string]any{}, "a": []any{}, "nested": []any{[]any{int64(1), "x"}},
	}}
	if got := wireAttributes(t, wireFields(t, p.data), 9)["list"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("list = %#v", got)
	}
	// Text that does not decode leaves no attribute.
	p = protobuf{}
	if p.structuredAttribute(9, "list", []byte(`[{"a":`)); len(p.data) != 0 {
		t.Fatalf("a broken list wrote %x", p.data)
	}
}

func TestTraceExportTimesEachStreamedToolCall(t *testing.T) {
	event := traceEvent()
	event.Performance.ToolCalls = []billing.ToolCall{
		{Type: "web_search_call", StartMS: pointer(uint32(300)), LatencyMS: pointer(uint32(450))},
		{Type: "function_call", StartMS: pointer(uint32(800)), CallIDHash: "0123456789abcdef"},
		// A whole response times no call.
		{Type: "function_call", CallIDHash: "fedcba9876543210"},
	}
	trace := encodeTrace(t, conventions141, event, "{}", Trace{Model: "gpt-5.6-sol"}, nil)
	if len(trace.spans) != 5 {
		t.Fatalf("got %d spans", len(trace.spans))
	}
	root, search, unfinished := trace.spans[0], trace.spans[3], trace.spans[4]
	start := time.Date(2026, 11, 20, 10, 0, 0, 250e6, time.UTC)
	if search.traceID != root.traceID || search.parentID != root.spanID || search.name != "tool_call web_search_call" || search.kind != 1 || search.statusCode != 0 ||
		!search.start.Equal(start.Add(300*time.Millisecond)) || !search.end.Equal(start.Add(750*time.Millisecond)) ||
		!reflect.DeepEqual(search.attributes, map[string]any{"stogas.tool_call.type": "web_search_call", "stogas.tool_call.start_ms": int64(300), "stogas.tool_call.latency_ms": int64(450)}) {
		t.Fatalf("unexpected hosted call: %+v", search)
	}
	// A call that the response ended before runs to the end of the request.
	if unfinished.parentID != root.spanID || unfinished.name != "tool_call function_call" || unfinished.spanID == search.spanID ||
		!unfinished.start.Equal(start.Add(800*time.Millisecond)) || !unfinished.end.Equal(root.end) ||
		unfinished.attributes["stogas.tool_call.call_id_hash"] != "0123456789abcdef" {
		t.Fatalf("unexpected unfinished call: %+v", unfinished)
	}
	// The request span still lists every call, timed or not.
	if listed, _ := root.attributes["stogas.performance.tool_calls"].(string); strings.Count(listed, `"type"`) != 3 {
		t.Fatalf("request span lists %q", listed)
	}
}

func TestTraceExportNamesItsOwnTraceWithoutACallers(t *testing.T) {
	event := traceEvent()
	event.TraceID = ""
	first := encodeTrace(t, conventions141, event, `{}`, Trace{Model: "gpt-5.6-sol"}, nil)
	again := encodeTrace(t, conventions141, event, `{}`, Trace{Model: "gpt-5.6-sol"}, nil)
	root := first.spans[0]
	// A retried delivery repeats the IDs, so a receiver keeps one trace.
	if len(root.traceID) != 32 || root.traceID == testTraceID || root.parentID != "" || !reflect.DeepEqual(first.spans, again.spans) {
		t.Fatalf("unexpected spans: %+v", first.spans)
	}
	event.RequestID = "req_other"
	if other := encodeTrace(t, conventions141, event, `{}`, Trace{}, nil).spans[0]; other.traceID == root.traceID || other.spanID == root.spanID || other.name != "chat" {
		t.Fatalf("another request shares IDs: %+v", other)
	}
	// The record of repeated rejections keeps one request's trace, which is not
	// the trace of every request it counts.
	event.TraceID = testTraceID
	if other := encodeTrace(t, conventions141, event, `{}`, Trace{TraceID: strings.Repeat("ab", 16), ParentSpanID: testParentID}, nil).spans[0]; other.traceID != testTraceID || other.parentID != "" {
		t.Fatalf("a span joined another trace's parent: %+v", other)
	}
}

func TestTraceExportMarksFailuresAndRejections(t *testing.T) {
	rejected := traceEvent()
	rejected.ProviderAttempts, rejected.Performance, rejected.Usage.Meters = nil, billing.RequestPerformance{}, billing.EventMeters{}
	rejected.GatewayError = &billing.EventError{Code: "rate_limit_exceeded", Status: 429}
	rejected.RequestCount, rejected.LastRequestAt = 4, "2026-11-20T10:00:30.250Z"
	trace := encodeTrace(t, conventions141, rejected, `{}`, Trace{Model: "gpt-5.6-sol"}, nil)
	root := trace.spans[0]
	if len(trace.spans) != 1 || root.statusCode != 2 || root.attributes["error.type"] != "rate_limit_exceeded" || root.attributes["stogas.gateway_error.status"] != int64(429) ||
		root.attributes["stogas.request_count"] != int64(4) || root.end.Sub(root.start) != 30*time.Second {
		t.Fatalf("unexpected rejection: %+v", root)
	}
	for _, absent := range []string{"gen_ai.provider.name", "gen_ai.response.finish_reasons"} {
		if _, named := root.attributes[absent]; named {
			t.Fatalf("a request that no provider received names %s", absent)
		}
	}

	failed := traceEvent()
	failed.ProviderAttempts = failed.ProviderAttempts[:1]
	failed.ProviderAttempts[0].Provider = "google-cloud"
	if root := encodeTrace(t, conventions141, failed, `{}`, Trace{}, nil).spans[0]; root.statusCode != 2 || root.attributes["error.type"] != "rate_limited" || root.attributes["gen_ai.provider.name"] != "gcp.vertex_ai" {
		t.Fatalf("unexpected failure: %+v", root)
	}

	// A provider that refused the request with an error reply ended it in an error.
	refused := traceEvent()
	refused.ProviderAttempts = []billing.ProviderAttempt{{Provider: "openai", Status: "content_filter", StatusCode: pointer(400)}}
	if spans := encodeTrace(t, conventions141, refused, `{}`, Trace{}, nil).spans; spans[0].statusCode != 2 || spans[0].attributes["error.type"] != "content_filter" ||
		spans[1].statusCode != 2 || spans[1].attributes["error.type"] != "content_filter" {
		t.Fatalf("unexpected refusal: %+v", spans)
	}

	// A reply that a content filter stopped and a caller that stopped end a request without an error.
	filtered := traceEvent()
	filtered.ProviderAttempts = []billing.ProviderAttempt{{Provider: "aws", Status: "content_filter", FinishReason: "content_filter"}}
	if root := encodeTrace(t, conventions141, filtered, `{}`, Trace{}, nil).spans[0]; root.statusCode != 0 || root.attributes["error.type"] != nil ||
		!reflect.DeepEqual(root.attributes["gen_ai.response.finish_reasons"], []any{"content_filter"}) || root.attributes["gen_ai.provider.name"] != "aws.bedrock" {
		t.Fatalf("unexpected filtered reply: %+v", root)
	}
	stopped := traceEvent()
	stopped.ClientStopMS = pointer(uint32(300))
	stopped.ProviderAttempts = []billing.ProviderAttempt{{Provider: "openai", Status: "cancelled"}}
	if spans := encodeTrace(t, conventions141, stopped, `{}`, Trace{}, nil).spans; spans[0].statusCode != 0 || spans[1].statusCode != 0 ||
		!reflect.DeepEqual(spans[0].attributes["gen_ai.response.finish_reasons"], []any{"interrupted"}) {
		t.Fatalf("unexpected stopped request: %+v", spans)
	}
}

// The Responses interface names a reason only for a reply that ended early.
func TestTraceExportNamesWhyAReplyEnded(t *testing.T) {
	for _, v := range []conventions{conventions141, conventions01} {
		for _, tc := range []struct {
			reason, status string
			stopped        bool
			calls          []billing.ToolCall
			want           any
		}{
			{reason: "", status: "success", want: []any{"stop"}},
			{reason: "", status: "success", calls: []billing.ToolCall{{Type: "web_search_call"}}, want: []any{"stop"}},
			{reason: "", status: "success", calls: []billing.ToolCall{{Type: "web_search_call"}, {Type: "function_call", CallIDHash: "ab"}}, want: []any{"tool_call"}},
			{reason: "max_output_tokens", status: "success", want: []any{"length"}},
			{reason: "tool_use", status: "success", want: []any{"tool_call"}},
			{reason: "content_filter", status: "content_filter", want: []any{"content_filter"}},
			// A reply that ended without a reason ended in error, or was
			// interrupted when the client stopped it.
			{reason: "", status: "unknown", want: []any{"error"}},
			{reason: "", status: "timeout", want: []any{"error"}},
			{reason: "", status: "cancelled", stopped: true, want: []any{"interrupted"}},
			{reason: "length", status: "cancelled", stopped: true, want: []any{"length"}},
		} {
			event := traceEvent()
			event.Interface, _ = billing.RequestShape(string(schemas.ResponsesRequest))
			event.ProviderAttempts = []billing.ProviderAttempt{{Provider: "openai", Status: tc.status, FinishReason: tc.reason}}
			event.Performance.ToolCalls = tc.calls
			if tc.stopped {
				event.ClientStopMS = pointer(uint32(300))
			}
			trace := encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{response: []byte(`{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi"}]}]}`)})
			if got := trace.spans[0].attributes["gen_ai.response.finish_reasons"]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%q after %s: finish reasons = %v, want %v", tc.reason, tc.status, got, tc.want)
			}
			want := tc.want.([]any)[0].(string)
			expectMessages(t, trace, "gen_ai.output.messages", `[{"role":"assistant","finish_reason":"`+want+`","parts":[{"type":"text","content":"Hi"}]}]`)
		}
	}
}

// structured reports whether a trace follows the 0.1 conventions, whose
// messages are structured values.
func structured(trace wireTrace) bool {
	return strings.Contains(trace.schemaURLs[0], "semconv-genai")
}

// messages reads a list of messages as JSON values: text under the 1.41
// conventions, and a structured value under 0.1.
func messages(t *testing.T, trace wireTrace, key string) any {
	t.Helper()
	value, ok := trace.spans[0].attributes[key]
	if !ok {
		return nil
	}
	encoded, text := value.(string)
	if text == structured(trace) {
		t.Fatalf("%s has the wrong form: %T", key, value)
	}
	if !text {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		encoded = string(raw)
	}
	var decoded any
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
		t.Fatalf("%s is not JSON: %v", key, err)
	}
	return decoded
}

func jsonValue(t *testing.T, encoded string) any {
	t.Helper()
	var decoded any
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func expectMessages(t *testing.T, trace wireTrace, key, want string) {
	t.Helper()
	expected := jsonValue(t, want)
	// The 0.1 conventions name a reply's finish reason on the span alone.
	if list, _ := expected.([]any); structured(trace) {
		for _, message := range list {
			if message, ok := message.(map[string]any); ok {
				delete(message, "finish_reason")
			}
		}
	}
	if got := messages(t, trace, key); !reflect.DeepEqual(got, expected) {
		encoded, _ := json.Marshal(got)
		t.Errorf("%s = %s\nwant %s", key, encoded, want)
	}
}

func TestTraceExportConvertsChatCompletionsContent(t *testing.T) {
	for _, v := range []conventions{conventions141, conventions01} {
		request := `{"model":"gpt-5.6-sol","messages":[
			{"role":"system","content":"Answer briefly. <b>&</b>"},
			{"role":"user","name":"ada","content":[
				{"type":"text","text":"What is in these?"},
				{"type":"image_url","image_url":{"url":"https://example.com/cat.png","detail":"low"}},
				{"type":"image_url","image_url":{"url":{"media_type":"image/png","size":3,"sha256":"ab"}}},
				{"type":"input_audio","input_audio":{"data":{"media_type":"audio/wav","size":9,"sha256":"cd"},"format":"wav"}},
				{"type":"file","file":{"file_id":"file-1"}},
				{"type":"file","file":{"file_data":{"media_type":"application/pdf","size":5,"sha256":"ef"},"filename":"a.pdf"}},
				{"type":"future_part","value":1}]},
			{"role":"assistant","content":null,"reasoning":"Look at each.","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"id\":18446744073709551616}"}},
				{"id":"call_2","type":"function","function":{"name":"broken","arguments":"{\"id\":"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"found"},
			{"role":"tool","tool_call_id":"call_2","content":[{"type":"text","text":"none"}]}],
			"tools":[{"type":"function","function":{"name":"lookup","description":"Looks up","parameters":{"type":"object"},"strict":true}}]}`
		wantInput := `[
			{"role":"system","parts":[{"type":"text","content":"Answer briefly. <b>&</b>"}]},
			{"role":"user","name":"ada","parts":[
				{"type":"text","content":"What is in these?"},
				{"type":"uri","modality":"image","uri":"https://example.com/cat.png"},
				{"type":"blob","modality":"image","mime_type":"image/png","size":3,"sha256":"ab"},
				{"type":"blob","modality":"audio","mime_type":"audio/wav","size":9,"sha256":"cd"},
				{"type":"file","modality":"document","file_id":"file-1"},
				{"type":"blob","modality":"document","mime_type":"application/pdf","size":5,"sha256":"ef"},
				{"type":"future_part","value":1}]},
			{"role":"assistant","parts":[
				{"type":"reasoning","content":"Look at each."},
				{"type":"tool_call","id":"call_1","name":"lookup","arguments":{"id":18446744073709551616}},
				{"type":"tool_call","id":"call_2","name":"broken","arguments":"{\"id\":"}]},
			{"role":"tool","parts":[{"type":"tool_call_response","id":"call_1","response":"found"}]},
			{"role":"tool","parts":[{"type":"tool_call_response","id":"call_2","response":[{"type":"text","text":"none"}]}]}]`
		wantTools := `[{"type":"function","name":"lookup","description":"Looks up","parameters":{"type":"object"},"strict":true}]`

		response := `{"id":"chatcmpl-1","choices":[
			{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":"Checking.","reasoning":"Think.","reasoning_content":"Think.","refusal":null,
				"tool_calls":[{"id":"call_3","type":"function","function":{"name":"lookup","arguments":"{}"}}]}},
			{"index":1,"finish_reason":"length","message":{"role":"assistant","content":"Cut","refusal":"No."}}]}`
		wantOutput := `[
			{"role":"assistant","finish_reason":"tool_call","parts":[
				{"type":"reasoning","content":"Think."},{"type":"text","content":"Checking."},{"type":"tool_call","id":"call_3","name":"lookup","arguments":{}}]},
			{"role":"assistant","finish_reason":"length","parts":[{"type":"text","content":"Cut"},{"type":"refusal","content":"No."}]}]`
		buffered := encodeTrace(t, v, traceEvent(), `{}`, Trace{}, &traceBodies{request: []byte(request), response: []byte(response)})
		expectMessages(t, buffered, "gen_ai.input.messages", wantInput)
		expectMessages(t, buffered, "gen_ai.tool.definitions", wantTools)
		expectMessages(t, buffered, "gen_ai.output.messages", wantOutput)
		if _, ok := buffered.spans[0].attributes["gen_ai.system_instructions"]; ok {
			t.Error("a chat history's system message is repeated as instructions")
		}
		// Content keeps its characters: no HTML escapes.
		if encoded, text := buffered.spans[0].attributes["gen_ai.input.messages"].(string); text && !strings.Contains(encoded, "<b>&</b>") {
			t.Errorf("content was escaped: %s", encoded)
		}

		events := [][]byte{
			[]byte(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning":"Thi","reasoning_content":"Thi"}}]}`),
			[]byte(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"reasoning":"nk.","reasoning_content":"nk."}},{"index":1,"delta":{"content":"Cut"}}]}`),
			[]byte(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"Check"}}]}`),
			[]byte(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"ing.","tool_calls":[{"index":0,"id":"call_3","type":"function","function":{"name":"lookup","arguments":""}}]}}]}`),
			[]byte(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{"}}]}},{"index":1,"delta":{"refusal":"No."},"finish_reason":"length"}]}`),
			[]byte(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"}"}}]},"finish_reason":"tool_calls"}]}`),
			[]byte(`{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":1}}`),
		}
		streamed := encodeTrace(t, v, traceEvent(), `{}`, Trace{}, &traceBodies{request: []byte(request), events: events})
		expectMessages(t, streamed, "gen_ai.output.messages", wantOutput)

		// A stream that ended early has no finish reason of its own, and takes the record's.
		cut := encodeTrace(t, v, traceEvent(), `{}`, Trace{}, &traceBodies{events: [][]byte{
			[]byte(`{"choices":[{"index":0,"delta":{"content":"Par"}}]}`), []byte(`{"error":{"message":"The provider stopped","code":"provider_error"}}`)}})
		expectMessages(t, cut, "gen_ai.output.messages", `[{"role":"assistant","finish_reason":"tool_call","parts":[{"type":"text","content":"Par"}]}]`)

		// A failure reply holds no message.
		for _, bodies := range []*traceBodies{{response: []byte(`{"error":{"message":"No"}}`)}, {events: [][]byte{[]byte(`{"error":{"message":"No"}}`)}}, {}} {
			if failed := encodeTrace(t, v, traceEvent(), `{}`, Trace{}, bodies); messages(t, failed, "gen_ai.output.messages") != nil || messages(t, failed, "gen_ai.input.messages") != nil {
				t.Error("a failure reply or a missing request made messages")
			}
		}
	}
}

func TestTraceExportConvertsResponsesContent(t *testing.T) {
	for _, v := range []conventions{conventions141, conventions01} {
		event := traceEvent()
		event.Interface, _ = billing.RequestShape(string(schemas.ResponsesRequest))
		event.ProviderAttempts[1].FinishReason = "stop"
		request := `{"model":"gpt-5.6-sol","instructions":"Answer briefly.","input":[
			{"role":"user","content":"Hi"},
			{"type":"message","role":"user","content":[
				{"type":"input_text","text":"What is this?"},
				{"type":"input_image","image_url":"https://example.com/cat.png"},
				{"type":"input_image","file_id":"file-1"},
				{"type":"input_file","file_data":{"media_type":"application/pdf","size":5,"sha256":"ef"},"filename":"a.pdf"},
				{"type":"input_file","file_url":"https://example.com/a.pdf"}]},
			{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"First."},{"type":"summary_text","text":"Second."}],"encrypted_content":"opaque"},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"A cat."}]},
			{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{\"q\":\"cat\"}"},
			{"type":"web_search_call","id":"ws_1","status":"completed"},
			{"type":"function_call_output","call_id":"call_1","output":"found"},
			{"type":"custom_tool_call","call_id":"call_2","name":"shell","input":"ls"},
			{"type":"custom_tool_call_output","call_id":"call_2","output":"a.txt"},
			{"type":"computer_call_output","call_id":"call_3","output":{"type":"computer_screenshot"}},
			{"type":"shell_call","id":"sh_1","call_id":"call_5","action":{"commands":["ls"]},"status":"completed"},
			{"type":"shell_call_output","call_id":"call_5","output":[{"stdout":"a.txt","stderr":""}]},
			{"type":"apply_patch_call","call_id":"call_6","operation":{"type":"update_file","path":"a.txt","diff":"@@"}},
			{"type":"apply_patch_call_output","call_id":"call_6","status":"failed"},
			{"type":"tool_search_call","id":"ts_1","execution":"server","call_id":null,"arguments":{"query":"weather"}},
			{"type":"tool_search_output","id":"tso_1","execution":"server","call_id":null,"tools":[]},
			{"type":"mcp_call","id":"mcp_1","server_label":"docs","name":"search","arguments":"{}","output":"found"},
			{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true}],
			"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}},{"type":"web_search","search_context_size":"low"}]}`
		wantInput := `[
			{"role":"user","parts":[{"type":"text","content":"Hi"}]},
			{"role":"user","parts":[
				{"type":"text","content":"What is this?"},
				{"type":"uri","modality":"image","uri":"https://example.com/cat.png"},
				{"type":"file","modality":"image","file_id":"file-1"},
				{"type":"blob","modality":"document","mime_type":"application/pdf","size":5,"sha256":"ef"},
				{"type":"uri","modality":"document","uri":"https://example.com/a.pdf"}]},
			{"role":"assistant","parts":[
				{"type":"reasoning","content":"First.\n\nSecond."},
				{"type":"text","content":"A cat."},
				{"type":"tool_call","id":"call_1","name":"lookup","arguments":{"q":"cat"}},
				{"type":"server_tool_call","id":"ws_1","name":"web_search","server_tool_call":{"type":"web_search","status":"completed"}}]},
			{"role":"tool","parts":[{"type":"tool_call_response","id":"call_1","response":"found"}]},
			{"role":"assistant","parts":[{"type":"tool_call","id":"call_2","name":"shell","arguments":"ls"}]},
			{"role":"tool","parts":[{"type":"tool_call_response","id":"call_2","response":"a.txt"}]},
			{"role":"tool","parts":[{"type":"tool_call_response","id":"call_3","response":{"type":"computer_screenshot"}}]},
			{"role":"assistant","parts":[{"type":"tool_call","id":"call_5","name":"shell","arguments":{"commands":["ls"]}}]},
			{"role":"tool","parts":[{"type":"tool_call_response","id":"call_5","response":[{"stdout":"a.txt","stderr":""}]}]},
			{"role":"assistant","parts":[{"type":"tool_call","id":"call_6","name":"apply_patch","arguments":{"type":"update_file","path":"a.txt","diff":"@@"}}]},
			{"role":"tool","parts":[{"type":"tool_call_response","id":"call_6","response":{"status":"failed"}}]},
			{"role":"assistant","parts":[
				{"type":"server_tool_call","id":"ts_1","name":"tool_search","server_tool_call":{"type":"tool_search","execution":"server","call_id":null,"arguments":{"query":"weather"}}},
				{"type":"server_tool_call_response","server_tool_call_response":{"type":"tool_search","execution":"server","call_id":null,"tools":[]}},
				{"type":"server_tool_call","id":"mcp_1","name":"search","server_tool_call":{"type":"mcp","server_label":"docs","name":"search","arguments":"{}","output":"found"}}]},
			{"role":"tool","parts":[{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true}]}]`
		output := `[
			{"type":"reasoning","id":"rs_2","summary":[],"content":[{"type":"reasoning_text","text":"Think."}]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Done.","annotations":[]},{"type":"refusal","refusal":"No more."}]},
			{"type":"function_call","call_id":"call_4","name":"lookup","arguments":"{}"}]`
		wantOutput := `[{"role":"assistant","finish_reason":"stop","parts":[
			{"type":"reasoning","content":"Think."},{"type":"text","content":"Done."},{"type":"refusal","content":"No more."},
			{"type":"tool_call","id":"call_4","name":"lookup","arguments":{}}]}]`
		buffered := encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{request: []byte(request), response: []byte(`{"id":"resp_1","status":"completed","output":` + output + `}`)})
		expectMessages(t, buffered, "gen_ai.system_instructions", `[{"type":"text","content":"Answer briefly."}]`)
		expectMessages(t, buffered, "gen_ai.input.messages", wantInput)
		expectMessages(t, buffered, "gen_ai.tool.definitions", `[{"type":"function","name":"lookup","parameters":{"type":"object"}},{"type":"web_search","name":"web_search","search_context_size":"low"}]`)
		expectMessages(t, buffered, "gen_ai.output.messages", wantOutput)

		text := encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{request: []byte(`{"input":"Hi"}`)})
		expectMessages(t, text, "gen_ai.input.messages", `[{"role":"user","parts":[{"type":"text","content":"Hi"}]}]`)

		// The event that ends a stream holds the whole response.
		items := []string{
			`{"type":"reasoning","id":"rs_2","summary":[],"content":[{"type":"reasoning_text","text":"Think."}]}`,
			`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Done.","annotations":[]},{"type":"refusal","refusal":"No more."}]}`,
			`{"type":"function_call","call_id":"call_4","name":"lookup","arguments":"{}"}`,
		}
		events := [][]byte{[]byte(`{"type":"response.created","response":{"output":[]}}`), []byte(`{"type":"response.output_text.delta","delta":"Do"}`)}
		for _, item := range items {
			events = append(events, []byte(`{"type":"response.output_item.done","item":`+item+`}`))
		}
		ended := append(events[:len(events):len(events)], []byte(`{"type":"response.completed","response":{"status":"completed","output":`+output+`}}`))
		expectMessages(t, encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{events: ended}), "gen_ai.output.messages", wantOutput)
		// A stream that stopped before that event keeps the items that had finished.
		expectMessages(t, encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{events: events}), "gen_ai.output.messages", wantOutput)
	}
}

// A Messages request runs as a Responses request, whose form the capture
// keeps, and its reply is Claude's: a message, or the events of its stream.
func TestTraceExportConvertsMessagesContent(t *testing.T) {
	for _, v := range []conventions{conventions141, conventions01} {
		event := traceEvent()
		event.Interface = "messages"
		event.ProviderAttempts[1].FinishReason = "tool_use"
		request := `{"model":"claude-sonnet-5-5","instructions":"Answer briefly.","input":[{"role":"user","content":"Hi"}],
			"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]}`
		content := `[
			{"type":"thinking","thinking":"Think.","signature":"sig"},
			{"type":"redacted_thinking","data":"opaque"},
			{"type":"text","text":"Checking.","citations":null},
			{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{"query":"cats"}},
			{"type":"web_search_tool_result","tool_use_id":"srvtoolu_1","content":[{"type":"web_search_result","url":"https://example.com","title":"Cats"}]},
			{"type":"tool_use","id":"toolu_1","name":"lookup","input":{"id":1}}]`
		wantOutput := `[{"role":"assistant","finish_reason":"tool_call","parts":[
			{"type":"reasoning","content":"Think."},
			{"type":"redacted_thinking","data":"opaque"},
			{"type":"text","content":"Checking."},
			{"type":"server_tool_call","id":"srvtoolu_1","name":"web_search","server_tool_call":{"type":"web_search","name":"web_search","input":{"query":"cats"}}},
			{"type":"server_tool_call_response","id":"srvtoolu_1","server_tool_call_response":{"type":"web_search","content":[{"type":"web_search_result","url":"https://example.com","title":"Cats"}]}},
			{"type":"tool_call","id":"toolu_1","name":"lookup","arguments":{"id":1}}]}]`
		reply := `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-5-5","content":` + content + `,"stop_reason":"tool_use"}`
		buffered := encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{request: []byte(request), response: []byte(reply)})
		expectMessages(t, buffered, "gen_ai.system_instructions", `[{"type":"text","content":"Answer briefly."}]`)
		expectMessages(t, buffered, "gen_ai.input.messages", `[{"role":"user","parts":[{"type":"text","content":"Hi"}]}]`)
		expectMessages(t, buffered, "gen_ai.tool.definitions", `[{"type":"function","name":"lookup","parameters":{"type":"object"}}]`)
		expectMessages(t, buffered, "gen_ai.output.messages", wantOutput)

		events := [][]byte{
			[]byte(`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"stop_reason":null}}`),
			[]byte(`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`),
			[]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Thi"}}`),
			[]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"nk."}}`),
			[]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}`),
			[]byte(`{"type":"content_block_stop","index":0}`),
			[]byte(`{"type":"content_block_start","index":1,"content_block":{"type":"redacted_thinking","data":"opaque"}}`),
			[]byte(`{"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`),
			[]byte(`{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"Check"}}`),
			[]byte(`{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"ing."}}`),
			[]byte(`{"type":"content_block_start","index":3,"content_block":{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{}}}`),
			[]byte(`{"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":""}}`),
			[]byte(`{"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":"{\"query\": \"cats\"}"}}`),
			[]byte(`{"type":"content_block_start","index":4,"content_block":{"type":"web_search_tool_result","tool_use_id":"srvtoolu_1","content":[{"type":"web_search_result","url":"https://example.com","title":"Cats"}]}}`),
			[]byte(`{"type":"content_block_start","index":5,"content_block":{"type":"tool_use","id":"toolu_1","name":"lookup","input":{}}}`),
			[]byte(`{"type":"content_block_delta","index":5,"delta":{"type":"input_json_delta","partial_json":"{\"id\""}}`),
			[]byte(`{"type":"content_block_delta","index":5,"delta":{"type":"input_json_delta","partial_json":":1}"}}`),
			[]byte(`{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":9}}`),
			[]byte(`{"type":"message_stop"}`),
		}
		expectMessages(t, encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{request: []byte(request), events: events}), "gen_ai.output.messages", wantOutput)

		// A stream that stopped early keeps the input that had arrived, as text, and takes the
		// record's finish reason.
		cut := append(events[:16:16], []byte(`{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`))
		expectMessages(t, encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{events: cut}), "gen_ai.output.messages", `[{"role":"assistant","finish_reason":"tool_call","parts":[
			{"type":"reasoning","content":"Think."},
			{"type":"redacted_thinking","data":"opaque"},
			{"type":"text","content":"Checking."},
			{"type":"server_tool_call","id":"srvtoolu_1","name":"web_search","server_tool_call":{"type":"web_search","name":"web_search","input":{"query":"cats"}}},
			{"type":"server_tool_call_response","id":"srvtoolu_1","server_tool_call_response":{"type":"web_search","content":[{"type":"web_search_result","url":"https://example.com","title":"Cats"}]}},
			{"type":"tool_call","id":"toolu_1","name":"lookup","arguments":"{\"id\""}]}]`)

		// A compaction summary arrives in its delta.
		compacted := encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{events: [][]byte{
			[]byte(`{"type":"message_start","message":{"role":"assistant","content":[]}}`),
			[]byte(`{"type":"content_block_start","index":0,"content_block":{"type":"compaction","content":null}}`),
			[]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"compaction_delta","content":"Summary.","encrypted_content":"opaque"}}`),
			[]byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"}}`),
		}})
		expectMessages(t, compacted, "gen_ai.output.messages", `[{"role":"assistant","finish_reason":"stop","parts":[{"type":"compaction","content":"Summary.","encrypted_content":"opaque"}]}]`)

		// An error reply holds no message.
		failure := []byte(`{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`)
		for _, bodies := range []*traceBodies{{response: failure}, {events: [][]byte{failure}}} {
			if failed := encodeTrace(t, v, event, `{}`, Trace{}, bodies); messages(t, failed, "gen_ai.output.messages") != nil {
				t.Error("an error reply made messages")
			}
		}
	}
}

// A long value needs a length of several bytes, which the encoder writes after
// the value.
func TestTraceExportEncodesLongAndNestedValues(t *testing.T) {
	for _, v := range []conventions{conventions141, conventions01} {
		event := traceEvent()
		long := strings.Repeat("é", 100_000)
		event.Metadata = map[string]string{"long": long, "short": "x"}
		request := `{"messages":[{"role":"user","content":"` + long + `"}]}`
		trace := encodeTrace(t, v, event, `{}`, Trace{}, &traceBodies{request: []byte(request)})
		root := trace.spans[0]
		if root.attributes["stogas.metadata.long"] != long || root.attributes["stogas.metadata.short"] != "x" || len(trace.spans) != 3 {
			t.Fatal("a long attribute changed the spans")
		}
		expectMessages(t, trace, "gen_ai.input.messages", `[{"role":"user","parts":[{"type":"text","content":"`+long+`"}]}]`)
	}
}

func TestTraceExportRefusesARecordWithoutItsRequest(t *testing.T) {
	for _, event := range []string{`{}`, `[]`, `{"request_id":"id"}`, `{"request_id":"id","created_at":"yesterday"}`, `null`} {
		if _, err := traceExport([]byte(event), nil, Trace{}, nil, conventions01); err == nil {
			t.Errorf("%s made a trace", event)
		}
	}
}

// One request reaches each destination in its own format, with the bodies that
// the destination takes.
func TestDestinationsGetTheirOwnFormat(t *testing.T) {
	type delivery struct {
		contentType, key string
		body             []byte
	}
	var mu sync.Mutex
	got := map[string]delivery{}
	receiver := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got[r.URL.Path] = delivery{r.Header.Get("Content-Type"), r.Header.Get("Idempotency-Key"), body}
		mu.Unlock()
	}))
	defer receiver.Close()
	e := New(context.Background(), testOptions(true, 1<<20))
	defer e.Close()
	none := exportconfig.Content{}
	config := &exportconfig.Config{Destinations: []exportconfig.Destination{
		{URL: receiver.URL + "/json"},
		{URL: receiver.URL + "/v1/traces", Format: exportconfig.FormatOTLPGenAI141},
		{URL: receiver.URL + "/metadata/v1/traces", Format: exportconfig.FormatOTLPGenAI141, Content: &none},
		{URL: receiver.URL + "/latest/v1/traces", Format: exportconfig.FormatOTLPGenAI01},
	}}
	c := e.Start(config, "req_trace", "", Trace{Model: "gpt-5.6-sol", TraceID: testTraceID, ParentSpanID: testParentID})
	c.Input(map[string]json.RawMessage{"messages": json.RawMessage(`[{"role":"user","content":"Hi"}]`)}, false)
	c.Response([]byte(`{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"Hello"}}]}`))
	c.Finish("req_trace", "success", traceEvent(), testMetadata())
	await(t, func() bool { return e.Diagnostics().Delivered == 4 })
	if e.Diagnostics().ReservedBytes != 0 {
		t.Fatal("delivered records keep memory")
	}
	if posted := got["/json"]; posted.contentType != "application/json" || !json.Valid(posted.body) || !strings.Contains(string(posted.body), `"request":{"messages"`) {
		t.Fatalf("unexpected JSON delivery: %s %s", posted.contentType, posted.body)
	}
	full, bare, latest := got["/v1/traces"], got["/metadata/v1/traces"], got["/latest/v1/traces"]
	if full.contentType != "application/x-protobuf" || bare.contentType != "application/x-protobuf" || latest.contentType != "application/x-protobuf" || full.key != "req_trace" {
		t.Fatalf("unexpected trace deliveries: %q %q %q %q", full.contentType, bare.contentType, latest.contentType, full.key)
	}
	// The latest conventions get the same messages as structured values.
	structuredContent := decodeTrace(t, latest.body)
	if !structured(structuredContent) {
		t.Fatalf("the 0.1 destination got %v", structuredContent.schemaURLs)
	}
	expectMessages(t, structuredContent, "gen_ai.input.messages", `[{"role":"user","parts":[{"type":"text","content":"Hi"}]}]`)
	expectMessages(t, structuredContent, "gen_ai.output.messages", `[{"role":"assistant","parts":[{"type":"text","content":"Hello"}]}]`)
	withContent, withoutContent := decodeTrace(t, full.body), decodeTrace(t, bare.body)
	if root := withContent.spans[0]; root.traceID != testTraceID || root.parentID != testParentID || root.name != "chat gpt-5.6-sol" {
		t.Fatalf("unexpected span: %+v", root)
	}
	expectMessages(t, withContent, "gen_ai.input.messages", `[{"role":"user","parts":[{"type":"text","content":"Hi"}]}]`)
	expectMessages(t, withContent, "gen_ai.output.messages", `[{"role":"assistant","finish_reason":"stop","parts":[{"type":"text","content":"Hello"}]}]`)
	if messages(t, withoutContent, "gen_ai.input.messages") != nil || messages(t, withoutContent, "gen_ai.output.messages") != nil ||
		withoutContent.spans[0].attributes["gen_ai.usage.input_tokens"] != int64(120) {
		t.Fatalf("a destination without content got bodies or lost usage: %v", withoutContent.spans[0].attributes)
	}

	// A rejection's export keeps the trace until its record is complete.
	c = e.Start(&exportconfig.Config{Destinations: config.Destinations[1:2]}, "req_rejected", "", Trace{Model: "gpt-5.6-sol", TraceID: testTraceID, ParentSpanID: testParentID})
	rejected := traceEvent()
	rejected.RequestID, rejected.ProviderAttempts, rejected.GatewayError = "req_rejected", nil, &billing.EventError{Code: "insufficient_balance", Status: 402}
	c.Hold().Finish("req_rejected", "rejected", rejected, testMetadata())
	await(t, func() bool { return e.Diagnostics().Delivered == 5 })
	mu.Lock()
	defer mu.Unlock()
	if root := decodeTrace(t, got["/v1/traces"].body).spans[0]; root.parentID != testParentID || root.name != "chat gpt-5.6-sol" || root.attributes["error.type"] != "insufficient_balance" {
		t.Fatalf("unexpected rejection span: %+v", root)
	}
}

// Memory that the trace cannot have ends the capture, as every refused
// admission does, and counts each of its destinations.
func TestTraceExportDropsWithoutMemory(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer receiver.Close()
	e := New(context.Background(), testOptions(true, 64<<10))
	defer e.Close()
	config := &exportconfig.Config{Destinations: []exportconfig.Destination{
		{URL: receiver.URL}, {URL: receiver.URL, Format: exportconfig.FormatOTLPGenAI141}, {URL: receiver.URL, Format: exportconfig.FormatOTLPGenAI01},
	}}
	c := e.Start(config, "id", "", Trace{})
	c.Response([]byte(`{"choices":[{"message":{"role":"assistant","content":"` + strings.Repeat("x", 16<<10) + `"}}]}`))
	c.Finish("id", "success", traceEvent(), testMetadata())
	if d := e.Diagnostics(); d.MemoryDropped != 3 || d.ReservedBytes != 0 || d.PendingDeliveries != 0 || c.held() {
		t.Fatalf("unexpected diagnostics: %+v", d)
	}
}
