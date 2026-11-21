package exporter

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"math"
	"slices"
	"strconv"
	"time"
)

const (
	traceService = "stogas-gateway"
	traceScope   = "stogas.gateway.export"

	spanKindInternal = 1
	spanKindClient   = 3
	statusCodeError  = 2
)

// conventions is the version of the OpenTelemetry GenAI semantic conventions
// that a trace follows: 1.41, the last release of semantic conventions that
// held them, or 0.1, the first release of their own repository. 0.1 renamed
// the cache write tokens, added the reasoning level, and made messages
// structured values without finish reasons.
type conventions int

const (
	conventions141 conventions = iota
	conventions01
)

// schemaURLs are the schemas of a trace's resource and of its spans. The 0.1
// conventions build on semantic conventions 1.45, which name the resource.
func (v conventions) schemaURLs() (resource, spans string) {
	if v == conventions01 {
		return "https://opentelemetry.io/schemas/1.45.0", "https://opentelemetry.io/schemas/semconv-genai-dev/0.1.0-dev"
	}
	return "https://opentelemetry.io/schemas/1.41.0", "https://opentelemetry.io/schemas/1.41.0"
}

var errTraceRecord = errors.New("export record has no trace form")

// traceBodies are the captured bodies of a record that a destination gets with
// content.
type traceBodies struct {
	request, response []byte
	events            [][]byte
}

// traceExport encodes a request record as one OTLP ExportTraceServiceRequest.
// The request is one span with the GenAI attributes and every other field of
// the record under "stogas.", and each provider attempt and each tool call
// that a stream timed is a child span. A trace tool then counts one model call
// for each request, with its tokens, and shows the attempts and the time of
// each tool call inside it. The IDs come from the request ID, so a retried
// delivery repeats them, and the trace is the caller's when the request named
// one.
func traceExport(event, metadata []byte, trace Trace, bodies *traceBodies, v conventions) ([]byte, error) {
	record, err := decodeObject(event)
	if err != nil {
		return nil, err
	}
	requestID, _ := record["request_id"].(string)
	start, err := time.Parse(time.RFC3339, text(record["created_at"]))
	if requestID == "" || err != nil {
		return nil, errTraceRecord
	}
	performance, _ := record["performance"].(map[string]any)
	end := start.Add(milliseconds(performance["total_ms"]))
	// The record of repeated rejections covers them all.
	if last, err := time.Parse(time.RFC3339, text(record["last_request_at"])); err == nil && last.After(end) {
		end = last
	}
	sum := sha256.Sum256([]byte(requestID))
	traceID, rootID := sum[:16], sum[16:24]
	var parentID []byte
	if id, err := hex.DecodeString(text(record["trace_id"])); err == nil && len(id) == 16 {
		traceID = id
		// The record of repeated rejections can hold another request's trace.
		if text(record["trace_id"]) == trace.TraceID {
			parentID, _ = hex.DecodeString(trace.ParentSpanID)
		}
	}
	attempts, _ := record["provider_attempts"].([]any)
	var served map[string]any
	if len(attempts) > 0 {
		served, _ = attempts[len(attempts)-1].(map[string]any)
	}

	p := protobuf{data: make([]byte, 0, traceSize(len(event)+len(metadata), bodies)), conventions: v}
	if bodies != nil && v == conventions01 {
		p.text = make([]byte, 0, bodies.textSize())
	}
	resourceSchema, spanSchema := v.schemaURLs()
	resourceSpans := p.open(1)
	resource := p.open(1)
	p.attribute(1, "service.name", traceService)
	p.attribute(1, "service.version", record["gateway_version"])
	p.close(resource)
	scopeSpans := p.open(2)
	scope := p.open(1)
	p.string(1, traceScope)
	p.close(scope)

	root := p.open(2)
	p.bytes(1, traceID)
	p.bytes(2, rootID)
	if len(parentID) == 8 {
		p.bytes(4, parentID)
	}
	p.string(5, spanName(traceOperation(record), trace.Model))
	p.varint(6, spanKindClient)
	p.fixed64(7, uint64(start.UnixNano()))
	p.fixed64(8, uint64(end.UnixNano()))
	failure, finish := requestFailure(record, served), requestFinish(record, served)
	p.genAIAttributes(record, served, trace.Model, failure, finish)
	if bodies != nil {
		p.contentAttributes(text(record["interface"]) == "responses", finish, bodies)
	}
	for _, key := range sortedKeys(record) {
		// These three are the trace, its conversation and its child spans.
		if key != "trace_id" && key != "session_id" && key != "provider_attempts" {
			p.flatten(9, "stogas."+key, record[key])
		}
	}
	// The metadata repeats the record's usage and times. These are its own.
	if extra, err := decodeObject(metadata); err == nil {
		for _, key := range []string{"catalog", "policy_versions_sha512", "provider", "receipt"} {
			p.flatten(9, "stogas."+key, extra[key])
		}
	}
	p.status(failure)
	p.close(root)

	for i, value := range attempts {
		attempt, _ := value.(map[string]any)
		id := sha256.Sum256([]byte(requestID + "/attempt/" + strconv.Itoa(i)))
		began := start.Add(milliseconds(attempt["start_ms"]))
		span := p.open(2)
		p.bytes(1, traceID)
		p.bytes(2, id[:8])
		p.bytes(4, rootID)
		p.string(5, spanName("provider_attempt", text(attempt["provider"])))
		p.varint(6, spanKindClient)
		p.fixed64(7, uint64(began.UnixNano()))
		p.fixed64(8, uint64(began.Add(milliseconds(attempt["latency_ms"])).UnixNano()))
		failure := attemptFailure(attempt)
		if failure != "" {
			p.attribute(9, "error.type", failure)
		}
		if status, ok := attempt["status_code"].(json.Number); ok {
			p.attribute(9, "http.response.status_code", status)
		}
		p.flatten(9, "stogas.attempt", attempt)
		p.status(failure)
		p.close(span)
	}
	// A stream times its tool calls: each runs from when the stream added the
	// call until it marked the call done, or until the response ended first.
	// The span holds no GenAI attribute, because the conventions' tool span
	// requires the tool's name, which no record keeps.
	calls, _ := performance["tool_calls"].([]any)
	for i, value := range calls {
		call, _ := value.(map[string]any)
		if call["start_ms"] == nil {
			continue
		}
		id := sha256.Sum256([]byte(requestID + "/tool_call/" + strconv.Itoa(i)))
		began := start.Add(milliseconds(call["start_ms"]))
		done := end
		if call["latency_ms"] != nil {
			done = began.Add(milliseconds(call["latency_ms"]))
		}
		span := p.open(2)
		p.bytes(1, traceID)
		p.bytes(2, id[:8])
		p.bytes(4, rootID)
		p.string(5, spanName("tool_call", text(call["type"])))
		p.varint(6, spanKindInternal)
		p.fixed64(7, uint64(began.UnixNano()))
		p.fixed64(8, uint64(max(done.UnixNano(), began.UnixNano())))
		p.flatten(9, "stogas.tool_call", call)
		p.close(span)
	}
	p.string(3, spanSchema)
	p.close(scopeSpans)
	p.string(3, resourceSchema)
	p.close(resourceSpans)
	return p.data, nil
}

// traceSize is the room that a trace starts with: the record's fields, whose
// names are longer as attributes, and each buffered body once, as the messages
// copy their text. A stream's output is far smaller than its events, and
// grows the trace as it is written.
func traceSize(record int, bodies *traceBodies) int {
	size := 2*record + 4<<10
	if bodies != nil {
		size += len(bodies.request) + len(bodies.response)
	}
	return size
}

// textSize is the room for the JSON text of one list of messages, which
// structured messages are decoded from: about the size of the body that the
// list comes from, or of a stream's joined events.
func (b *traceBodies) textSize() int {
	joined := 0
	for _, event := range b.events {
		joined += len(event)
	}
	return max(len(b.request), len(b.response), joined) + 4<<10
}

// traceForm builds the record's trace form within admitted memory: the trace
// itself, while a stream's deltas are joined, their text, which is no longer
// than the events, and for structured messages, the text of each list. It
// ends the capture, as every refused admission does, when memory or the
// record fails.
func (c *Capture) traceForm(event []byte, f form) ([]byte, bool) {
	v, content := f.trace()
	var bodies *traceBodies
	joined := 0
	if content {
		bodies = &traceBodies{request: c.request, response: c.response, events: c.events}
		for _, event := range c.events {
			joined += len(event)
		}
		if v == conventions01 {
			joined += bodies.textSize()
		}
	}
	size := traceSize(len(event)+len(c.metadata), bodies)
	scratch := &reservation{engine: c.engine, lease: c.engine.options.NewLease()}
	defer scratch.release()
	if !scratch.grow(joined) {
		c.engine.memoryDropped.Add(uint64(len(c.destinations)))
		c.Discard()
		return nil, false
	}
	if !c.grow(size) {
		return nil, false
	}
	trace, err := traceExport(event, c.metadata, c.trace, bodies, v)
	if err != nil {
		c.engine.failed.Add(uint64(len(c.destinations)))
		c.Discard()
		return nil, false
	}
	if !c.grow(cap(trace) - size) {
		clear(trace)
		return nil, false
	}
	return trace, true
}

func (p *protobuf) genAIAttributes(record, served map[string]any, model, failure, finish string) {
	p.attribute(9, "gen_ai.operation.name", traceOperation(record))
	// A request that no provider received has no provider to name.
	p.attribute(9, "gen_ai.provider.name", traceProvider(text(served["provider"])))
	if failure != "" {
		p.attribute(9, "error.type", failure)
	}
	p.attribute(9, "gen_ai.conversation.id", record["session_id"])
	p.attribute(9, "gen_ai.request.model", model)
	settings, _ := record["request_settings"].(map[string]any)
	switch text(settings["response_format"]) {
	case "json_object", "json_schema":
		p.attribute(9, "gen_ai.output.type", "json")
	case "text":
		p.attribute(9, "gen_ai.output.type", "text")
	}
	for _, setting := range [...][2]string{
		{"seed", "seed"}, {"top_k", "top_k"}, {"frequency_penalty", "frequency_penalty"},
		{"max_tokens", "max_output_tokens"}, {"presence_penalty", "presence_penalty"},
		{"temperature", "temperature"}, {"top_p", "top_p"},
	} {
		p.attribute(9, "gen_ai.request."+setting[0], settings[setting[1]])
	}
	// The settings hold the effort as the gateway sent it to the provider.
	if p.conventions == conventions01 {
		p.attribute(9, "gen_ai.request.reasoning.level", settings["reasoning_effort"])
	}
	if stream, _ := record["stream"].(bool); stream {
		p.attribute(9, "gen_ai.request.stream", true)
	}
	if finish != "" {
		p.attribute(9, "gen_ai.response.finish_reasons", []any{finish})
	}
	p.attribute(9, "gen_ai.response.id", served["provider_response_id"])
	p.attribute(9, "gen_ai.response.model", served["provider_model"])
	performance, _ := record["performance"].(map[string]any)
	if first, ok := performance["ttft_ms"].(json.Number); ok {
		if ms, err := first.Float64(); err == nil {
			p.attribute(9, "gen_ai.response.time_to_first_chunk", ms/1000)
		}
	}
	usage, _ := record["usage"].(map[string]any)
	meters, _ := usage["meters"].(map[string]any)
	cacheWrite := "cache_creation.input_tokens"
	if p.conventions == conventions01 {
		cacheWrite = "cache_write.input_tokens"
	}
	// The conventions ask for the cache and reasoning counts among the totals
	// only when they are not zero.
	for _, meter := range [...][2]string{
		{cacheWrite, "total_cache_write_tokens"}, {"cache_read.input_tokens", "cached_input_tokens"},
		{"input_tokens", "total_input_tokens"}, {"output_tokens", "total_output_tokens"},
		{"reasoning.output_tokens", "reasoning_tokens"},
	} {
		counted, _ := meters[meter[1]].(map[string]any)
		quantity, err := strconv.ParseInt(text(counted["quantity"]), 10, 64)
		if err == nil && (quantity != 0 || meter[0] == "input_tokens" || meter[0] == "output_tokens") {
			p.attribute(9, "gen_ai.usage."+meter[0], json.Number(strconv.FormatInt(quantity, 10)))
		}
	}
}

// traceOperation names every text generation interface "chat", as the
// conventions do for both of OpenAI's.
func traceOperation(record map[string]any) string {
	switch name := text(record["interface"]); name {
	case "", "chat_completions", "responses":
		return "chat"
	default:
		return name
	}
}

// traceProvider gives the conventions' name of a catalog provider that has
// one. Azure serves models of several authors, so it takes the name that
// covers them all.
func traceProvider(provider string) string {
	switch provider {
	case "aws":
		return "aws.bedrock"
	case "azure":
		return "azure.ai.inference"
	case "google-cloud":
		return "gcp.vertex_ai"
	}
	return provider
}

// finishReason spells a finish reason as the conventions' output messages do.
// A Chat Completions reply has OpenAI's reasons, and a Responses reply the
// provider's own.
func finishReason(reason string) string {
	switch reason {
	case "tool_calls", "function_call", "tool_use":
		return "tool_call"
	case "max_output_tokens", "max_tokens":
		return "length"
	case "end_turn", "stop_sequence":
		return "stop"
	case "refusal":
		return "content_filter"
	}
	return reason
}

// requestFinish is why the reply ended, empty for a request that no provider
// received. A reply that ended without a reason was interrupted when the
// client stopped it, and otherwise ended in error, as the conventions name
// them. The Responses interface names no reason for a reply that ended on its
// own, which ended for its client tool calls when it has some, as a Chat
// Completions reply says of itself.
func requestFinish(record, served map[string]any) string {
	if served == nil {
		return ""
	}
	if reason := finishReason(text(served["finish_reason"])); reason != "" {
		return reason
	}
	switch status := text(served["status"]); {
	case record["client_stop_ms"] != nil:
		return "interrupted"
	case status == "content_filter":
		return "content_filter"
	case status != "success":
		return "error"
	}
	performance, _ := record["performance"].(map[string]any)
	calls, _ := performance["tool_calls"].([]any)
	for _, value := range calls {
		// Only a call that the client runs has an ID for its result.
		if call, _ := value.(map[string]any); text(call["call_id_hash"]) != "" {
			return "tool_call"
		}
	}
	return "stop"
}

// requestFailure names the error that ended the request, empty when none did:
// the gateway's own, or else that of the last provider attempt.
func requestFailure(record, served map[string]any) string {
	if failure, _ := record["gateway_error"].(map[string]any); text(failure["code"]) != "" {
		return text(failure["code"])
	}
	if served == nil || record["client_stop_ms"] != nil {
		return ""
	}
	return attemptFailure(served)
}

// attemptFailure is the attempt's status when the call ended in an error. A
// call that the caller ended is no error, and nor is a reply that a content
// filter stopped or that refused, which has a finish reason: a provider that
// refused the request with an error reply gives none.
func attemptFailure(attempt map[string]any) string {
	switch status := text(attempt["status"]); status {
	case "success", "unknown", "cancelled":
		return ""
	case "content_filter":
		if text(attempt["finish_reason"]) != "" {
			return ""
		}
		return status
	default:
		return status
	}
}

func spanName(operation, subject string) string {
	if subject == "" {
		return operation
	}
	return operation + " " + subject
}

func decodeObject(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// Numbers keep their digits, so an integer stays one.
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errTraceRecord
	}
	return object, nil
}

// text reads a string, or a number's digits.
func text(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	return ""
}

func milliseconds(value any) time.Duration {
	n, _ := strconv.ParseInt(text(value), 10, 64)
	return time.Duration(max(n, 0)) * time.Millisecond
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// protobuf appends the wire form of the OTLP messages, whose field numbers
// opentelemetry-proto's trace/v1, common/v1 and resource/v1 give. Under the
// 0.1 conventions, text holds the JSON text of a list of messages, which is
// then written as a structured value.
type protobuf struct {
	data, text  []byte
	conventions conventions
}

func (p *protobuf) tag(field, wire int) {
	p.data = binary.AppendUvarint(p.data, uint64(field)<<3|uint64(wire))
}

func (p *protobuf) varint(field int, value uint64) {
	p.tag(field, 0)
	p.data = binary.AppendUvarint(p.data, value)
}

func (p *protobuf) fixed64(field int, value uint64) {
	p.tag(field, 1)
	p.data = binary.LittleEndian.AppendUint64(p.data, value)
}

func (p *protobuf) bytes(field int, value []byte) {
	p.tag(field, 2)
	p.data = binary.AppendUvarint(p.data, uint64(len(value)))
	p.data = append(p.data, value...)
}

func (p *protobuf) string(field int, value string) {
	p.tag(field, 2)
	p.data = binary.AppendUvarint(p.data, uint64(len(value)))
	p.data = append(p.data, value...)
}

// open starts a nested message and close writes its length, which takes one
// byte until the message is known to need more.
func (p *protobuf) open(field int) int {
	p.tag(field, 2)
	p.data = append(p.data, 0)
	return len(p.data)
}

func (p *protobuf) close(start int) {
	size := len(p.data) - start
	var length [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(length[:], uint64(size))
	p.data = append(p.data, length[:n-1]...)
	copy(p.data[start+n-1:], p.data[start:start+size])
	copy(p.data[start-1:], length[:n])
}

// attribute writes a KeyValue, and nothing for a value that says nothing: nil,
// an empty string or an empty list.
func (p *protobuf) attribute(field int, key string, value any) {
	switch v := value.(type) {
	case nil:
		return
	case string:
		if v == "" {
			return
		}
	case []any:
		if len(v) == 0 {
			return
		}
	}
	pair := p.open(field)
	p.string(1, key)
	p.anyValue(2, value)
	p.close(pair)
}

func (p *protobuf) anyValue(field int, value any) {
	item := p.open(field)
	switch v := value.(type) {
	case string:
		p.string(1, v)
	case bool:
		p.varint(2, map[bool]uint64{true: 1}[v])
	case json.Number:
		if integer, err := strconv.ParseInt(v.String(), 10, 64); err == nil {
			p.varint(3, uint64(integer))
		} else if number, err := v.Float64(); err == nil {
			p.fixed64(4, math.Float64bits(number))
		}
	case float64:
		p.fixed64(4, math.Float64bits(v))
	case []any:
		list := p.open(5)
		for _, element := range v {
			p.anyValue(1, element)
		}
		p.close(list)
	}
	p.close(item)
}

// structuredAttribute writes JSON text as an attribute with a structured value,
// and nothing when the text does not decode, which only a bug could cause.
func (p *protobuf) structuredAttribute(field int, key string, text []byte) {
	start := len(p.data)
	pair := p.open(field)
	p.string(1, key)
	if err := p.jsonValue(2, jsontext.NewDecoder(bytes.NewBuffer(text))); err != nil {
		p.data = p.data[:start]
		return
	}
	p.close(pair)
}

// jsonValue writes the decoder's next JSON value as an AnyValue: an object as
// a list of key-value pairs, a number as an integer when it is one that fits,
// and null as a value that holds nothing. Strings are unescaped straight into
// the trace.
func (p *protobuf) jsonValue(field int, decoder *jsontext.Decoder) error {
	item := p.open(field)
	switch kind := decoder.PeekKind(); kind {
	case '[', '{':
		if _, err := decoder.ReadToken(); err != nil {
			return err
		}
		end, values := jsontext.Kind(']'), 5
		if kind == '{' {
			end, values = '}', 6
		}
		container := p.open(values)
		for decoder.PeekKind() != end {
			if kind == '[' {
				if err := p.jsonValue(1, decoder); err != nil {
					return err
				}
				continue
			}
			name, err := decoder.ReadValue()
			if err != nil {
				return err
			}
			pair := p.open(1)
			if err := p.unquote(1, name); err != nil {
				return err
			}
			if err := p.jsonValue(2, decoder); err != nil {
				return err
			}
			p.close(pair)
		}
		p.close(container)
		if _, err := decoder.ReadToken(); err != nil {
			return err
		}
	case '"':
		value, err := decoder.ReadValue()
		if err != nil {
			return err
		}
		if err := p.unquote(1, value); err != nil {
			return err
		}
	case '0':
		value, err := decoder.ReadValue()
		if err != nil {
			return err
		}
		if integer, err := strconv.ParseInt(string(value), 10, 64); err == nil {
			p.varint(3, uint64(integer))
		} else {
			// A number beyond a double's range reads as infinity.
			number, _ := strconv.ParseFloat(string(value), 64)
			p.fixed64(4, math.Float64bits(number))
		}
	case 't', 'f', 'n':
		if _, err := decoder.ReadToken(); err != nil {
			return err
		}
		switch kind {
		case 't':
			p.varint(2, 1)
		case 'f':
			p.varint(2, 0)
		}
	default:
		_, err := decoder.ReadToken()
		return errors.Join(errTraceRecord, err)
	}
	p.close(item)
	return nil
}

// unquote writes a JSON string's text as a string field.
func (p *protobuf) unquote(field int, quoted []byte) error {
	start := p.open(field)
	var err error
	p.data, err = jsontext.AppendUnquote(p.data, quoted)
	p.close(start)
	return err
}

// flatten writes a JSON value as attributes: an object as one attribute for
// each member, named by its path, and a list as a list, or as JSON text when
// it holds objects, which an attribute list cannot name.
func (p *protobuf) flatten(field int, key string, value any) {
	switch v := value.(type) {
	case map[string]any:
		for _, name := range sortedKeys(v) {
			p.flatten(field, key+"."+name, v[name])
		}
	case []any:
		for _, element := range v {
			switch element.(type) {
			case map[string]any, []any:
				if encoded, err := json.Marshal(v); err == nil {
					p.attribute(field, key, string(encoded))
				}
				return
			}
		}
		p.attribute(field, key, v)
	default:
		p.attribute(field, key, value)
	}
}

func (p *protobuf) status(failure string) {
	if failure == "" {
		return
	}
	status := p.open(15)
	p.string(2, failure)
	p.varint(3, statusCodeError)
	p.close(status)
}
