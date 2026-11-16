package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestEscapedStringRedactionDoesNotExpandUnchangedHTML(t *testing.T) {
	compiled, err := CompilePolicy(Options{CustomPatterns: []CustomPattern{{Expression: "~"}}})
	if err != nil {
		t.Fatal(err)
	}
	input := `"` + strings.Repeat("<>&", 4096) + `\n~"`
	raw := map[string]json.RawMessage{"input": json.RawMessage(input)}
	expansion := 0
	r := NewWithPolicy(compiled)
	if err := r.RedactRequestFields(raw, SurfaceResponses, func(bytes int) error {
		if string(raw["input"]) != input || bytes < expansion {
			t.Fatal("expansion must be admitted before applying replacements")
		}
		expansion = bytes
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if string(raw["input"]) != strings.Replace(input, "~", "<CUSTOM_PII>", 1) || expansion != len("<CUSTOM_PII>")-1 {
		t.Fatal("redaction expanded unchanged HTML or missed the replacement growth")
	}
	var decoded string
	if json.Unmarshal(raw["input"], &decoded) != nil || decoded != strings.Repeat("<>&", 4096)+"\n<CUSTOM_PII>" {
		t.Fatal("redaction changed text outside the match")
	}
}

func TestExpansionAdmissionFailureKeepsEveryOriginalField(t *testing.T) {
	compiled, err := CompilePolicy(Options{CustomPatterns: []CustomPattern{{Expression: "~"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]json.RawMessage{"input": json.RawMessage(`"~"`), "instructions": json.RawMessage(`"~"`)}
	r := NewWithPolicy(compiled)
	capacity := errors.New("request memory capacity")
	calls := 0
	err = r.RedactRequestFields(raw, SurfaceResponses, func(bytes int) error {
		calls++
		if calls == 2 {
			return capacity
		}
		return nil
	})
	if !errors.Is(err, capacity) || calls != 2 || r.Summary().ItemsRedacted != 0 || r.InputTextBytes() != 0 || string(raw["input"]) != `"~"` || string(raw["instructions"]) != `"~"` {
		t.Fatalf("memory failure partially applied redaction: calls=%d err=%v", calls, err)
	}
}

func TestInputTextBytesCountsTransformedUTF8WithoutProtocolOrOpaqueData(t *testing.T) {
	for _, tc := range []struct {
		name    string
		surface Surface
		body    string
		want    int
	}{
		{"one byte", SurfaceResponses, `{"input":"a"}`, 1},
		{"three bytes", SurfaceResponses, `{"input":"€"}`, 3},
		{"four bytes", SurfaceResponses, `{"input":"🙂"}`, 4},
		{"five bytes", SurfaceResponses, `{"input":"é€"}`, 5},
		{"split five bytes", SurfaceResponses, `{"instructions":"é","input":[{"role":"user","content":"€"}]}`, 5},
		{"literal unicode", SurfaceResponses, `{"input":"é🙂"}`, 6},
		{"escaped unicode", SurfaceResponses, `{"input":"\u00e9\ud83d\ude42"}`, 6},
		{"JSON controls", SurfaceResponses, `{"input":"a\n\"b"}`, 4},
		{"known empty", SurfaceChat, `{"messages":[{"role":"user","content":""}]}`, 0},
		{"protocol identifiers", SurfaceChat, `{"messages":[{"role":"assistant","tool_calls":[{"id":"call_123","type":"function","function":{"name":"search","arguments":"{}"}}]}]}`, 2},
		{"protected responses", SurfaceResponses, `{"input":[{"summary":[{"type":"summary_text","text":"hidden"}],"encrypted_content":"opaque","type":"reasoning"},{"type":"message","role":"user","content":"é🙂"}]}`, 6},
		{"protected chat", SurfaceChat, `{"messages":[{"role":"assistant","reasoning":"hidden","reasoning_details":[{"type":"reasoning.text","text":"hidden","signature":"opaque"}],"content":"é🙂"}]}`, 6},
		{"protected search results", SurfaceResponses, `{"input":[{"action":{"sources":[{"encrypted_content":"opaque"}]},"type":"web_search_call"},{"type":"message","role":"user","content":"é🙂"}]}`, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.body), &raw); err != nil {
				t.Fatal(err)
			}
			r := NewWithPolicy(nil)
			if err := r.RedactRequestFields(raw, tc.surface, nil); err != nil {
				t.Fatal(err)
			}
			if got := r.InputTextBytes(); got != tc.want {
				t.Fatalf("decoded text bytes = %d, want %d", got, tc.want)
			}
		})
	}
	compiled, err := CompilePolicy(Options{CustomPatterns: []CustomPattern{{Expression: "~"}}})
	if err != nil {
		t.Fatal(err)
	}
	r := NewWithPolicy(compiled)
	raw := map[string]json.RawMessage{"input": json.RawMessage(`"é ~"`)}
	if err := r.RedactRequestFields(raw, SurfaceResponses, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := r.InputTextBytes(), len("é <CUSTOM_PII>"); got != want {
		t.Fatalf("transformed text bytes = %d, want %d", got, want)
	}
}

func TestEscapedTextNormalizationPreservesTextWithoutCountingPII(t *testing.T) {
	raw := map[string]json.RawMessage{"input": json.RawMessage(`"\u0061\u00e9\ud83d\ude42\n<>&"`)}
	r := NewWithPolicy(nil)
	if err := r.RedactRequestFields(raw, SurfaceResponses, nil); err != nil {
		t.Fatal(err)
	}
	if got := string(raw["input"]); got != `"aé🙂\n<>&"` || r.Summary() != nil || r.InputTextBytes() != 11 {
		t.Fatalf("normalization changed decoded text or redaction accounting: %s, %+v, %d", got, r.Summary(), r.InputTextBytes())
	}
}

func FuzzJSONWithoutRedactionPreservesDecodedValues(f *testing.F) {
	for _, seed := range []string{
		`"\u0061\u00e9\ud83d\ude42\n<>&"`,
		`"  \t\r\ne\u0301\u2028\u2029\\\/\"  "`,
		`[{"role":"user","content":"\u0068ello"}]`,
		`[{"type":"reasoning","summary":"\u0061","encrypted_content":"opaque"}]`,
		`{"arguments":"{\"amount\":9007199254740993}","enum":[1.0,9007199254740993]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > 8192 || !json.Valid(source) {
			return
		}
		decode := func(value []byte) any {
			t.Helper()
			decoder := json.NewDecoder(bytes.NewReader(value))
			decoder.UseNumber()
			var decoded any
			if err := decoder.Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			return decoded
		}
		want := decode(source)
		for _, context := range []jsonValueContext{jsonContextGeneral, jsonContextChatMessages, jsonContextResponsesInput} {
			r := NewWithPolicy(nil)
			out, _, err := r.redactJSONContext(source, context)
			if errors.Is(err, ErrNestingLimit) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decode(out), want) || r.Summary() != nil {
				t.Fatalf("decoded value or PII accounting changed in context %d", context)
			}
		}
	})
}

func TestCustomPatternStillReceivesAllWhitespace(t *testing.T) {
	compiled, err := CompilePolicy(Options{CustomPatterns: []CustomPattern{{Expression: "^ +$"}}})
	if err != nil {
		t.Fatal(err)
	}
	out, changed, err := NewWithPolicy(compiled).redactBytes([]byte("            "))
	if err != nil || !changed || string(out) != "<CUSTOM_PII>" {
		t.Fatalf("padding was hidden from the custom rule: %q, %t, %v", out, changed, err)
	}
}

// Only a signed or encrypted reasoning detail is the provider's own. Reasoning text without one
// reaches a provider as the client wrote it, so it is scanned like other text, and both names of a
// message's reasoning text get the same treatment, since the request's checks compare them.
func TestReasoningHistoryIsScannedUnlessADetailSealsIt(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, message, want string
		items               uint32
	}{
		{
			name:    "plain detail",
			message: `{"role":"assistant","reasoning":"plain@corp.io","reasoning_content":"plain@corp.io","reasoning_details":[{"index":0,"type":"reasoning.text","text":"plain@corp.io"}]}`,
			want:    `{"role":"assistant","reasoning":"<EMAIL_ADDRESS>","reasoning_content":"<EMAIL_ADDRESS>","reasoning_details":[{"index":0,"type":"reasoning.text","text":"<EMAIL_ADDRESS>"}]}`,
			items:   3,
		},
		{
			name:    "empty signature",
			message: `{"role":"assistant","reasoning_details":[{"index":0,"type":"reasoning.text","signature":"","text":"plain@corp.io"}],"reasoning":"plain@corp.io"}`,
			want:    `{"role":"assistant","reasoning_details":[{"index":0,"type":"reasoning.text","signature":"","text":"<EMAIL_ADDRESS>"}],"reasoning":"<EMAIL_ADDRESS>"}`,
			items:   2,
		},
		{
			name:    "signed detail",
			message: `{"role":"assistant","reasoning":"signed@corp.io","reasoning_content":"signed@corp.io","reasoning_details":[{"index":0,"type":"reasoning.text","text":"signed@corp.io","signature":"opaque"}]}`,
			want:    `{"role":"assistant","reasoning":"signed@corp.io","reasoning_content":"signed@corp.io","reasoning_details":[{"index":0,"type":"reasoning.text","text":"signed@corp.io","signature":"opaque"}]}`,
		},
		{
			name:    "signed and plain details",
			message: `{"role":"assistant","reasoning_content":"signed@corp.io","reasoning_details":[{"index":0,"type":"reasoning.text","text":"signed@corp.io","signature":"opaque"},{"index":1,"type":"reasoning.text","text":"plain@corp.io"}]}`,
			want:    `{"role":"assistant","reasoning_content":"signed@corp.io","reasoning_details":[{"index":0,"type":"reasoning.text","text":"signed@corp.io","signature":"opaque"},{"index":1,"type":"reasoning.text","text":"<EMAIL_ADDRESS>"}]}`,
			items:   1,
		},
		{
			name:    "sealed detail of an earlier message",
			message: `{"role":"assistant","reasoning_details":[{"index":0,"type":"reasoning.encrypted","data":"opaque"}]},{"role":"assistant","reasoning":"plain@corp.io"}`,
			want:    `{"role":"assistant","reasoning_details":[{"index":0,"type":"reasoning.encrypted","data":"opaque"}]},{"role":"assistant","reasoning":"<EMAIL_ADDRESS>"}`,
			items:   1,
		},
	} {
		raw := map[string]json.RawMessage{"messages": json.RawMessage(`[` + test.message + `]`)}
		redactor := newTestRedactor()
		if err := redactor.RedactRequestFields(raw, SurfaceChat, nil); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if got := string(raw["messages"]); got != `[`+test.want+`]` {
			t.Fatalf("%s: messages = %s", test.name, got)
		}
		if got := redactor.Summary().ItemsRedacted; got != test.items {
			t.Fatalf("%s: items_redacted = %d, want %d", test.name, got, test.items)
		}
	}
}

func TestProtectedReasoningDoesNotDependOnKeyOrder(t *testing.T) {
	t.Parallel()
	chatMessages := []string{
		`{"role":"assistant","reasoning":"signed@corp.io","reasoning_details":[{"index":0,"type":"reasoning.text","text":"signed@corp.io","signature":"marker@corp.io"}]}`,
		`{"reasoning_details":[{"signature":"marker@corp.io","text":"signed@corp.io","type":"reasoning.text","index":0}],"reasoning":"signed@corp.io","role":"assistant"}`,
		`{"role":"assistant","reasoning":"signed\u0040corp.io","reasoning\u005fdetails":[{"index":0,"sign\u0061ture":"marker@corp.io","text":"signed@corp.io","ty\u0070e":"reasoning.\u0074ext"}]}`,
		`{"role":"assistant","reasoning_details":[{"index":0,"type":"reasoning.encrypted","data":"cipher@corp.io"}]}`,
	}
	for _, message := range chatMessages {
		raw := map[string]json.RawMessage{
			"messages": json.RawMessage(`[{"role":"user","content":"outside@corp.io"},` + message + `]`),
		}
		redactor := newTestRedactor()
		if err := redactor.RedactRequestFields(raw, SurfaceChat, nil); err != nil {
			t.Fatal(err)
		}
		protectedEmail := []byte("signed@corp.io")
		if strings.Contains(message, "cipher@corp.io") {
			protectedEmail = []byte("cipher@corp.io")
		}
		if !bytes.Contains(raw["messages"], []byte("<EMAIL_ADDRESS>")) ||
			!bytes.Contains(raw["messages"], protectedEmail) {
			t.Fatalf("signed Chat reasoning changed: %s", raw["messages"])
		}
		if redactor.Summary().ItemsRedacted != 1 {
			t.Fatalf("items_redacted = %d, want 1", redactor.Summary().ItemsRedacted)
		}
	}

	responsesItems := []string{
		`{"type":"reasoning","summary":[{"type":"summary_text","text":"inside@corp.io"}],"encrypted_content":"cipher@corp.io"}`,
		`{"encrypted_content":"cipher@corp.io","summary":[{"text":"inside@corp.io","type":"summary_text"}],"type":"reasoning"}`,
		`{"encrypted\u005fcontent":"cipher@corp.io","summary":[{"type":"summary_text","text":"inside@corp.io"}],"ty\u0070e":"reasoning"}`,
	}
	for _, item := range responsesItems {
		raw := map[string]json.RawMessage{
			"input": json.RawMessage(`[{"type":"message","role":"user","content":"outside@corp.io"},` + item + `]`),
		}
		redactor := newTestRedactor()
		if err := redactor.RedactRequestFields(raw, SurfaceResponses, nil); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw["input"], []byte("<EMAIL_ADDRESS>")) ||
			!bytes.Contains(raw["input"], []byte("inside@corp.io")) ||
			!bytes.Contains(raw["input"], []byte("cipher@corp.io")) {
			t.Fatalf("encrypted Responses reasoning changed: %s", raw["input"])
		}
		if redactor.Summary().ItemsRedacted != 1 {
			t.Fatalf("items_redacted = %d, want 1", redactor.Summary().ItemsRedacted)
		}
	}
}

// Claude refuses a web search whose encrypted results changed, so they stay as the reply returned
// them, and only there: the same key in any other position is ordinary text.
func TestEncryptedSearchResultsStayOnlyInSearchCalls(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		item string
		kept int
	}{
		{`{"type":"web_search_call","id":"srvtoolu_01","status":"completed","action":{"type":"search","query":"q","sources":[{"type":"url","url":"https://example.com","title":"bob@corp.io","encrypted_content":"cipher@corp.io"}]}}`, 1},
		{`{"action":{"sources":[{"title":"bob@corp.io","encrypted_content":"cipher@corp.io"}],"type":"search"},"status":"completed","ty\u0070e":"web_search_call"}`, 1},
		{`{"type":"web_search_call","action":{"sources":[{"title":"bob@corp.io","encrypted\u005fcontent":"cipher@corp.io"}]}}`, 1},
		{`{"type":"function_call","action":{"sources":[{"title":"bob@corp.io","encrypted_content":"cipher@corp.io"}]}}`, 0},
		{`{"type":"web_search_call","type":"message","action":{"sources":[{"title":"bob@corp.io","encrypted_content":"cipher@corp.io"}]}}`, 0},
		{`{"type":"web_search_call","action":{"title":"bob@corp.io","encrypted_content":"cipher@corp.io"}}`, 0},
		{`{"type":"web_search_call","action":{"filters":{"sources":[{"title":"bob@corp.io","encrypted_content":"cipher@corp.io"}]}}}`, 0},
		{`{"type":"web_search_call","action":{"sources":[{"title":"bob@corp.io","encrypted_content":{"text":"cipher@corp.io"}}]}}`, 0},
		{`{"type":"web_search_call","action":{"sources":[{"title":"bob@corp.io","encrypted_content":"cipher@corp.io"}]},"content":[{"type":"input_text","text":"x","encrypted_content":"cipher@corp.io"}]}`, 1},
	} {
		raw := map[string]json.RawMessage{"input": json.RawMessage(`[` + tc.item + `]`)}
		redactor := newTestRedactor()
		if err := redactor.RedactRequestFields(raw, SurfaceResponses, nil); err != nil {
			t.Fatal(err)
		}
		input := string(raw["input"])
		if strings.Contains(input, "bob@corp.io") || strings.Count(input, "cipher@corp.io") != tc.kept {
			t.Fatalf("redaction of %s = %s, want %d encrypted results kept", tc.item, input, tc.kept)
		}
	}
}

func TestEmptyProtectionMarkersDoNotBypassRedaction(t *testing.T) {
	t.Parallel()
	for _, item := range []string{
		`{"type":"reasoning","summary":"alice@corp.io","encrypted_content":""}`,
		`{"type":"reasoning","summary":"alice@corp.io","encrypted_content":null}`,
		`{"type":"reasoning","summary":"alice@corp.io","encrypted_content":42}`,
		`{"type":"reasoning","encrypted_content":"old","encrypted_content":"","summary":"alice@corp.io"}`,
		`{"type":"reasoning","type":"message","encrypted_content":"opaque","summary":"alice@corp.io"}`,
	} {
		raw := map[string]json.RawMessage{"input": json.RawMessage(`[` + item + `]`)}
		redactor := newTestRedactor()
		if err := redactor.RedactRequestFields(raw, SurfaceResponses, nil); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw["input"], []byte("<EMAIL_ADDRESS>")) || redactor.Summary().ItemsRedacted != 1 {
			t.Fatalf("empty marker bypassed redaction: input=%s summary=%#v", raw["input"], redactor.Summary())
		}
	}
}

func TestEscapedJSONStringIsAssertedAfterDecoding(t *testing.T) {
	t.Parallel()
	source := []byte(`{"text":"path:\/users\/alice and alice\u0040corp.io","count":1.25e+2,"enabled":true}`)
	out, changed, err := newTestRedactor().redactJSON(source)
	if err != nil || !changed || !json.Valid(out) {
		t.Fatalf("redaction = %q, changed=%t, err=%v", out, changed, err)
	}
	var decoded struct {
		Text    string  `json:"text"`
		Count   float64 `json:"count"`
		Enabled bool    `json:"enabled"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Text != "path:/users/alice and <EMAIL_ADDRESS>" || decoded.Count != 125 || !decoded.Enabled {
		t.Fatalf("decoded output = %#v", decoded)
	}
}

func TestJSONSyntaxValidation(t *testing.T) {
	t.Parallel()
	invalid := [][]byte{
		[]byte("{\"text\":\"plain\ntext\"}"),
		[]byte(`{"text":"plain\q"}`),
		[]byte(`{"text":"plain\u12xz"}`),
		[]byte(`{"value":truth}`),
		[]byte(`{"value":01}`),
		[]byte(`{"value":1.}`),
		[]byte(`{"value":1e}`),
		[]byte(`{"value":+1}`),
	}
	for _, source := range invalid {
		if _, _, err := newTestRedactor().redactJSON(source); !errors.Is(err, errInvalidJSON) {
			t.Fatalf("invalid JSON %q returned %v", source, err)
		}
	}

	for _, source := range []string{
		`null`, `true`, `false`, `0`, `-0`, `12`, `-12.5`, `1e9`, `1E-9`,
		`{"values":[null,true,false,0,-0,12,-12.5,1e9,1E-9]}`,
	} {
		out, changed, err := newTestRedactor().redactJSON([]byte(source))
		if err != nil || changed || string(out) != source {
			t.Fatalf("valid JSON %q returned %q, changed=%t, err=%v", source, out, changed, err)
		}
	}
}

func TestJSONNestingBoundary(t *testing.T) {
	t.Parallel()
	accepted := []byte(strings.Repeat("[", 128) + `"alice@corp.io"` + strings.Repeat("]", 128))
	out, changed, err := newTestRedactor().redactJSON(accepted)
	if err != nil || !changed || !json.Valid(out) {
		t.Fatalf("depth 128 failed: changed=%t err=%v", changed, err)
	}
	rejected := []byte(strings.Repeat("[", 129) + `"alice@corp.io"` + strings.Repeat("]", 129))
	if _, _, err := newTestRedactor().redactJSON(rejected); !errors.Is(err, ErrNestingLimit) {
		t.Fatalf("depth 129 error = %v, want ErrNestingLimit", err)
	}
}

func TestProtocolKeyNamesCannotHideOrdinaryText(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		`{"signature":"alice@corp.io"}`,
		`{"encrypted_content":{"description":"alice@corp.io"}}`,
		`{"image_url":{"description":"alice@corp.io"}}`,
		`{"name":{"description":"alice@corp.io"}}`,
		`{"properties":{"id":{"description":"alice@corp.io"}}}`,
		`{"type":"reasoning.text","signature":"opaque","text":"alice@corp.io"}`,
		`{"type":"reasoning","encrypted_content":"opaque","summary":"alice@corp.io"}`,
	} {
		redactor := newTestRedactor()
		out, changed, err := redactor.redactJSON([]byte(source))
		if err != nil || !changed || !json.Valid(out) || bytes.Contains(out, []byte("alice@corp.io")) {
			t.Fatalf("protocol-key redaction of %s = %s, changed=%t, err=%v", source, out, changed, err)
		}
		if redactor.Summary().ItemsRedacted != 1 {
			t.Fatalf("protocol-key redaction count for %s = %d, want 1", source, redactor.Summary().ItemsRedacted)
		}
	}
}

func TestReasoningShapesInToolSchemasAreNotProtected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		surface Surface
		field   string
		value   string
	}{
		{
			surface: SurfaceChat,
			field:   "tools",
			value:   `[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"payload":{"type":"reasoning.text","signature":"opaque","description":"alice@corp.io"}}}}}]`,
		},
		{
			surface: SurfaceResponses,
			field:   "tools",
			value:   `[{"type":"function","name":"lookup","parameters":{"type":"object","default":{"type":"reasoning","encrypted_content":"opaque","description":"alice@corp.io"}}}]`,
		},
		{
			surface: SurfaceChat,
			field:   "tools",
			value:   `[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"image_url":{"type":"object","description":"alice@corp.io"}}}}}]`,
		},
	}
	for _, test := range tests {
		raw := map[string]json.RawMessage{test.field: json.RawMessage(test.value)}
		redactor := newTestRedactor()
		if err := redactor.RedactRequestFields(raw, test.surface, nil); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw[test.field], []byte("<EMAIL_ADDRESS>")) || redactor.Summary().ItemsRedacted != 1 {
			t.Fatalf("tool schema bypassed redaction: value=%s summary=%#v", raw[test.field], redactor.Summary())
		}
	}
}

func TestStopSequencesAreProviderBoundText(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		surface Surface
		field   string
		value   string
	}{
		{surface: SurfaceChat, field: "stop", value: `"alice@corp.io"`},
		{surface: SurfaceChat, field: "stop_sequences", value: `["alice@corp.io"]`},
		{surface: SurfaceResponses, field: "stop", value: `["alice@corp.io"]`},
		{surface: SurfaceResponses, field: "stop_sequences", value: `["alice@corp.io"]`},
	} {
		raw := map[string]json.RawMessage{test.field: json.RawMessage(test.value)}
		redactor := newTestRedactor()
		if err := redactor.RedactRequestFields(raw, test.surface, nil); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw[test.field], []byte("alice@corp.io")) ||
			!bytes.Contains(raw[test.field], []byte("<EMAIL_ADDRESS>")) ||
			redactor.Summary().ItemsRedacted != 1 {
			t.Fatalf("stop field was not redacted: field=%s value=%s summary=%#v", test.field, raw[test.field], redactor.Summary())
		}
	}
}

func TestProtectedReasoningRollbackIncludesMarkerValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		surface Surface
		field   string
		value   string
	}{
		{
			surface: SurfaceChat,
			field:   "messages",
			value:   `[{"role":"assistant","reasoning":"bob@corp.io","reasoning_details":[{"index":0,"type":"reasoning.text","signature":"alice@corp.io","text":"bob@corp.io"}]}]`,
		},
		{
			surface: SurfaceResponses,
			field:   "input",
			value:   `[{"type":"reasoning","encrypted_content":"alice@corp.io","summary":[{"type":"summary_text","text":"bob@corp.io"}]}]`,
		},
	}
	for _, test := range tests {
		raw := map[string]json.RawMessage{test.field: json.RawMessage(test.value)}
		original := append([]byte(nil), raw[test.field]...)
		redactor := newTestRedactor()
		if err := redactor.RedactRequestFields(raw, test.surface, nil); err != nil ||
			!bytes.Equal(raw[test.field], original) || redactor.Summary().ItemsRedacted != 0 {
			t.Fatalf("protected object changed: output=%s summary=%#v err=%v", raw[test.field], redactor.Summary(), err)
		}
	}
}

func TestJSONErrorsRollBackMetricsAndFieldUpdates(t *testing.T) {
	t.Parallel()
	redactor := newTestRedactor()
	if _, _, err := redactor.redactJSON([]byte(`{"text":"alice@corp.io","broken":}`)); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
	if redactor.Summary().ItemsRedacted != 0 {
		t.Fatalf("failed JSON changed metrics: %#v", redactor.Summary())
	}

	raw := map[string]json.RawMessage{
		"messages": json.RawMessage(`[{"content":"alice@corp.io"}]`),
		"tools":    json.RawMessage(`[{"description":"bob@corp.io"},]`),
	}
	originalMessages := append([]byte(nil), raw["messages"]...)
	originalTools := append([]byte(nil), raw["tools"]...)
	if err := redactor.RedactRequestFields(raw, SurfaceChat, nil); err == nil {
		t.Fatal("invalid request field was accepted")
	}
	if redactor.Summary().ItemsRedacted != 0 || !bytes.Equal(raw["messages"], originalMessages) || !bytes.Equal(raw["tools"], originalTools) {
		t.Fatalf("failed request redaction was not transactional: summary=%#v messages=%s tools=%s", redactor.Summary(), raw["messages"], raw["tools"])
	}
}
