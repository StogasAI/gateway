package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

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
		redactor := New()
		if err := redactor.RedactRequestFields(raw, SurfaceChat); err != nil {
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
		redactor := New()
		if err := redactor.RedactRequestFields(raw, SurfaceResponses); err != nil {
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
		redactor := New()
		if err := redactor.RedactRequestFields(raw, SurfaceResponses); err != nil {
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
	out, changed, err := New().redactJSON(source)
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
		if _, _, err := New().redactJSON(source); !errors.Is(err, errInvalidJSON) {
			t.Fatalf("invalid JSON %q returned %v", source, err)
		}
	}

	for _, source := range []string{
		`null`, `true`, `false`, `0`, `-0`, `12`, `-12.5`, `1e9`, `1E-9`,
		`{"values":[null,true,false,0,-0,12,-12.5,1e9,1E-9]}`,
	} {
		out, changed, err := New().redactJSON([]byte(source))
		if err != nil || changed || string(out) != source {
			t.Fatalf("valid JSON %q returned %q, changed=%t, err=%v", source, out, changed, err)
		}
	}
}

func TestJSONNestingBoundary(t *testing.T) {
	t.Parallel()
	accepted := []byte(strings.Repeat("[", 128) + `"alice@corp.io"` + strings.Repeat("]", 128))
	out, changed, err := New().redactJSON(accepted)
	if err != nil || !changed || !json.Valid(out) {
		t.Fatalf("depth 128 failed: changed=%t err=%v", changed, err)
	}
	rejected := []byte(strings.Repeat("[", 129) + `"alice@corp.io"` + strings.Repeat("]", 129))
	if _, _, err := New().redactJSON(rejected); !errors.Is(err, ErrNestingLimit) {
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
		redactor := New()
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
		redactor := New()
		if err := redactor.RedactRequestFields(raw, test.surface); err != nil {
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
		redactor := New()
		if err := redactor.RedactRequestFields(raw, test.surface); err != nil {
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
		redactor := New()
		if err := redactor.RedactRequestFields(raw, test.surface); err != nil ||
			!bytes.Equal(raw[test.field], original) || redactor.Summary().ItemsRedacted != 0 {
			t.Fatalf("protected object changed: output=%s summary=%#v err=%v", raw[test.field], redactor.Summary(), err)
		}
	}
}

func TestJSONErrorsRollBackMetricsAndFieldUpdates(t *testing.T) {
	t.Parallel()
	redactor := New()
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
	if err := redactor.RedactRequestFields(raw, SurfaceChat); err == nil {
		t.Fatal("invalid request field was accepted")
	}
	if redactor.Summary().ItemsRedacted != 0 || !bytes.Equal(raw["messages"], originalMessages) || !bytes.Equal(raw["tools"], originalTools) {
		t.Fatalf("failed request redaction was not transactional: summary=%#v messages=%s tools=%s", redactor.Summary(), raw["messages"], raw["tools"])
	}
}
