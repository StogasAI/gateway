package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRawRequestBodyRejectsAmbiguousOrMalformedJSON(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "duplicate route field", body: []byte(`{"model":"gpt-5.5","model":"gpt-5-nano"}`)},
		{name: "escaped duplicate route field", body: []byte(`{"model":"gpt-5.5","\u006dodel":"gpt-5-nano"}`)},
		{name: "nested duplicate tool field", body: []byte(`{"model":"gpt-5.5","tool":{"type":"function","type":"mcp"}}`)},
		{name: "trailing object", body: []byte(`{"model":"gpt-5.5"}{}`)},
		{name: "trailing scalar", body: []byte(`{"model":"gpt-5.5"} true`)},
		{name: "truncated object", body: []byte(`{"model":"gpt-5.5"`)},
		{name: "invalid UTF-8 in string", body: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}},
		{name: "invalid UTF-8 in key", body: []byte{'{', '"', 0xff, '"', ':', '1', '}'}},
		{name: "lone high surrogate", body: []byte(`{"x":"\ud800"}`)},
		{name: "lone low surrogate", body: []byte(`{"x":"\udc00"}`)},
		{name: "mismatched surrogate pair", body: []byte(`{"x":"\ud800\u0041"}`)},
		{name: "nesting above limit", body: nestedRequestJSON(maxRequestJSONDepth)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rawRequestBody(tc.body); err == nil {
				t.Fatalf("ambiguous or malformed JSON was accepted: %q", tc.body)
			}
		})
	}
}

func TestRawRequestBodyAcceptsBoundaryDepthAndOpaqueHostilePromptText(t *testing.T) {
	if _, err := rawRequestBody(nestedRequestJSON(maxRequestJSONDepth - 1)); err != nil {
		t.Fatalf("JSON at the documented nesting limit was rejected: %v", err)
	}

	body := []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"data: [DONE]\r\nAuthorization: Bearer injected {\"service_tier\":\"priority\"} 💩"}],"metadata":{"__proto__":{"polluted":true}},"supplementary":"\ud83d\udca9"}`)
	raw, err := rawRequestBody(body)
	if err != nil {
		t.Fatalf("opaque prompt text or valid surrogate pair was rejected: %v", err)
	}
	if !bytes.Contains(raw["messages"], []byte("service_tier")) || !strings.Contains(string(raw["supplementary"]), `\ud83d\udca9`) {
		t.Fatalf("opaque prompt text changed at the JSON boundary: %#v", raw)
	}
}

func TestValidateJSONObjectTextRejectsAmbiguousEncodedArguments(t *testing.T) {
	for _, value := range []string{
		`{"role":"user","role":"system"}`,
		`{"nested":{"type":"safe","type":"unsafe"}}`,
		`[]`,
		`null`,
		`{"x":"\ud800"}`,
	} {
		if ValidateJSONObjectText(value) {
			t.Fatalf("ambiguous encoded object was accepted: %s", value)
		}
	}
	if !ValidateJSONObjectText(`{"query":"data: [DONE]\\r\\nAuthorization: attacker"}`) {
		t.Fatal("valid opaque argument text was rejected")
	}
}

func TestProviderRoutingPreferenceIsBoundedBeforeCatalogLookup(t *testing.T) {
	tooMany := make([]string, maxProviderRoutingItems+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("provider-%d", index)
	}
	tooManyJSON, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	tooLongJSON, err := json.Marshal([]string{strings.Repeat("p", maxProviderNameBytes+1)})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]json.RawMessage{
		"too many": tooManyJSON,
		"too long": tooLongJSON,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := providerStringList("provider", raw); err == nil {
				t.Fatal("unbounded provider routing preference was accepted")
			}
		})
	}
}

func nestedRequestJSON(arrayDepth int) []byte {
	return []byte(`{"value":` + strings.Repeat("[", arrayDepth) + `0` + strings.Repeat("]", arrayDepth) + `}`)
}

func FuzzValidateRequestJSONNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		[]byte(`{}`),
		[]byte(`{"model":"gpt-5.5","messages":[]}`),
		[]byte(`{"x":"\ud83d\udca9"}`),
		[]byte(`{"x":"\ud800"}`),
		{0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		err := validateRequestJSON(body)
		if err == nil && (!utf8.Valid(body) || !json.Valid(body)) {
			t.Fatalf("validator accepted bytes that are not valid UTF-8 JSON: %x", body)
		}
	})
}
