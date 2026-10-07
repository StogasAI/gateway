package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRequestJSONAdmissionCountsValuesBeforeMaterializingObjects(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{}`, 1},
		{`{"k":{},"list":[null,true,false,1,"{},[]"],"nested":[[]]}`, 10},
		{`{"model":"example","messages":[{"role":"user","content":"[{},null]"},{"role":"assistant","content":""}]}`, 9},
	} {
		rejected := errors.New("no capacity")
		calls := 0
		fields, err := DecodeRequestBody([]byte(tc.body), func(values int) error {
			calls++
			if values != tc.want {
				t.Fatalf("JSON values = %d, want %d for %s", values, tc.want, tc.body)
			}
			return rejected
		})
		if !errors.Is(err, rejected) || fields != nil || calls != 1 {
			t.Fatalf("rejected admission returned fields=%v, err=%v, calls=%d", fields, err, calls)
		}
	}
	for _, body := range []string{`{"x":`, `{} {}`} {
		_, err := DecodeRequestBody([]byte(body), func(int) error {
			t.Fatal("malformed JSON reached structure admission")
			return nil
		})
		if !errors.Is(err, ErrInvalidJSON) {
			t.Fatalf("invalid body = %v", err)
		}
	}
	for _, body := range []string{`{"x":1,"x":2}`, `{"x":1,"\u0078":2}`, `{"nested":{"x":1,"x":2}}`} {
		admitted := false
		fields, err := DecodeRequestBody([]byte(body), func(int) error {
			admitted = true
			return nil
		})
		if !admitted || !errors.Is(err, ErrInvalidJSON) || fields != nil {
			t.Fatalf("duplicate names must fail after bookkeeping admission: %v", err)
		}
	}
}

func TestRequestStructureLimitsRejectBeforeAdmission(t *testing.T) {
	message := `{"role":"user","content":[{"type":"text","text":"a"}]}`
	for _, field := range []string{"messages", "input", `\u006dessages`} {
		prefix := `{"` + field + `":[` + strings.Repeat(message+",", maxRequestMessages-1) + message
		if _, err := DecodeRequestBody([]byte(prefix+`]}`), nil); err != nil {
			t.Fatalf("message boundary rejected for %s: %v", field, err)
		}
		// The parser must stop before reading an oversized or malformed next item.
		if _, err := DecodeRequestBody([]byte(prefix+`,{"broken":`), func(int) error {
			t.Fatal("oversized message array reached decoded-memory admission")
			return nil
		}); !errors.Is(err, errRequestMessageLimit) {
			t.Fatalf("message overflow for %s = %v", field, err)
		}
	}
	// Root object and array are two values; keys and string contents are not.
	values := `{"schema":[` + strings.Repeat(`null,`, MaxRequestJSONValues-3) + `null`
	if _, err := DecodeRequestBody([]byte(values+`]}`), nil); err != nil {
		t.Fatalf("JSON value boundary rejected: %v", err)
	}
	if _, err := DecodeRequestBody([]byte(values+`,null]}`), func(int) error {
		t.Fatal("oversized JSON structure reached decoded-memory admission")
		return nil
	}); !errors.Is(err, errRequestJSONValueLimit) {
		t.Fatalf("JSON structure overflow = %v", err)
	}
	// A single large text value may contain arbitrary JSON-looking prompt text.
	large, _ := json.Marshal(map[string]string{"input": strings.Repeat("{},[]", MaxRequestJSONValues)})
	if _, err := DecodeRequestBody(large, nil); err != nil {
		t.Fatalf("text size became structural complexity: %v", err)
	}
}

func referenceJSONValueCount(value any) int {
	count := 1
	switch value := value.(type) {
	case []any:
		for _, child := range value {
			count += referenceJSONValueCount(child)
		}
	case map[string]any:
		for _, child := range value {
			count += referenceJSONValueCount(child)
		}
	}
	return count
}

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
			if _, err := DecodeRequestBody(tc.body, nil); err == nil {
				t.Fatalf("ambiguous or malformed JSON was accepted: %q", tc.body)
			}
		})
	}
}

func TestRawRequestBodyAcceptsBoundaryDepthAndOpaqueHostilePromptText(t *testing.T) {
	if _, err := DecodeRequestBody(nestedRequestJSON(maxRequestJSONDepth-1), nil); err != nil {
		t.Fatalf("JSON at the documented nesting limit was rejected: %v", err)
	}
	for _, empty := range []string{"[]", "{}"} {
		body := []byte(`{"value":` + strings.Repeat("[", maxRequestJSONDepth-1) + empty + strings.Repeat("]", maxRequestJSONDepth-1) + `}`)
		if _, err := DecodeRequestBody(body, nil); err != nil {
			t.Fatalf("empty container at the nesting boundary was rejected: %v", err)
		}
	}

	body := []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"data: [DONE]\r\nAuthorization: Bearer injected {\"service_tier\":\"priority\"} 💩"}],"metadata":{"__proto__":{"polluted":true}},"supplementary":"\ud83d\udca9"}`)
	raw, err := DecodeRequestBody(body, nil)
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
		[]byte(`{"x":1e9999999999}`),
		[]byte(`{"items":[{"x":1},{"x":2}],"x":3}`),
		nestedRequestJSON(maxRequestJSONDepth - 1),
		nestedRequestJSON(maxRequestJSONDepth),
		{0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		before := bytes.Clone(body)
		values, err := validateRequestJSON(body)
		if !bytes.Equal(body, before) {
			t.Fatal("JSON validation mutated request bytes")
		}
		if want := referenceValidateRequestJSON(body); (err == nil) != (want == nil) {
			t.Fatalf("strict request JSON differs from independent parser: got %v, want %v for %x", err, want, body)
		}
		if err == nil && (!utf8.Valid(body) || !json.Valid(body)) {
			t.Fatalf("validator accepted bytes that are not valid UTF-8 JSON: %x", body)
		}
		if err == nil {
			if fields, decodeErr := DecodeRequestBody(body, func(count int) error {
				if count != values {
					t.Fatalf("admission scan count %d differs from strict validation %d", count, values)
				}
				return nil
			}); decodeErr == nil {
				var reference map[string]json.RawMessage
				if err := json.Unmarshal(body, &reference); err != nil || len(reference) != len(fields) {
					t.Fatalf("request field decoding differs: %v", err)
				}
				for name, value := range fields {
					if !bytes.Equal(reference[name], value) {
						t.Fatalf("raw field %q changed", name)
					}
					_ = append(value, '!')
				}
				if !bytes.Equal(body, before) {
					t.Fatal("appending a field changed borrowed request bytes")
				}
			}
			var value any
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			if want := referenceJSONValueCount(value); values != want {
				t.Fatalf("JSON values = %d, independent decoder = %d for %x", values, want, body)
			}
		}
	})
}
