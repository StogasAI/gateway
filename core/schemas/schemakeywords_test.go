package schemas

import (
	"encoding/json"
	"strings"
	"testing"
)

// A schema keeps every keyword that the client wrote, in the client's order, including those
// that no field of the struct holding it names.
const keywordSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","minProperties":1,` +
	`"properties":{"a":{"type":"string"}},"patternProperties":{"^x-":{"type":"string"}},"required":["a"],` +
	`"additionalProperties":false,"x-vendor":{"k":[1,2.50]}}`

func TestToolParametersKeepEveryKeyword(t *testing.T) {
	var tool ChatTool
	if err := Unmarshal([]byte(`{"type":"function","function":{"name":"f","parameters":`+keywordSchema+`}}`), &tool); err != nil {
		t.Fatal(err)
	}
	for name, params := range map[string]*ToolFunctionParameters{
		"decoded": tool.Function.Parameters,
		"copied":  DeepCopyToolFunctionParameters(tool.Function.Parameters),
	} {
		encoded, err := MarshalSorted(params)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != keywordSchema {
			t.Fatalf("%s parameters = %s", name, encoded)
		}
	}
}

func TestResponsesSchemasKeepEveryKeyword(t *testing.T) {
	var text ResponsesTextConfig
	if err := Unmarshal([]byte(`{"format":{"type":"json_schema","name":"answer","schema":`+keywordSchema+`,"strict":true}}`), &text); err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalSorted(text.Format.JSONSchema)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != keywordSchema {
		t.Fatalf("schema = %s", encoded)
	}
	if raw := text.Format.JSONSchema.RawSchemaJSON(); string(raw) != keywordSchema {
		t.Fatalf("raw schema = %s", raw)
	}

	// A Responses request served through Chat Completions sends the same schema.
	chat := ChatResponseFormatFromResponsesFormat(text.Format)
	want := `{"type":"json_schema","json_schema":{"name":"answer","schema":` + keywordSchema + `,"strict":true}}`
	if got := string((*chat).(json.RawMessage)); got != want {
		t.Fatalf("response_format = %s", got)
	}

	// A Chat Completions request served through Responses keeps it too, decoded through a map, so
	// its numbers keep their values but not their spelling.
	decoded := strings.Replace(keywordSchema, "2.50", "2.5", 1)
	format := ResponsesTextConfigFormatFromChatResponseFormat(chat)
	if encoded, err := MarshalSorted(format.JSONSchema); err != nil || string(encoded) != decoded {
		t.Fatalf("converted schema = %s, %v", encoded, err)
	}
	schema, err := MarshalSorted(format.JSONSchema.ToMap())
	if err != nil || string(schema) != decoded {
		t.Fatalf("schema map = %s, %v", schema, err)
	}

	// A schema decoded without its order keeps its other keywords in sorted order.
	fromMap := JSONSchemaFromMap(map[string]interface{}{"type": "object", "x-b": true, "x-a": "a"})
	if encoded, err := MarshalSorted(fromMap); err != nil || string(encoded) != `{"type":"object","x-a":"a","x-b":true}` {
		t.Fatalf("map schema = %s, %v", encoded, err)
	}
}

// A schema that is no object has no keywords, and of members with the same name the last counts,
// as the decoder keeps it.
func TestSchemaKeywordsOfOddSchemas(t *testing.T) {
	var tool ChatTool
	if err := Unmarshal([]byte(`{"type":"function","function":{"name":"f","parameters":"null"}}`), &tool); err != nil {
		t.Fatal(err)
	}
	if encoded, err := MarshalSorted(tool); err != nil || !json.Valid(encoded) {
		t.Fatalf("tool = %s, %v", encoded, err)
	}
	var text ResponsesTextConfig
	if err := Unmarshal([]byte(`{"format":{"type":"json_schema","name":"a","schema":{"type":"object","x-a":1,"x-a":2}}}`), &text); err != nil {
		t.Fatal(err)
	}
	if encoded, err := MarshalSorted(text.Format.JSONSchema); err != nil || string(encoded) != `{"type":"object","x-a":2}` {
		t.Fatalf("schema = %s, %v", encoded, err)
	}
}
