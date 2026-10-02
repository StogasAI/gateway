package stogas

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestOpenAIInputScanUsesExactObjectMembers(t *testing.T) {
	raw := json.RawMessage(` 
 [
  {"id":"parent","children":[
   {"id":"child","t\u0079pe":"file"},
   ["type",{"id":"grandchild","type":null}]
  ],"type":"text"},
  {"id":"value_only","label":"type","content":"{\"type\":\"file\"}","nested":{"id":"nested","type":"text"}},
  {"id":"sibling","type":false}
 ] `)
	before := bytes.Clone(raw)
	visited := map[string]string{}
	err := openAIWalkRawJSON(raw, "type", func(object map[string]json.RawMessage) error {
		var id string
		if err := json.Unmarshal(object["id"], &id); err != nil {
			return err
		}
		if _, duplicate := visited[id]; duplicate {
			t.Fatalf("object visited twice: %q", id)
		}
		visited[id] = string(object["type"])
		return nil
	})
	want := map[string]string{"parent": `"text"`, "child": `"file"`, "grandchild": "null", "sibling": "false", "nested": `"text"`}
	if err != nil || !reflect.DeepEqual(visited, want) || !bytes.Equal(raw, before) {
		t.Fatalf("scan = %v, %v; input preserved = %v", visited, err, bytes.Equal(raw, before))
	}
}

func TestOpenAIInputScanRejectsMalformedJSONAndPreservesVisitorErrors(t *testing.T) {
	for _, raw := range []string{
		`[{"type":"text","\u0074ype":"file"}]`,
		`[{"type":"\ud800"}]`,
		`[{"type":"text"}] {}`,
		`[{"type":"text"},]`,
		`{"type":`,
	} {
		if err := openAIWalkRawJSON(json.RawMessage(raw), "type", func(map[string]json.RawMessage) error { return nil }); !errors.Is(err, errOpenAIUnsupportedInput) {
			t.Fatalf("malformed input returned %v for %s", err, raw)
		}
	}
	rejected := errors.New("selected object rejected")
	err := openAIWalkRawJSON(json.RawMessage(`[{"type":"text"}]`), "type", func(map[string]json.RawMessage) error { return rejected })
	if !errors.Is(err, rejected) {
		t.Fatalf("visitor error = %v", err)
	}
}
