package inputfiles

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestInlineExtractionRejectsMalformedOrUninspectableText(t *testing.T) {
	for _, tc := range []struct{ name, data, extra string }{
		{"invalid base64", "?", ""},
		{"noncanonical base64", "Zh==", ""},
		{"invalid UTF-8", "/w==", ""},
		{"NUL", "YQBi", ""},
		{"ambiguous source", "aGk=", `,"file_id":"file-private"`},
		{"type mismatch", "aGk=", `,"file_type":"application/pdf"`},
		{"unpreserved field", "aGk=", `,"future":true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]json.RawMessage{"input": json.RawMessage(`[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,` + tc.data + `"` + tc.extra + `}]}]`)}
			before := string(fields["input"])
			if _, err := Process(fields, true, true, nil); err == nil {
				t.Fatal("invalid text attachment accepted")
			}
			if string(fields["input"]) != before {
				t.Fatal("failed transformation mutated the request")
			}
		})
	}
}

func TestExtractionReservesMemoryBeforeReplacement(t *testing.T) {
	fields := map[string]json.RawMessage{"messages": json.RawMessage(`[{"role":"user","content":[{"type":"file","file":{"file_data":"data:text/plain;base64,aGk="}}]}]`)}
	before := string(fields["messages"])
	capacity := errors.New("capacity")
	_, err := Process(fields, false, true, func(bytes int) error {
		if bytes < 2 {
			t.Fatal("decoded expansion was not admitted")
		}
		return capacity
	})
	if !errors.Is(err, capacity) || string(fields["messages"]) != before {
		t.Fatal("capacity failure allocated a replacement or lost its error")
	}
}

func TestExtractionPreservesOrderAndLeavesDocumentsOpaque(t *testing.T) {
	fields := map[string]json.RawMessage{"input": json.RawMessage(`[{"role":"user","content":[{"type":"input_text","text":"before"},{"type":"input_file","file_data":"data:text/plain;base64,aGk=","filename":"note.txt"},{"type":"input_file","file_data":"data:application/pdf;base64,JVBERg=="},{"type":"input_text","text":"after"}]}]`)}
	stats, err := Process(fields, true, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Count != 2 || stats.InlineBytes != 6 || !stats.Opaque {
		t.Fatalf("wrong quantities: %+v", stats)
	}
	// Decode the public field names, independently of the processor's maps.
	var result []map[string]json.RawMessage
	if err := json.Unmarshal(fields["input"], &result); err != nil {
		t.Fatal(err)
	}
	var blocks []struct {
		Type     string `json:"type"`
		Text     string `json:"text"`
		FileData string `json:"file_data"`
	}
	if err := json.Unmarshal(result[0]["content"], &blocks); err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 4 || blocks[0].Text != "before" || blocks[1].Text != "note.txt\nhi" || blocks[2].Type != "input_file" || blocks[2].FileData != "data:application/pdf;base64,JVBERg==" || blocks[3].Text != "after" {
		t.Fatal("attachment conversion changed order or binary content")
	}
	if !strings.Contains(string(result[0]["role"]), "user") {
		t.Fatal("attachment changed message role")
	}
}
