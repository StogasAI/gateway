package inputfiles

import (
	"encoding/json"
	"errors"
	"reflect"
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

func TestDescribeReplacesOnlyInlineAttachments(t *testing.T) {
	const digest = `"sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"`
	for _, tc := range []struct {
		name, field, body, want string
		responses               bool
	}{
		{
			name:  "chat",
			field: "messages",
			body:  `[{"role":"user","content":[{"type":"text","text":"aGVsbG8="},{"type":"image_url","image_url":{"url":"data:image/PNG;base64,aGVsbG8=","detail":"low"}},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}},{"type":"input_audio","input_audio":{"data":"aGVsbG8=","format":"wav"}},{"type":"file","file":{"file_data":"aGVsbG8=","filename":"a.pdf"}},{"type":"file","file":{"file_id":"file-1"}}]}]`,
			want:  `[{"role":"user","content":[{"type":"text","text":"aGVsbG8="},{"type":"image_url","image_url":{"url":{"media_type":"image/png","size":5,` + digest + `},"detail":"low"}},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}},{"type":"input_audio","input_audio":{"data":{"size":5,` + digest + `},"format":"wav"}},{"type":"file","file":{"file_data":{"size":5,` + digest + `},"filename":"a.pdf"}},{"type":"file","file":{"file_id":"file-1"}}]}]`,
		},
		{
			name:      "responses",
			field:     "input",
			responses: true,
			body:      `[{"role":"user","content":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":"data:image/jpeg;base64,aGVsbG8=","detail":"auto"},{"type":"input_file","file_data":"data:application/pdf;base64,aGVsbG8=","filename":"a.pdf"},{"type":"input_file","file_url":"https://example.com/a.pdf"}]},{"type":"function_call_output","call_id":"c","output":"data:image/png;base64,aGVsbG8="}]`,
			want:      `[{"role":"user","content":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":{"media_type":"image/jpeg","size":5,` + digest + `},"detail":"auto"},{"type":"input_file","file_data":{"media_type":"application/pdf","size":5,` + digest + `},"filename":"a.pdf"},{"type":"input_file","file_url":"https://example.com/a.pdf"}]},{"type":"function_call_output","call_id":"c","output":"data:image/png;base64,aGVsbG8="}]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]json.RawMessage{tc.field: json.RawMessage(tc.body), "model": json.RawMessage(`"m"`)}
			described, err := Describe(fields, tc.responses)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(described[tc.field], &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("described %s", described[tc.field])
			}
			if string(fields[tc.field]) != tc.body || string(described["model"]) != `"m"` {
				t.Fatal("description changed the request or dropped a field")
			}
		})
	}
}
