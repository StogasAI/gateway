package inputfiles

import (
	"encoding/base64"
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
			if _, err := Process(fields, true, Options{Extract: true}); err == nil {
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
	_, err := Process(fields, false, Options{Extract: true, Reserve: func(bytes int) error {
		if bytes < 2 {
			t.Fatal("decoded expansion was not admitted")
		}
		return capacity
	}})
	if !errors.Is(err, capacity) || string(fields["messages"]) != before {
		t.Fatal("capacity failure allocated a replacement or lost its error")
	}
}

func TestExtractionPreservesOrderAndLeavesDocumentsOpaque(t *testing.T) {
	fields := map[string]json.RawMessage{"input": json.RawMessage(`[{"role":"user","content":[{"type":"input_text","text":"before"},{"type":"input_file","file_data":"data:text/plain;base64,aGk=","filename":"note.txt"},{"type":"input_file","file_data":"data:application/pdf;base64,JVBERg=="},{"type":"input_text","text":"after"}]}]`)}
	stats, err := Process(fields, true, Options{Extract: true})
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
	if len(blocks) != 4 || blocks[0].Text != "before" || blocks[1].Text != "note.txt (text/plain)\nhi" || blocks[2].Type != "input_file" || blocks[2].FileData != "data:application/pdf;base64,JVBERg==" || blocks[3].Text != "after" {
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

func TestExtractionKeepsTheFilesMetadataAndOnlyTextTypes(t *testing.T) {
	for _, tc := range []struct{ name, block, want string }{
		{"name and type", `{"type":"file","file":{"filename":"orders.csv","file_data":"data:text/csv;base64,aWQKMQ=="}}`, `{"type":"text","text":"orders.csv (text/csv)\nid\n1"}`},
		{"type alone", `{"type":"file","file":{"file_data":"data:application/yaml;base64,YTogMQ=="}}`, `{"type":"text","text":"(application/yaml)\na: 1"}`},
		{"cache marker", `{"type":"file","file":{"file_data":"data:application/toml;base64,YSA9IDE="},"cache_control":{"type":"ephemeral"}}`, `{"cache_control":{"type":"ephemeral"},"type":"text","text":"(application/toml)\na = 1"}`},
		{"RTF stays a file", `{"type":"file","file":{"file_data":"data:application/rtf;base64,e1xydGYxfQ=="}}`, `{"type":"file","file":{"file_data":"data:application/rtf;base64,e1xydGYxfQ=="}}`},
		{"Protocol Buffers stay a file", `{"type":"file","file":{"file_data":"data:application/x-protobuf;base64,CAE="}}`, `{"type":"file","file":{"file_data":"data:application/x-protobuf;base64,CAE="}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]json.RawMessage{"messages": json.RawMessage(`[{"role":"user","content":[` + tc.block + `]}]`)}
			if _, err := Process(fields, false, Options{Extract: true}); err != nil {
				t.Fatal(err)
			}
			var got, want any
			_ = json.Unmarshal(fields["messages"], &got)
			_ = json.Unmarshal([]byte(`[{"role":"user","content":[`+tc.want+`]}]`), &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %s", fields["messages"])
			}
		})
	}
}

func TestNativeTextFilesStayFiles(t *testing.T) {
	fields := map[string]json.RawMessage{"input": json.RawMessage(`[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk=","filename":"a.txt"},{"type":"input_file","file_data":"data:text/plain;base64,aGk=","filename":"b.txt"}]}]`)}
	var asked []string
	stats, err := Process(fields, true, Options{Extract: true, Native: func(path string) bool {
		asked = append(asked, path)
		return path == "input[0].content[0]"
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(asked, []string{"input[0].content[0]", "input[0].content[1]"}) || !stats.Opaque {
		t.Fatalf("asked %v, stats %+v", asked, stats)
	}
	if !strings.Contains(string(fields["input"]), `"type":"input_file","file_data":"data:text/plain;base64,aGk=","filename":"a.txt"`) || !strings.Contains(string(fields["input"]), `"text":"b.txt (text/plain)\nhi"`) {
		t.Fatalf("got %s", fields["input"])
	}
}

func encoded(data string) string { return base64.StdEncoding.EncodeToString([]byte(data)) }

const (
	pngBytes  = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
	jpegBytes = "\xff\xd8\xff\xe0\x00\x10JFIF"
	pdfBytes  = "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
	zipBytes  = "PK\x03\x04\x14\x00\x00\x00"
	wavBytes  = "RIFF\x24\x00\x00\x00WAVEfmt "
	oleBytes  = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00"
)

func TestMediaTypesFollowTheContent(t *testing.T) {
	for _, tc := range []struct {
		name, kind, declared, payload string
		want                          MediaType
		err                           string
	}{
		{"declared image", "image_url", "image/png", encoded(pngBytes), MediaType{"image", "image/png"}, ""},
		{"image of another type", "image_url", "image/jpeg", encoded(pngBytes), MediaType{}, "declares image/jpeg, but its content is image/png"},
		{"image that is text", "input_image", "image/png", encoded("hello"), MediaType{}, "declares image/png, but its content is text/plain"},
		{"SVG", "image_url", "image/svg+xml", encoded(`<?xml version="1.0"?><svg/>`), MediaType{"image", "image/svg+xml"}, ""},
		{"image part with a document", "image_url", "application/pdf", encoded(pdfBytes), MediaType{}, "is an image part, but its type is application/pdf"},
		{"text that is a PDF", "file", "text/plain", encoded(pdfBytes), MediaType{}, "declares text/plain, but its content is application/pdf"},
		{"text that is binary", "file", "text/csv", encoded(oleBytes), MediaType{}, "declares text/csv, but its content is application/octet-stream"},
		{"text", "input_file", "text/csv", encoded("a,b\n1,2"), MediaType{"text", "text/csv"}, ""},
		{"Word document", "file", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", encoded(zipBytes), MediaType{"application", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}, ""},
		{"PDF that is an archive", "file", "application/pdf", encoded(zipBytes), MediaType{}, "declares application/pdf, but its content is application/zip"},
		{"unknown binary format", "file", "application/msword", encoded(oleBytes), MediaType{"application", "application/msword"}, ""},
		{"undeclared", "file", "", encoded(pdfBytes), MediaType{"application", "application/pdf"}, ""},
		{"undeclared binary", "file", "application/octet-stream", encoded(oleBytes), MediaType{}, ""},
		{"WAV", "input_audio", "audio/wav", encoded(wavBytes), MediaType{"audio", "audio/wav"}, ""},
		{"image URL", "image_url", "", "", MediaType{Class: "image"}, ""},
		{"document URL", "input_file", "", "", MediaType{}, ""},
		{"invalid base64", "file", "text/plain", "a", MediaType{}, "has invalid base64"},
		{"case", "image_url", "IMAGE/PNG", encoded(pngBytes), MediaType{"image", "image/png"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveMediaType(tc.kind, tc.declared, tc.payload)
			message := ""
			if err != nil {
				message = err.Error()
			}
			if message != tc.err || got != tc.want {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

func TestSniffReadsOnlyTheStartOfAPayload(t *testing.T) {
	// Binary bytes after the first 512 leave the type to the first 512.
	payload := encoded(strings.Repeat("a", 600) + oleBytes)
	if got := Sniff(payload); got != "text/plain" {
		t.Fatalf("sniffed %q", got)
	}
	if got := Sniff(encoded(strings.Repeat("a", 500) + oleBytes)); got != "application/octet-stream" {
		t.Fatalf("sniffed %q", got)
	}
}

func TestChecksNameTheAttachmentAndSeeEveryPart(t *testing.T) {
	body := `[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"` + encoded(wavBytes) + `","format":"wav"}},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}},{"type":"file","file":{"file_id":"file-1"}},{"type":"file","file":{"file_data":"data:text/plain;base64,` + encoded(pdfBytes) + `"}}]}]`
	var seen []string
	_, err := Process(map[string]json.RawMessage{"messages": json.RawMessage(body)}, false, Options{Check: func(path string, mediaType MediaType) error {
		seen = append(seen, path+" "+mediaType.String())
		return nil
	}})
	if err == nil || err.Error() != "messages[0].content[3] declares text/plain, but its content is application/pdf" {
		t.Fatalf("got %v", err)
	}
	if !reflect.DeepEqual(seen, []string{"messages[0].content[0] audio/wav", "messages[0].content[1] image/* of unknown type", "messages[0].content[2] unknown type"}) {
		t.Fatalf("checked %v", seen)
	}
	refused := errors.New("refused")
	if _, err := Process(map[string]json.RawMessage{"messages": json.RawMessage(body)}, false, Options{Check: func(string, MediaType) error { return refused }}); !errors.Is(err, refused) {
		t.Fatalf("got %v", err)
	}
}
