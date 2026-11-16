package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func hoisted(t *testing.T, body string) (map[string]json.RawMessage, error) {
	t.Helper()
	var rawData map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &rawData); err != nil {
		t.Fatal(err)
	}
	return rawData, hoistAdditionalTools(rawData)
}

func compactJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(encoded.String(), "\n")
}

// Codex declares every tool in additional_tools items for the models whose metadata selects
// Responses Lite, and declares changed tools in later items.
func TestHoistAdditionalToolsMergesDeclarationsInOrder(t *testing.T) {
	rawData, err := hoisted(t, `{"model":"m","tool_choice":"auto","input":[
		{"type":"additional_tools","id":"at_1","role":"developer","tools":[
			{"type":"namespace","name":"functions","description":"Default tools.","tools":[
				{"type":"function","name":"exec","description":"Run a command."},
				{"type":"custom","name":"apply_patch","description":"Patch files."}]},
			{"type":"web_search","external_web_access":false}]},
		{"type":"message","role":"developer","content":"Be brief."},
		{"type":"message","role":"user","content":"hi"},
		{"type":"additional_tools","role":"developer","tools":[
			{"type":"namespace","name":"functions","tools":[{"type":"function","name":"exec","description":"Run a command <safely>."}]},
			{"type":"namespace","name":"mcp__crm","description":"CRM.","tools":[{"type":"function","name":"find"}]}]},
		{"type":"message","role":"user","content":"again"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	// A rebuilt namespace keeps its text as sent.
	if !bytes.Contains(rawData["tools"], []byte("<safely>")) {
		t.Fatalf("tools escaped: %s", rawData["tools"])
	}
	if got, want := compactJSON(t, rawData["tools"]), `[{"description":"Default tools.","name":"functions","tools":[{"description":"Run a command <safely>.","name":"exec","type":"function"},{"description":"Patch files.","name":"apply_patch","type":"custom"}],"type":"namespace"},{"external_web_access":false,"type":"web_search"},{"description":"CRM.","name":"mcp__crm","tools":[{"name":"find","type":"function"}],"type":"namespace"}]`; got != want {
		t.Fatalf("tools = %s\nwant    %s", got, want)
	}
	if got, want := compactJSON(t, rawData["input"]), `[{"content":"Be brief.","role":"developer","type":"message"},{"content":"hi","role":"user","type":"message"},{"content":"again","role":"user","type":"message"}]`; got != want {
		t.Fatalf("input = %s\nwant    %s", got, want)
	}
}

// A function in the functions namespace is a top-level tool, so it replaces a top-level tool of
// its name in place, and a namespace left without members of its own is dropped.
func TestHoistAdditionalToolsReplacesTopLevelTools(t *testing.T) {
	rawData, err := hoisted(t, `{"tools":[{"type":"function","name":"read"},{"type":"function","name":"exec","description":"old"}],"input":[
		{"type":"message","role":"user","content":"hi"},
		{"type":"additional_tools","role":"developer","tools":[
			{"type":"namespace","name":"functions","tools":[{"type":"function","name":"exec","description":"new"}]},
			{"type":"function","name":"read","description":"Read a file."}]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := compactJSON(t, rawData["tools"]), `[{"description":"Read a file.","name":"read","type":"function"},{"description":"new","name":"exec","type":"function"}]`; got != want {
		t.Fatalf("tools = %s\nwant    %s", got, want)
	}
}

func TestHoistAdditionalToolsLeavesOtherRequestsAlone(t *testing.T) {
	body := `{"tools":[{"type":"function","name":"read"}],"input":[{"type":"message","role":"user","content":"additional_tools"}]}`
	rawData, err := hoisted(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if string(rawData["tools"]) != `[{"type":"function","name":"read"}]` || string(rawData["input"]) != `[{"type":"message","role":"user","content":"additional_tools"}]` {
		t.Fatalf("request changed: %s %s", rawData["tools"], rawData["input"])
	}
	// An escaped type is the same type.
	rawData, err = hoisted(t, `{"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"function","name":"read"}]},{"type":"message","role":"user","content":"hi"}]}`)
	if err != nil || compactJSON(t, rawData["tools"]) != `[{"name":"read","type":"function"}]` {
		t.Fatalf("escaped item: tools %s, err %v", rawData["tools"], err)
	}
}

func TestHoistAdditionalToolsRejectsMalformedItems(t *testing.T) {
	for _, tc := range []struct{ name, body, message string }{
		{"tools not an array", `{"input":[{"type":"additional_tools","role":"developer","tools":{}}]}`, "input[0].tools must be an array"},
		{"tools missing", `{"input":[{"type":"additional_tools","role":"developer"}]}`, "input[0].tools must be an array"},
		{"tool not an object", `{"input":[{"type":"message","role":"user","content":"hi"},{"type":"additional_tools","tools":["exec"]}]}`, "input[1].tools[0] must be an object"},
		{"unknown key", `{"input":[{"type":"additional_tools","role":"developer","tools":[],"status":"completed"}]}`, "input[0].status is not supported"},
		{"id not a string", `{"input":[{"type":"additional_tools","id":7,"tools":[]}]}`, "input[0].id must be a string"},
		{"top-level tools not an array", `{"tools":{},"input":[{"type":"additional_tools","tools":[]}]}`, "tools must be an array"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hoisted(t, tc.body)
			var apiErr APIError
			if !errors.As(err, &apiErr) || apiErr.Message != tc.message || apiErr.StatusCode != 400 {
				t.Fatalf("err = %v, want %q", err, tc.message)
			}
		})
	}
}
