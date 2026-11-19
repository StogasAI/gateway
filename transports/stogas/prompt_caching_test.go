package stogas

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMarkAnthropicPromptCache(t *testing.T) {
	const fiveMinutes, anHour = `{"type":"ephemeral"}`, `{"type":"ephemeral","ttl":"1h"}`
	tool := func(name string) string {
		return `{"name":"` + name + `","input_schema":{"type":"object","properties":{"cache_control":{"type":"string"}}}}`
	}
	for _, tc := range []struct {
		name, lifetime, body, want string
	}{
		{
			"a system prompt as text becomes a marked block",
			"5m",
			`{"system":"Be brief.","messages":[{"role":"user","content":"Hi"}]}`,
			`{"system":[{"cache_control":` + fiveMinutes + `,"text":"Be brief.","type":"text"}],"messages":[{"role":"user","content":"Hi"}],"cache_control":` + fiveMinutes + `}`,
		},
		{
			"the last system block with text",
			"1h",
			`{"system":[{"type":"text","text":"One."},{"type":"text","text":"Two."},{"type":"text","text":""}],"tools":[` + tool("a") + `],"messages":[]}`,
			`{"system":[{"type":"text","text":"One."},{"type":"text","text":"Two.","cache_control":` + anHour + `},{"type":"text","text":""}],"tools":[` + tool("a") + `],"messages":[],"cache_control":` + anHour + `}`,
		},
		{
			"the last tool without a system prompt",
			"5m",
			`{"tools":[` + tool("a") + `,` + tool("b") + `],"messages":[]}`,
			`{"tools":[` + tool("a") + `,{"name":"b","input_schema":{"type":"object","properties":{"cache_control":{"type":"string"}}},"cache_control":` + fiveMinutes + `}],"messages":[],"cache_control":` + fiveMinutes + `}`,
		},
		{
			"the last tool after an empty system prompt",
			"5m",
			`{"system":"","tools":[` + tool("a") + `],"messages":[]}`,
			`{"system":"","tools":[{"name":"a","input_schema":{"type":"object","properties":{"cache_control":{"type":"string"}}},"cache_control":` + fiveMinutes + `}],"messages":[],"cache_control":` + fiveMinutes + `}`,
		},
		{
			"only the conversation without a system prompt or tools",
			"1h",
			`{"messages":[{"role":"user","content":"Hi"}]}`,
			`{"messages":[{"role":"user","content":"Hi"}],"cache_control":` + anHour + `}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := markAnthropicPromptCache([]byte(tc.body), tc.lifetime)
			if err != nil {
				t.Fatal(err)
			}
			var gotValue, wantValue any
			if err := json.Unmarshal(got, &gotValue); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.want), &wantValue); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotValue, wantValue) {
				t.Fatalf("body = %s\nwant   %s", got, tc.want)
			}
		})
	}
}
