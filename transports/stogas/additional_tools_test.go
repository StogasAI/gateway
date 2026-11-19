package stogas

import (
	"encoding/json"
	"strings"
	"testing"
)

// codexLiteRequest is the request that Codex sends for a model whose metadata selects Responses
// Lite, such as GPT-6.1 Sol: its tools come in an additional_tools item before the instructions,
// none at the top level, and reasoning.context asks for the reasoning of every turn.
func codexLiteRequest(model, tools string) string {
	return `{"model":"` + model + `","stream":true,"input":[` +
		`{"type":"additional_tools","id":"at_0f3c","role":"developer","tools":[` + tools + `]},` +
		`{"type":"message","id":"msg_0f3c","role":"developer","content":[{"type":"input_text","text":"You are Codex."}]},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"List the files."}]}],` +
		`"tool_choice":"auto","parallel_tool_calls":false,"reasoning":{"effort":"medium","summary":"auto","context":"all_turns"},` +
		`"store":false,"include":["reasoning.encrypted_content"],"prompt_cache_key":"thread-1",` +
		`"client_metadata":{"x-codex-installation-id":"install-1"}}`
}

const codexFunctionTools = `{"type":"namespace","name":"functions","description":"Default tools.","tools":[` +
	`{"type":"function","name":"exec_command","description":"Run a command.","parameters":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]},"strict":false}]},` +
	`{"type":"namespace","name":"mcp__docs","description":"Docs server.","tools":[{"type":"function","name":"search","parameters":{"type":"object"}}]}`

func TestCodexLiteToolsReachEveryProviderAsTopLevelTools(t *testing.T) {
	for _, tc := range []struct{ name, request string }{
		{"OpenAI wire", codexLiteRequest("provider:openai gpt-5.5", codexFunctionTools+`,{"type":"custom","name":"apply_patch","description":"Patch files.","format":{"type":"grammar","syntax":"lark","definition":"start: \"x\""}}`)},
		// Claude has no reasoning context setting, so a client that sends tools this way to Claude
		// leaves it out.
		{"Anthropic wire", strings.Replace(codexLiteRequest("anthropic-claude-sonnet-4-6", codexFunctionTools), `,"context":"all_turns"`, "", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _, _ := providerBody(t, "/v1/responses", tc.request)
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "additional_tools") {
				t.Fatalf("provider body keeps the item: %s", encoded)
			}
			// Claude gets the namespace's tools as functions named mcp__docs__search.
			for _, name := range []string{`"exec_command"`, "search"} {
				if !strings.Contains(string(body["tools"]), name) {
					t.Fatalf("provider tools lack %s: %s", name, body["tools"])
				}
			}
		})
	}
	body, _, _ := providerBody(t, "/v1/responses", codexLiteRequest("provider:openai gpt-5.5", codexFunctionTools))
	if got := string(body["reasoning"]); !strings.Contains(got, `"context":"all_turns"`) {
		t.Fatalf("OpenAI reasoning = %s, want the context", got)
	}
	// Claude has no such setting, so it serves the request without it.
	body, _, _ = providerBody(t, "/v1/responses", codexLiteRequest("anthropic-claude-sonnet-4-6", codexFunctionTools))
	if encoded, _ := json.Marshal(body); strings.Contains(string(encoded), "all_turns") {
		t.Fatalf("Claude got reasoning.context: %s", encoded)
	}
}

// Tool policies and tool_choice read tools declared in additional_tools items as top-level ones.
func TestCodexLiteToolsAreDeclaredTools(t *testing.T) {
	request := strings.Replace(codexLiteRequest("provider:openai gpt-5.5", codexFunctionTools),
		`"tool_choice":"auto"`, `"tool_choice":{"type":"function","name":"exec_command"}`, 1)
	if err := requestCheckError(t, "/v1/responses", request); err != nil {
		t.Fatalf("named choice of a declared tool: %v", err)
	}
	request = strings.Replace(request, `"name":"exec_command"}`, `"name":"missing"}`, 1)
	if err := requestCheckError(t, "/v1/responses", request); err == nil || err.Error() != "tool_choice selects an unknown function tool" {
		t.Fatalf("named choice of an undeclared tool: %v", err)
	}
}
