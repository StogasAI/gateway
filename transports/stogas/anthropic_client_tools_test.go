package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	anthropicBashTool   = `{"type":"bash_20250124","name":"bash"}`
	anthropicEditorTool = `{"type":"text_editor_20250728","name":"str_replace_based_edit_tool"}`
)

// Anthropic's bash and text editor tools reach every Claude hosting as Anthropic documents them
// (https://platform.claude.com/docs/en/agents-and-tools/tool-use/bash-tool and text-editor-tool):
// the dated type and the fixed name, with no schema, and a forced call by the tool's name.
// Upstream sent bash as a function without schema, and the older text editor to both Haiku models.
func TestAnthropicClientToolsReachClaudeAsNamed(t *testing.T) {
	const tools = `"tools":[` + anthropicBashTool + `,{"type":"text_editor_20250728","name":"str_replace_based_edit_tool","max_characters":10000,"cache_control":{"type":"ephemeral"}},{"type":"function","name":"lookup"}],`
	const forcedTools = tools + `"tool_choice":{"type":"function","name":"str_replace_based_edit_tool"},`
	const wantTools = `[{"name":"bash","type":"bash_20250124"},{"name":"str_replace_based_edit_tool","type":"text_editor_20250728","cache_control":{"type":"ephemeral"},"max_characters":10000},{"name":"lookup","input_schema":{"type":"object","properties":{}},"eager_input_streaming":true}]`
	check := func(t *testing.T, wire []byte, forced bool) {
		t.Helper()
		var sent struct {
			Tools      []map[string]json.RawMessage `json:"tools"`
			ToolChoice json.RawMessage              `json:"tool_choice"`
		}
		if err := json.Unmarshal(wire, &sent); err != nil {
			t.Fatalf("decode %s: %v", wire, err)
		}
		// The gateway marks function tools for input streaming; nothing may mark Anthropic's own.
		for _, tool := range sent.Tools[:min(2, len(sent.Tools))] {
			delete(tool, "cache_control")
			delete(tool, "max_characters")
			if len(tool) != 2 {
				t.Errorf("Anthropic tool got other fields: %s", wire)
			}
		}
		var want []map[string]json.RawMessage
		if err := json.Unmarshal([]byte(wantTools), &want); err != nil {
			t.Fatal(err)
		}
		if len(sent.Tools) != 3 || string(sent.Tools[0]["type"]) != `"bash_20250124"` || string(sent.Tools[0]["name"]) != `"bash"` ||
			string(sent.Tools[1]["type"]) != `"text_editor_20250728"` || string(sent.Tools[1]["name"]) != `"str_replace_based_edit_tool"` ||
			string(sent.Tools[2]["name"]) != `"lookup"` || sent.Tools[2]["type"] != nil {
			t.Errorf("tools changed on Anthropic wire: %s", wire)
		}
		if forced && (sent.ToolChoice == nil || !sameJSON(t, sent.ToolChoice, []byte(`{"type":"tool","name":"str_replace_based_edit_tool"}`))) {
			t.Errorf("tool_choice changed on Anthropic wire: %s", sent.ToolChoice)
		}
		// Neither tool needs a beta header; only computer use does.
		if strings.Contains(string(wire), "computer-use") {
			t.Errorf("unneeded beta: %s", wire)
		}
	}
	for _, model := range []string{"anthropic-claude-sonnet-4-6", "anthropic-claude-haiku-4-5", "anthropic-claude-haiku-5-5", "anthropic-claude-opus-4-5", "anthropic-claude-opus-5", "azure-claude-opus-4-8-anthropic-hosted"} {
		t.Run(model, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(`{"input":"hi",` + forcedTools + `"model":"` + model + `"}`)})
			if err != nil {
				t.Fatal(err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatal(err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
			request, err := resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatal(err)
			}
			wire := preparedProviderBody(t, ctx, request.ResponsesRequest)
			check(t, wire, true)
			if model == "anthropic-claude-haiku-4-5" {
				var sent struct {
					Tools json.RawMessage `json:"tools"`
				}
				if err := json.Unmarshal(wire, &sent); err != nil || !sameJSON(t, sent.Tools, []byte(wantTools)) {
					t.Errorf("tools = %s, want %s", sent.Tools, wantTools)
				}
			}
		})
	}
	for _, deployment := range []string{"aws-claude-fable-5-1", "aws-claude-fable-5-1-us", "google-cloud-claude-fable-5-1", "aws-claude-fable-5-1-anthropic-hosted", "google-cloud-claude-fable-5-1-anthropic-hosted"} {
		for _, streaming := range []bool{false, true} {
			t.Run(deployment, func(t *testing.T) {
				state := resolveCloudState(t, "/v1/responses", deployment, `"input":"hi",`+tools)
				if err := state.Adapter.ValidateRequest(state); err != nil {
					t.Fatal(err)
				}
				if err := state.Adapter.SanitizeRequest(state); err != nil {
					t.Fatal(err)
				}
				ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				request, err := state.Resolution.ToBifrost(ctx)
				if err != nil {
					t.Fatal(err)
				}
				wire, bifrostErr := prepareResponsesProviderBody(ctx, request.ResponsesRequest, streaming, state.Resolution.Deployment.Hosting)
				if bifrostErr != nil {
					t.Fatal(bifrostErr.Error)
				}
				check(t, wire, false)
			})
		}
	}
}

func TestResponsesPolicyChecksAnthropicClientTools(t *testing.T) {
	const claude = `{"model":"anthropic-claude-sonnet-4-6","input":"hi",`
	for name, test := range map[string]struct{ body, want string }{
		"both tools":            {claude + `"tools":[` + anthropicBashTool + `,` + anthropicEditorTool + `]}`, ""},
		"beside a function":     {claude + `"tools":[` + anthropicBashTool + `,{"type":"function","name":"lookup"}],"tool_choice":"required","parallel_tool_calls":false}`, ""},
		"a forced call by name": {claude + `"tools":[` + anthropicBashTool + `],"tool_choice":{"type":"function","name":"bash"}}`, ""},
		"view limit and cache":  {claude + `"tools":[{"type":"text_editor_20250728","name":"str_replace_based_edit_tool","max_characters":1,"cache_control":{"type":"ephemeral"}}]}`, ""},
		"Azure-hosted Claude":   {`{"model":"azure-claude-opus-4-8-anthropic-hosted","input":"hi","tools":[` + anthropicBashTool + `]}`, ""},
		"a call and its result": {`{"model":"anthropic-claude-sonnet-4-6","input":[{"role":"user","content":"list"},{"type":"function_call","call_id":"toolu_1","name":"bash","arguments":"{\"command\":\"ls\"}"},{"type":"function_call_output","call_id":"toolu_1","output":"a.txt"}],"tools":[` + anthropicBashTool + `]}`, ""},

		"no name":                    {claude + `"tools":[{"type":"bash_20250124"}]}`, "tools[0].name must be bash"},
		"another name":               {claude + `"tools":[{"type":"bash_20250124","name":"shell"}]}`, "tools[0].name must be bash"},
		"the older editor name":      {claude + `"tools":[{"type":"text_editor_20250728","name":"str_replace_editor"}]}`, "tools[0].name must be str_replace_based_edit_tool"},
		"a description":              {claude + `"tools":[{"type":"bash_20250124","name":"bash","description":"Runs commands"}]}`, "tools[0].description is not supported"},
		"parameters":                 {claude + `"tools":[{"type":"bash_20250124","name":"bash","parameters":{"type":"object"}}]}`, "tools[0].parameters is not supported"},
		"a view limit on bash":       {claude + `"tools":[{"type":"bash_20250124","name":"bash","max_characters":10}]}`, "tools[0].max_characters is not supported"},
		"an empty view limit":        {claude + `"tools":[{"type":"text_editor_20250728","name":"str_replace_based_edit_tool","max_characters":0}]}`, "tools[0].max_characters must be a positive integer"},
		"the tool twice":             {claude + `"tools":[` + anthropicBashTool + `,` + anthropicBashTool + `]}`, "tools[1].name duplicates another client tool"},
		"a function of its name":     {claude + `"tools":[{"type":"function","name":"bash"},` + anthropicBashTool + `]}`, "tools[1].name duplicates another client tool"},
		"an older bash":              {claude + `"tools":[{"type":"bash_20241022","name":"bash"}]}`, "Claude takes bash_20250124 and text_editor_20250728"},
		"an older editor":            {claude + `"tools":[{"type":"text_editor_20250124","name":"str_replace_editor"}]}`, "Claude takes bash_20250124 and text_editor_20250728"},
		"computer use":               {claude + `"tools":[{"type":"computer_20250124","name":"computer","display_width_px":1024,"display_height_px":768}]}`, "computer tools are not supported because tool results carry only text"},
		"memory":                     {claude + `"tools":[{"type":"memory_20250818","name":"memory"}]}`, "memory tools are not supported"},
		"a selector by type":         {claude + `"tools":[` + anthropicBashTool + `],"tool_choice":{"type":"bash_20250124"}}`, "only string tool_choice modes or named function selectors"},
		"a forced undeclared tool":   {claude + `"tools":[` + anthropicBashTool + `],"tool_choice":{"type":"function","name":"str_replace_based_edit_tool"}}`, "tool_choice selects an unknown function tool"},
		"max_tool_calls":             {claude + `"tools":[` + anthropicBashTool + `],"max_tool_calls":2}`, "max_tool_calls"},
		"OpenAI":                     {`{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + anthropicBashTool + `]}`, "Only function, custom, namespace, shell, apply_patch"},
		"Azure OpenAI":               {`{"model":"azure-gpt-5.6-sol","input":"hi","tools":[` + anthropicEditorTool + `]}`, "Only function, custom, and namespace tools are supported for Azure deployments"},
		"OpenAI's shell on Claude":   {claude + `"tools":[{"type":"shell"}]}`, "Only function, namespace, bash_20250124, text_editor_20250728"},
		"OpenAI's patch on Claude":   {claude + `"tools":[{"type":"apply_patch"}]}`, "Only function, namespace, bash_20250124, text_editor_20250728"},
		"a shell call in history":    {`{"model":"anthropic-claude-sonnet-4-6","input":[{"type":"shell_call","call_id":"call_1","action":{"commands":["ls"]}},{"type":"shell_call_output","call_id":"call_1","output":[]}]}`, "shell_call input items are supported only for OpenAI deployments"},
		"Chat Completions on Claude": {"chat", "Only function tools are supported"},
	} {
		t.Run(name, func(t *testing.T) {
			path, body := "/v1/responses", test.body
			if body == "chat" {
				path, body = "/v1/chat/completions", `{"model":"anthropic-claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[`+anthropicBashTool+`]}`
			}
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: path, Body: []byte(body)})
			if err == nil {
				state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
				err = state.Adapter.ValidateRequest(state)
			}
			if test.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// Claude calls Anthropic's tools as it calls a function, so a reply's call is checked against the
// tools that the request declared and its tool_choice allows, and policies read their names.
func TestAnthropicClientToolCallsAreFunctionCalls(t *testing.T) {
	const claude = `{"model":"anthropic-claude-sonnet-4-6","input":"hi",`
	call := func(name, arguments string) *schemas.BifrostResponsesResponse {
		response := validUnaryResponsesProviderResponse("resp_bash")
		itemType := schemas.ResponsesMessageTypeFunctionCall
		response.Output = []schemas.ResponsesMessage{{
			ID: schemas.Ptr("fc_1"), Type: &itemType, Status: schemas.Ptr("completed"),
			ResponsesToolMessage: &schemas.ResponsesToolMessage{CallID: schemas.Ptr("toolu_1"), Name: &name, Arguments: &arguments},
		}}
		return response
	}
	both := claude + `"tools":[` + anthropicBashTool + `,` + anthropicEditorTool + `]}`
	for name, test := range map[string]struct {
		request  string
		response *schemas.BifrostResponsesResponse
		refused  bool
	}{
		"bash":                {both, call("bash", `{"command":"ls -la"}`), false},
		"bash restart":        {both, call("bash", `{"restart":true}`), false},
		"text editor":         {both, call("str_replace_based_edit_tool", `{"command":"view","path":"/repo/a.txt"}`), false},
		"an undeclared tool":  {claude + `"tools":[` + anthropicBashTool + `]}`, call("str_replace_based_edit_tool", `{"command":"view","path":"a"}`), true},
		"the older name":      {both, call("str_replace_editor", `{"command":"view","path":"a"}`), true},
		"a tool not chosen":   {both[:len(both)-1] + `,"tool_choice":{"type":"function","name":"bash"}}`, call("str_replace_based_edit_tool", `{"command":"view","path":"a"}`), true},
		"tools turned off":    {both[:len(both)-1] + `,"tool_choice":"none"}`, call("bash", `{"command":"ls"}`), true},
		"arguments not JSON":  {both, call("bash", `ls -la`), true},
		"arguments an array":  {both, call("bash", `["ls"]`), true},
		"no tools in request": {claude[:len(claude)-1] + `}`, call("bash", `{"command":"ls"}`), true},
	} {
		t.Run(name, func(t *testing.T) {
			state := resolvedResponseValidationState(t, test.request)
			err := validateProviderResponsesResponse(state, test.response)
			if test.refused && !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v, want malformed provider response", err)
			}
			if !test.refused {
				if err != nil {
					t.Fatalf("reply refused: %v", err)
				}
				if calls := state.loggedToolCalls(); len(calls) != 1 || calls[0].Type != "function_call" || calls[0].CallID != "toolu_1" {
					t.Fatalf("logged calls = %+v, want the function call", calls)
				}
			}
		})
	}
}

// Anthropic documents what each tool adds to the input, which the request does not show: 325
// tokens for bash and 974 for the text editor on Claude Opus 4.7 and later, and less before.
func TestHoldCoversAnthropicClientToolInstructions(t *testing.T) {
	const claude = `{"model":"anthropic-claude-sonnet-4-6","input":"hi"`
	plain, _ := heldInputTokens(t, claude+`}`)
	for _, test := range []struct {
		name, tools string
		added       int64
	}{
		{"bash", anthropicBashTool, 325},
		{"text editor", anthropicEditorTool, 974},
		{"both", anthropicBashTool + `,` + anthropicEditorTool, 325 + 974},
	} {
		if held, _ := heldInputTokens(t, claude+`,"tools":[`+test.tools+`]}`); held-plain < test.added {
			t.Errorf("%s: held %d more input tokens, Anthropic adds %d", test.name, held-plain, test.added)
		}
	}
}
