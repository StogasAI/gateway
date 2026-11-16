package stogas

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// toolSearchExchange returns an exchange of the provider capture openai/tool-search (gpt-5.4-mini,
// November 16, 2026) and its request, sent to an OpenAI deployment of the test catalog.
func toolSearchExchange(t *testing.T, name string) (providerExchange, string) {
	t.Helper()
	recorded := exchange(t, providerCapture(t, "openai/tool-search"), name)
	var body map[string]json.RawMessage
	if err := json.Unmarshal(recorded.Request.Body, &body); err != nil {
		t.Fatal(err)
	}
	body["model"] = json.RawMessage(`"provider:openai gpt-5.5"`)
	request, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return recorded, string(request)
}

// changedRequest returns a request with the fields that change replaces.
func changedRequest(t *testing.T, request string, change func(map[string]any)) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(request), &body); err != nil {
		t.Fatal(err)
	}
	change(body)
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// changedStream decodes the events of a recorded stream, each after change edits the items that
// it carries.
func changedStream(t *testing.T, recorded providerExchange, change func(item map[string]any)) []*schemas.BifrostResponsesStreamResponse {
	t.Helper()
	changed := recorded
	changed.Response.Events = make([]json.RawMessage, len(recorded.Response.Events))
	for index, data := range recorded.Response.Events {
		var event map[string]any
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatal(err)
		}
		if item, ok := event["item"].(map[string]any); ok {
			change(item)
		}
		if response, ok := event["response"].(map[string]any); ok {
			output, _ := response["output"].([]any)
			for _, item := range output {
				change(item.(map[string]any))
			}
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		changed.Response.Events[index] = encoded
	}
	return changed.responsesStream(t)
}

// completedOutput returns the output items of a recorded stream's last event as the gateway sends
// them on to the client.
func completedOutput(t *testing.T, recorded providerExchange) []json.RawMessage {
	t.Helper()
	events := recorded.responsesStream(t)
	last := events[len(events)-1]
	if last.Type != schemas.ResponsesStreamResponseTypeCompleted || last.Response == nil {
		t.Fatalf("%s ends with %s", recorded.Name, last.Type)
	}
	items := make([]json.RawMessage, 0, len(last.Response.Output))
	for index := range last.Response.Output {
		encoded, err := json.Marshal(&last.Response.Output[index])
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, encoded)
	}
	return items
}

func TestOpenAIToolSearchStreamsAsRecorded(t *testing.T) {
	for _, test := range []struct {
		name           string
		calls          []billing.ToolCallInput
		client, hosted string
	}{
		// The client runs the search, and answers the call by its ID.
		{"client search stream", []billing.ToolCallInput{{Type: "tool_search_call", CallID: "call_XAOoe2DdPwUQcdFr05SX9CAQ"}}, "1", ""},
		// OpenAI runs the search and loads the deferred tool, which the model then calls.
		{"hosted search stream", []billing.ToolCallInput{{Type: "tool_search_call"}, {Type: "function_call", CallID: "call_UYXGSm0QwZPWFufrduf0LvV0"}}, "1", "1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorded, request := toolSearchExchange(t, test.name)
			state := resolvedResponseValidationState(t, request)
			if err := replayLocalToolStream(state, recorded.responsesStream(t)); err != nil {
				t.Fatalf("recorded stream refused: %v", err)
			}
			calls := state.loggedToolCalls()
			if len(calls) != len(test.calls) {
				t.Fatalf("logged calls = %+v, want %+v", calls, test.calls)
			}
			for index, call := range calls {
				if call.Type != test.calls[index].Type || call.CallID != test.calls[index].CallID || call.DoneAt.Before(call.StartedAt) {
					t.Fatalf("logged call %d = %+v, want %+v", index, call, test.calls[index])
				}
			}
			meters := metersForState(state)
			if got := meters[billing.MeterClientToolCalls].Quantity; got != test.client {
				t.Fatalf("client tool calls = %s, want %s", got, test.client)
			}
			if got := meters[billing.MeterHostedToolCalls].Quantity; got != test.hosted {
				t.Fatalf("hosted tool calls = %s, want %s", got, test.hosted)
			}
		})
	}
}

func TestOpenAIToolSearchStreamChecks(t *testing.T) {
	isType := func(item map[string]any, itemType string) bool { return item["type"] == itemType }
	for _, test := range []struct {
		name, exchange string
		request        func(map[string]any)
		item           func(map[string]any)
	}{
		{name: "a server search that the request runs on the client", exchange: "hosted search stream",
			request: func(body map[string]any) {
				body["tools"].([]any)[1].(map[string]any)["execution"] = "client"
			}},
		{name: "a client search that the request leaves to OpenAI", exchange: "client search stream",
			request: func(body map[string]any) {
				body["tools"] = []any{map[string]any{"type": "tool_search"}}
			}},
		{name: "a search that the request does not declare", exchange: "client search stream",
			request: func(body map[string]any) {
				body["tools"] = []any{map[string]any{"type": "function", "name": "find_customer"}}
			}},
		{name: "tools turned off", exchange: "client search stream",
			request: func(body map[string]any) { body["tool_choice"] = "none" }},
		{name: "a client search without call ID", exchange: "client search stream",
			item: func(item map[string]any) {
				if isType(item, "tool_search_call") {
					delete(item, "call_id")
				}
			}},
		{name: "a server search with a call ID", exchange: "hosted search stream",
			item: func(item map[string]any) {
				if isType(item, "tool_search_call") {
					item["call_id"] = "call_1"
				}
			}},
		{name: "arguments that are not an object", exchange: "hosted search stream",
			item: func(item map[string]any) {
				if isType(item, "tool_search_call") && item["status"] == "completed" {
					item["arguments"] = []any{"crm"}
				}
			}},
		{name: "an output of the client's search", exchange: "hosted search stream",
			item: func(item map[string]any) {
				if isType(item, "tool_search_output") {
					item["execution"] = "client"
				}
			}},
		// A search that loads a hosted tool would let the model run a tool that the request never
		// declared, and that can cost money.
		{name: "a loaded hosted tool", exchange: "hosted search stream",
			item: func(item map[string]any) {
				if isType(item, "tool_search_output") {
					item["tools"] = []any{map[string]any{"type": "web_search"}}
				}
			}},
		{name: "a search that stays in progress", exchange: "hosted search stream",
			item: func(item map[string]any) {
				if isType(item, "tool_search_call") {
					item["status"] = "in_progress"
				}
			}},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorded, request := toolSearchExchange(t, test.exchange)
			if test.request != nil {
				request = changedRequest(t, request, test.request)
			}
			events := recorded.responsesStream(t)
			if test.item != nil {
				events = changedStream(t, recorded, test.item)
			}
			err := replayLocalToolStream(resolvedResponseValidationState(t, request), events)
			if !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v, want malformed provider response", err)
			}
		})
	}
}

// What the gateway passes on from a search is what OpenAI took back in the next request, and the
// gateway sends the search items of that request on unchanged.
func TestOpenAIToolSearchRepliesGoBack(t *testing.T) {
	for _, test := range []struct{ stream, replay string }{
		{"client search stream", "client search replay"},
		{"hosted search stream", "hosted search replay"},
	} {
		t.Run(test.replay, func(t *testing.T) {
			stream, _ := toolSearchExchange(t, test.stream)
			recorded, request := toolSearchExchange(t, test.replay)
			var fields struct {
				Input []json.RawMessage `json:"input"`
			}
			if err := json.Unmarshal(recorded.Request.Body, &fields); err != nil {
				t.Fatal(err)
			}
			// The recorded replay sends the user's message, the stream's output and the client's
			// answers, in that order.
			output := completedOutput(t, stream)
			for index, item := range output {
				var sent, recordedItem any
				if json.Unmarshal(item, &sent) != nil || json.Unmarshal(fields.Input[1+index], &recordedItem) != nil {
					t.Fatal("items do not decode")
				}
				if !reflect.DeepEqual(sent, recordedItem) {
					t.Fatalf("the gateway passes on %s, and OpenAI took back %s", item, fields.Input[1+index])
				}
			}
			body, _, _ := providerBody(t, "/v1/responses", request)
			var sent []any
			if err := json.Unmarshal(body["input"], &sent); err != nil || len(sent) != len(fields.Input) {
				t.Fatalf("the gateway sends %s", body["input"])
			}
			for index, item := range fields.Input {
				var took any
				if err := json.Unmarshal(item, &took); err != nil {
					t.Fatal(err)
				}
				if itemType, _ := took.(map[string]any)["type"].(string); strings.HasPrefix(itemType, "tool_search") && !reflect.DeepEqual(sent[index], took) {
					t.Fatalf("the gateway sends %v, and OpenAI took %s", sent[index], item)
				}
			}
		})
	}
}

// A tool that the client's search loads is callable like a declared one, and the reply that calls
// it passes the gateway's checks, while one that calls a tool that nothing loaded does not.
func TestOpenAIToolSearchLoadsCallableTools(t *testing.T) {
	recorded, request := toolSearchExchange(t, "client search replay")
	if err := validateProviderResponsesResponse(resolvedResponseValidationState(t, request), recorded.responsesReply(t)); err != nil {
		t.Fatalf("recorded reply refused: %v", err)
	}
	_, withoutSearch := toolSearchExchange(t, "client search stream")
	for name, request := range map[string]string{
		"a call to a tool that no search loaded": withoutSearch,
		"a call in another namespace": changedRequest(t, request, func(body map[string]any) {
			input := body["input"].([]any)
			input[len(input)-1].(map[string]any)["tools"].([]any)[0].(map[string]any)["name"] = "billing"
		}),
	} {
		t.Run(name, func(t *testing.T) {
			err := validateProviderResponsesResponse(resolvedResponseValidationState(t, request), recorded.responsesReply(t))
			if !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v, want malformed provider response", err)
			}
		})
	}
}

func TestToolSearchRequestChecks(t *testing.T) {
	const (
		deferred     = `{"type":"namespace","name":"crm","description":"CRM.","tools":[{"type":"function","name":"find","defer_loading":true}]}`
		clientSearch = `{"type":"tool_search","execution":"client","description":"Finds tools.","parameters":{"type":"object","properties":{"goal":{"type":"string"}}}}`
		clientCall   = `{"type":"tool_search_call","call_id":"call_1","execution":"client","status":"completed","arguments":{"goal":"crm"}}`
		loaded       = `[{"type":"namespace","name":"crm","description":"CRM.","tools":[{"type":"function","name":"find","defer_loading":true,"parameters":{"type":"object"}}]}]`
	)
	request := func(tools, input string) string {
		return `{"model":"provider:openai gpt-5.5","tools":[` + tools + `],"input":[{"role":"user","content":"hi"}` + input + `]}`
	}
	output := func(tools string) string {
		return `,` + clientCall + `,{"type":"tool_search_output","call_id":"call_1","execution":"client","status":"completed","tools":` + tools + `}`
	}
	for _, test := range []struct{ name, body, want string }{
		{"deferred tools without a search", request(deferred, ""), "tools[0].tools[0].defer_loading needs a tool_search tool"},
		{"a deferred function", request(`{"type":"function","name":"find","defer_loading":true},{"type":"tool_search"}`, ""), ""},
		{"a deferred custom tool", request(`{"type":"custom","name":"note","defer_loading":true},{"type":"tool_search"}`, ""), ""},
		{"defer_loading that is not a boolean", request(`{"type":"function","name":"find","defer_loading":"yes"},{"type":"tool_search"}`, ""),
			"tools[0].defer_loading must be a boolean"},
		{"deferred tools on Claude", strings.Replace(request(deferred, ""), "provider:openai gpt-5.5", "anthropic-claude-sonnet-4-6", 1),
			"tools[0].tools[0].defer_loading is not supported for model claude-sonnet-4-6"},
		{"a search on Azure", strings.Replace(request(`{"type":"tool_search"}`, ""), "provider:openai gpt-5.5", "azure-gpt-5.5-2026-04-23", 1),
			"Only function, custom, and namespace tools are supported for Azure deployments"},
		{"two searches", request(`{"type":"tool_search"},`+clientSearch, ""), "tools[1].type duplicates another tool_search tool"},
		{"a search on an unknown side", request(`{"type":"tool_search","execution":"browser"}`, ""), "tools[0].execution must be server or client"},
		{"a search with an unknown field", request(`{"type":"tool_search","limit":3}`, ""), "tools[0].limit is not supported"},
		{"a client search and its output", request(clientSearch, output(loaded)), ""},
		{"an unanswered client search", request(clientSearch, `,`+clientCall), "tool_search tool calls require one matching output in the same stateless input"},
		{"an unanswered client search before a message", request(clientSearch, `,`+clientCall+`,{"role":"user","content":"again"}`), "input[2] must resolve the preceding client tool calls before adding another input item"},
		{"a function output for a search", request(clientSearch, `,`+clientCall+`,{"type":"function_call_output","call_id":"call_1","output":"x"}`), "input[2].call_id selects a different client tool type"},
		{"a search output for a function call", request(clientSearch+`,{"type":"function","name":"find"}`, `,{"type":"function_call","call_id":"call_1","name":"find","arguments":"{}"},{"type":"tool_search_output","call_id":"call_1","execution":"client","tools":[]}`), "input[2].call_id selects a different client tool type"},
		{"an output without its call", request(clientSearch, `,{"type":"tool_search_output","call_id":"call_1","execution":"client","tools":`+loaded+`}`),
			"input[1].call_id must match an earlier client tool call"},
		{"an output twice", request(clientSearch, output(loaded)+`,{"type":"tool_search_output","call_id":"call_1","execution":"client","tools":`+loaded+`}`),
			"input[3].call_id duplicates a client tool output"},
		{"a client search without call ID", request(clientSearch, `,{"type":"tool_search_call","execution":"client","arguments":{}}`),
			"input[1].call_id is required"},
		{"a server search with a call ID", request(`{"type":"tool_search"}`, `,{"type":"tool_search_call","call_id":"call_1","execution":"server","arguments":{}}`),
			"input[1].call_id must be null when OpenAI runs the search"},
		{"arguments that are not an object", request(clientSearch, `,{"type":"tool_search_call","call_id":"call_1","execution":"client","arguments":"crm"}`),
			"input[1].arguments must be an object"},
		{"a loaded hosted tool", request(clientSearch, output(`[{"type":"web_search"}]`)), "input[2].tools[0].type must be function, custom or namespace"},
		{"a loaded MCP server", request(clientSearch, output(`[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com"}]`)),
			"input[2].tools[0].type must be function, custom or namespace"},
		{"a loaded tool with cache_control", request(clientSearch, output(`[{"type":"function","name":"find","cache_control":{"type":"ephemeral"}}]`)),
			"input[2].tools[0].cache_control is not supported"},
		{"a loaded output schema that is not an object", request(clientSearch, output(`[{"type":"function","name":"find","output_schema":"text"}]`)),
			"input[2].tools[0].output_schema must be an object"},
		{"search items on Claude", strings.Replace(request(`{"type":"function","name":"find"}`, `,`+clientCall), "provider:openai gpt-5.5", "anthropic-claude-sonnet-4-6", 1),
			"tool_search_call input items are supported only for OpenAI deployments"},
		{"image search", request(`{"type":"web_search","search_content_types":["text","image"]}`, ""), ""},
		{"an unknown content type", request(`{"type":"web_search","search_content_types":["video"]}`, ""),
			"tools[0].search_content_types must be an array of text and image"},
		{"content types on the preview search", request(`{"type":"web_search_preview","search_content_types":["image"]}`, ""),
			"tools[0].search_content_types is not supported"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateResolvedResponses(t, test.body)
			if test.want == "" && err != nil || test.want != "" && (err == nil || err.Error() != test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// Codex 0.169 with gpt-5.5 declares its own tool search and image search, and loads the tools of
// MCP servers through the search, as its source builds them.
func TestCodexToolSearchReachesOpenAI(t *testing.T) {
	const tools = `[{"type":"function","name":"exec_command","description":"Runs a command.","strict":false,"parameters":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"],"additionalProperties":false}},` +
		`{"type":"tool_search","execution":"client","description":"# Tool discovery\n\nSearches over deferred tool metadata with BM25.","parameters":{"type":"object","properties":{"limit":{"type":"number","description":"Maximum number of tools to return. Defaults to 8."},"query":{"type":"string","description":"Search query for deferred tools."}},"required":["query"],"additionalProperties":false}},` +
		`{"type":"web_search","external_web_access":true,"search_content_types":["text","image"]}]`
	const input = `[{"type":"message","role":"user","content":[{"type":"input_text","text":"Find customer Ada."}]},` +
		`{"type":"tool_search_call","call_id":"call_search","status":"completed","execution":"client","arguments":{"query":"crm customer","limit":8}},` +
		`{"type":"tool_search_output","call_id":"call_search","status":"completed","execution":"client","tools":[{"type":"namespace","name":"mcp__crm__","description":"Tools in the crm MCP server.","tools":[{"type":"function","name":"find_customer","description":"Find a customer by name.","strict":false,"defer_loading":true,"parameters":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}]}]}]`
	request := `{"model":"provider:openai gpt-5.5","stream":true,"store":false,"tool_choice":"auto","parallel_tool_calls":true,"reasoning":{"effort":"medium"},` +
		`"include":["reasoning.encrypted_content"],"text":{"verbosity":"low"},"prompt_cache_key":"00000000-0000-7000-8000-000000000000","tools":` + tools + `,"input":` + input + `}`
	body, _, _ := providerBody(t, "/v1/responses", request)
	for field, want := range map[string]string{"tools": tools, "input": input} {
		var sent, took any
		if json.Unmarshal(body[field], &sent) != nil || json.Unmarshal([]byte(want), &took) != nil {
			t.Fatalf("%s does not decode", field)
		}
		if !reflect.DeepEqual(sent, took) {
			t.Fatalf("the gateway sends %s %s", field, body[field])
		}
	}
}
