package stogas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// computerExchange returns an exchange of the provider capture openai/computer-use (gpt-5.6-luna and
// gpt-6.2-sol, November 22, 2026) and its request, sent to an OpenAI deployment of the test catalog,
// whose model takes other reasoning efforts.
func computerExchange(t *testing.T, name string) (providerExchange, string) {
	t.Helper()
	recorded := exchange(t, providerCapture(t, "openai/computer-use"), name)
	var body map[string]json.RawMessage
	if err := json.Unmarshal(recorded.Request.Body, &body); err != nil {
		t.Fatal(err)
	}
	body["model"] = json.RawMessage(`"provider:openai gpt-5.5"`)
	delete(body, "reasoning")
	request, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return recorded, string(request)
}

// recordedOutput returns the raw output items of a recorded reply.
func recordedOutput(t *testing.T, recorded providerExchange) []json.RawMessage {
	t.Helper()
	var body struct {
		Output []json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(recorded.Response.Body, &body); err != nil || len(body.Output) == 0 {
		t.Fatalf("%s has no output: %v", recorded.Name, err)
	}
	return body.Output
}

func TestOpenAIComputerRepliesPass(t *testing.T) {
	for _, test := range []struct {
		name, outputBytes string
	}{
		{"a call", "0"},
		{"a screenshot returned", "0"},
		{"a screenshot at original detail", "0"},
		{"a screenshot without safety checks", "0"},
		// The model types "hello", which counts as output text.
		{"a typed text", "5"},
		{"a call on GPT-6.2 Sol", "0"},
		{"a forced call", "0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorded, request := computerExchange(t, test.name)
			var item struct {
				CallID string `json:"call_id"`
			}
			if err := json.Unmarshal(recordedOutput(t, recorded)[0], &item); err != nil || item.CallID == "" {
				t.Fatalf("recorded call has no call ID: %v", err)
			}
			state := resolvedResponseValidationState(t, request)
			reply := recorded.responsesReply(t)
			// The test deployment runs another model than the recording.
			reply.Model = state.Resolution.Deployment.Upstream.Model
			state.Signals = &StandardSignals{Prompt: 10, Completion: 10}
			if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: reply}, nil); err != nil {
				t.Fatalf("recorded reply refused: %v", err)
			}
			calls := state.loggedToolCalls()
			if len(calls) != 1 || calls[0].Type != "computer_call" || calls[0].CallID != item.CallID {
				t.Fatalf("logged calls = %+v, want the computer call %s", calls, item.CallID)
			}
			meters := metersForState(state)
			if got := meters[billing.MeterClientToolCalls].Quantity; got != "1" {
				t.Fatalf("client tool calls = %s, want 1", got)
			}
			if got := meters[billing.MeterOutputTextBytes].Quantity; got != test.outputBytes && !(test.outputBytes == "0" && got == "") {
				t.Fatalf("output text bytes = %s, want %s", got, test.outputBytes)
			}
		})
	}
}

func TestOpenAIComputerStreamsAsRecorded(t *testing.T) {
	recorded, request := computerExchange(t, "a streamed call")
	events := recorded.responsesStream(t)
	state := resolvedResponseValidationState(t, request)
	if err := replayLocalToolStream(state, events); err != nil {
		t.Fatalf("recorded stream refused: %v", err)
	}
	calls := state.loggedToolCalls()
	if len(calls) != 1 || calls[0].Type != "computer_call" || calls[0].CallID == "" || calls[0].DoneAt.Before(calls[0].StartedAt) {
		t.Fatalf("logged calls = %+v, want one timed computer call", calls)
	}
	if got := metersForState(state)[billing.MeterClientToolCalls].Quantity; got != "1" {
		t.Fatalf("client tool calls = %s, want 1", got)
	}
	// Typed text counts as output, as it does in a whole reply.
	typed := changedStream(t, recorded, func(item map[string]any) {
		if item["type"] == "computer_call" && item["status"] == "completed" {
			item["actions"] = []any{map[string]any{"type": "type", "text": "hello"}}
		}
	})
	typedState := resolvedResponseValidationState(t, request)
	if err := replayLocalToolStream(typedState, typed); err != nil {
		t.Fatalf("typed stream refused: %v", err)
	}
	if got := metersForState(typedState)[billing.MeterOutputTextBytes].Quantity; got != "5" {
		t.Fatalf("output text bytes = %s, want 5", got)
	}
	// The call's actions arrive whole on its done event, which a fallback must not follow.
	for _, event := range events {
		switch event.Type {
		case schemas.ResponsesStreamResponseTypeOutputItemAdded:
			if responsesEventHasOutput(event) {
				t.Fatal("the added call without actions counts as output")
			}
		case schemas.ResponsesStreamResponseTypeOutputItemDone:
			if !responsesEventHasOutput(event) {
				t.Fatal("the done call with its actions does not count as output")
			}
		}
	}
}

func TestOpenAIComputerStreamChecks(t *testing.T) {
	done := func(item map[string]any) bool {
		return item["type"] == "computer_call" && item["status"] == "completed"
	}
	for _, test := range []struct {
		name    string
		request func(map[string]any)
		item    func(map[string]any)
	}{
		{name: "a call that the request does not declare",
			request: func(body map[string]any) {
				body["tools"] = []any{map[string]any{"type": "function", "name": "look"}}
			}},
		{name: "tools turned off",
			request: func(body map[string]any) { body["tool_choice"] = "none" }},
		{name: "a call while the request forces a function",
			request: func(body map[string]any) {
				body["tools"] = append(body["tools"].([]any), map[string]any{"type": "function", "name": "look"})
				body["tool_choice"] = map[string]any{"type": "function", "name": "look"}
			}},
		{name: "a call without call ID",
			item: func(item map[string]any) {
				if item["type"] == "computer_call" {
					delete(item, "call_id")
				}
			}},
		{name: "a call that stays in progress",
			item: func(item map[string]any) {
				if item["type"] == "computer_call" {
					item["status"] = "in_progress"
				}
			}},
		{name: "a call with a name",
			item: func(item map[string]any) {
				if done(item) {
					item["name"] = "computer"
				}
			}},
		{name: "an action without type",
			item: func(item map[string]any) {
				if done(item) {
					item["actions"] = []any{map[string]any{"x": 1, "y": 2}}
				}
			}},
		{name: "typed text with a NUL",
			item: func(item map[string]any) {
				if done(item) {
					item["actions"] = []any{map[string]any{"type": "type", "text": "a\x00b"}}
				}
			}},
		{name: "a key that is empty",
			item: func(item map[string]any) {
				if done(item) {
					item["actions"] = []any{map[string]any{"type": "keypress", "keys": []any{""}}}
				}
			}},
		{name: "a safety check without ID",
			item: func(item map[string]any) {
				if done(item) {
					item["pending_safety_checks"] = []any{map[string]any{"code": "malicious_instructions", "message": "Check."}}
				}
			}},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorded, request := computerExchange(t, "a streamed call")
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

// Every action and safety check that OpenAI can send reaches the client as OpenAI sent it, and a
// check without its optional code and message stays without them.
func TestOpenAIComputerCallsReachTheClientUnchanged(t *testing.T) {
	var items []json.RawMessage
	for _, name := range []string{"a call", "a typed text", "a forced call"} {
		recorded, _ := computerExchange(t, name)
		items = append(items, recordedOutput(t, recorded)...)
	}
	stream, _ := computerExchange(t, "a streamed call")
	items = append(items, completedOutput(t, stream)...)
	items = append(items,
		json.RawMessage(`{"id":"cu_1","type":"computer_call","status":"completed","call_id":"call_1","actions":[`+
			`{"type":"click","button":"left","x":10,"y":20,"keys":["shift"]},{"type":"double_click","x":1,"y":2},`+
			`{"type":"drag","path":[{"x":0,"y":0},{"x":5,"y":6}]},{"type":"keypress","keys":["ctrl","c"]},{"type":"move","x":3,"y":4},`+
			`{"type":"scroll","x":5,"y":6,"scroll_x":0,"scroll_y":-120},{"type":"type","text":"héllo"},{"type":"wait"},{"type":"screenshot"}],`+
			`"pending_safety_checks":[{"id":"cu_sc_1","code":"malicious_instructions","message":"Check."},{"id":"cu_sc_2"}]}`))
	for _, item := range items {
		var decoded schemas.ResponsesMessage
		if err := json.Unmarshal(item, &decoded); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(&decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !sameJSON(t, encoded, item) {
			t.Fatalf("OpenAI sent %s, and the client gets %s", item, encoded)
		}
	}
}

// The gateway sends the computer items of a request as the client wrote them, which OpenAI took.
func TestOpenAIComputerItemsGoBack(t *testing.T) {
	first, _ := computerExchange(t, "a call")
	for _, name := range []string{"a screenshot returned", "a screenshot at original detail", "a screenshot without safety checks", "a typed text"} {
		t.Run(name, func(t *testing.T) {
			recorded, request := computerExchange(t, name)
			var took struct {
				Input []json.RawMessage `json:"input"`
			}
			if err := json.Unmarshal(recorded.Request.Body, &took); err != nil || len(took.Input) != 3 {
				t.Fatalf("recorded input: %v", err)
			}
			// The client returns the call as the gateway passed it on.
			if !sameJSON(t, took.Input[1], recordedOutput(t, first)[0]) {
				t.Fatalf("OpenAI took back %s, and sent %s", took.Input[1], recordedOutput(t, first)[0])
			}
			body, _, _ := providerBody(t, "/v1/responses", request)
			var sent []json.RawMessage
			if err := json.Unmarshal(body["input"], &sent); err != nil || len(sent) != len(took.Input) {
				t.Fatalf("the gateway sends %s", body["input"])
			}
			for index := 1; index < len(took.Input); index++ {
				// Core leaves out acknowledged_safety_checks null, and OpenAI took the same screenshot
				// without the field ("a screenshot returned").
				var want, got map[string]any
				if json.Unmarshal(took.Input[index], &want) != nil || json.Unmarshal(sent[index], &got) != nil {
					t.Fatal("items do not decode")
				}
				if checks, ok := want["acknowledged_safety_checks"]; ok && checks == nil {
					delete(want, "acknowledged_safety_checks")
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("the gateway sends %s, and OpenAI took %s", sent[index], took.Input[index])
				}
			}
		})
	}
}

func TestComputerRequestChecks(t *testing.T) {
	const (
		png        = `"data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="`
		call       = `{"type":"computer_call","id":"cu_1","call_id":"call_1","status":"completed","actions":[{"type":"screenshot"}]}`
		screenshot = `{"type":"computer_screenshot","image_url":` + png + `}`
	)
	request := func(tools, input string) string {
		return `{"model":"provider:openai gpt-5.5","tools":[` + tools + `],"input":[{"role":"user","content":"hi"}` + input + `]}`
	}
	answered := func(output string) string {
		return request(`{"type":"computer"}`, `,`+call+`,{"type":"computer_call_output","call_id":"call_1","output":`+output+`}`)
	}
	withChoice := func(choice string) string {
		return strings.Replace(request(`{"type":"computer"}`, ""), `"tools"`, `"tool_choice":`+choice+`,"tools"`, 1)
	}
	model := func(body, model string) string { return strings.Replace(body, "provider:openai gpt-5.5", model, 1) }
	for _, test := range []struct{ name, body, want string }{
		{"the computer tool", request(`{"type":"computer"}`, ""), ""},
		{"a computer tool with a display size", request(`{"type":"computer","display_width":1024}`, ""), "tools[0].display_width is not supported"},
		{"the retired preview tool", request(`{"type":"computer_use_preview","display_width":1024,"display_height":768,"environment":"browser"}`, ""),
			"computer_use_preview is not supported because OpenAI retired the model that runs it; use the computer tool"},
		{"Anthropic's computer tool", request(`{"type":"computer_20251124","name":"computer","display_width_px":1024,"display_height_px":768}`, ""),
			"Only function, custom, namespace, shell, apply_patch, computer, tool_search, file_search, code_interpreter, image_generation, remote MCP, and priced hosted web search tools are supported"},
		{"the computer tool on Azure", model(request(`{"type":"computer"}`, ""), "azure-gpt-5.5-2026-04-23"),
			"Only function, custom, and namespace tools are supported for Azure deployments"},
		{"the computer tool on Claude", model(request(`{"type":"computer"}`, ""), "anthropic-claude-sonnet-4-6"), "computer tools are not supported"},
		{"a forced computer tool", withChoice(`{"type":"computer"}`), ""},
		{"a forced computer tool that the request does not declare", strings.Replace(withChoice(`{"type":"computer"}`), `{"type":"computer"}]`, `{"type":"function","name":"look"}]`, 1),
			"tool_choice selects an undeclared computer tool"},
		{"a forced computer tool with a name", withChoice(`{"type":"computer","name":"computer"}`), "tool_choice.name is not supported"},
		{"the computer tool among allowed tools", withChoice(`{"type":"allowed_tools","mode":"required","tools":[{"type":"computer"}]}`), ""},
		{"the computer tool allowed twice", withChoice(`{"type":"allowed_tools","mode":"auto","tools":[{"type":"computer"},{"type":"computer"}]}`),
			"tool_choice.tools[1] duplicates another allowed tool"},
		{"a screenshot", answered(screenshot), ""},
		{"a screenshot at original detail", answered(`{"type":"computer_screenshot","image_url":` + png + `,"detail":"original"}`), ""},
		{"a screenshot by URL", answered(`{"type":"computer_screenshot","image_url":"https://example.com/screen.png"}`), ""},
		{"a screenshot by FTP", answered(`{"type":"computer_screenshot","image_url":"ftp://example.com/screen.png"}`),
			"input[2].output requires an HTTP(S) URL or base64 data URL"},
		{"a screenshot by file ID on our own account", answered(`{"type":"computer_screenshot","file_id":"file-1"}`), "BYOK"},
		// OpenAI refuses it too (capture openai/computer-use), which the Agents SDK sends when its
		// computer returns no screenshot.
		{"a screenshot with an empty URL", answered(`{"type":"computer_screenshot","image_url":""}`),
			"input[2].output requires exactly one inline payload, URL or provider file ID"},
		{"a screenshot with two sources", answered(`{"type":"computer_screenshot","image_url":"https://example.com/a.png","file_id":"file-1"}`),
			"exactly one"},
		{"a screenshot with another field", answered(`{"type":"computer_screenshot","image_url":` + png + `,"size":1}`), "input[2].output.size is not supported"},
		{"a screenshot with invalid base64", answered(`{"type":"computer_screenshot","image_url":"data:image/png;base64,@@@@"}`), "base64"},
		{"an image instead of a screenshot", answered(`{"type":"input_image","image_url":` + png + `}`), "input[2].output must be a computer_screenshot"},
		{"text instead of a screenshot", answered(`"done"`), "input[2].output must be a computer_screenshot"},
		{"an unanswered call", request(`{"type":"computer"}`, `,`+call), "computer tool calls require one matching output in the same stateless input"},
		{"a message before the answer", request(`{"type":"computer"}`, `,`+call+`,{"role":"user","content":"again"}`),
			"input[2] must resolve the preceding client tool calls before adding another input item"},
		{"an answer without its call", request(`{"type":"computer"}`, `,{"type":"computer_call_output","call_id":"call_1","output":`+screenshot+`}`),
			"input[1].call_id must match an earlier client tool call"},
		{"a function output for a computer call", request(`{"type":"computer"}`, `,`+call+`,{"type":"function_call_output","call_id":"call_1","output":"x"}`),
			"input[2].call_id selects a different client tool type"},
		{"a screenshot for a function call", request(`{"type":"function","name":"look"}`, `,{"type":"function_call","call_id":"call_1","name":"look","arguments":"{}"},{"type":"computer_call_output","call_id":"call_1","output":`+screenshot+`}`),
			"input[2].call_id selects a different client tool type"},
		{"an answer twice", request(`{"type":"computer"}`, `,`+call+`,{"type":"computer_call_output","call_id":"call_1","output":`+screenshot+`},{"type":"computer_call_output","call_id":"call_1","output":`+screenshot+`}`),
			"input[3].call_id duplicates a client tool output"},
		{"two calls with one call ID", request(`{"type":"computer"}`, `,`+call+`,`+call), "input[2].call_id duplicates another client tool call"},
		{"a call of the preview's single action", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","action":{"type":"click","button":"left","x":1,"y":2}},{"type":"computer_call_output","call_id":"call_1","output":`+screenshot+`}`), ""},
		{"actions that are not a list", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","actions":{"type":"wait"}}`),
			"Invalid JSON body"},
		{"an action that is null", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","actions":[null]}`),
			"input[1].actions[0] must be an object"},
		{"a single action that is text", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","action":"click"}`),
			"input[1].action must be an object"},
		{"null instead of optional fields", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","action":null,"actions":[{"type":"wait"}],"pending_safety_checks":null},{"type":"computer_call_output","call_id":"call_1","output":`+screenshot+`}`), ""},
		{"an action without type", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","actions":[{"x":1}]}`),
			"input[1].actions[0].type is required"},
		{"a call with a name", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","name":"computer","actions":[]}`),
			"input[1].name is not supported"},
		{"a call ID over 64 bytes", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"`+strings.Repeat("c", 65)+`","actions":[]}`),
			"input[1].call_id must contain at most 64 bytes"},
		{"a failed call", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","status":"failed","actions":[]}`),
			"input[1].status is not supported"},
		{"a call without call ID", request(`{"type":"computer"}`, `,{"type":"computer_call","actions":[]}`), "input[1].call_id is required"},
		{"acknowledged safety checks", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","actions":[{"type":"wait"}],"pending_safety_checks":[{"id":"cu_sc_1","code":"malicious_instructions","message":"Check."}]},{"type":"computer_call_output","call_id":"call_1","output":`+screenshot+`,"acknowledged_safety_checks":[{"id":"cu_sc_1","code":"malicious_instructions","message":null}]}`), ""},
		{"no safety checks as null", answered(screenshot + `,"acknowledged_safety_checks":null`), ""},
		{"a safety check without ID", answered(screenshot + `,"acknowledged_safety_checks":[{"code":"malicious_instructions"}]`),
			"input[2].acknowledged_safety_checks[0].id is required"},
		{"a safety check with another field", answered(screenshot + `,"acknowledged_safety_checks":[{"id":"cu_sc_1","level":"high"}]`),
			"input[2].acknowledged_safety_checks[0].level is not supported"},
		{"safety checks that are not a list", answered(screenshot + `,"acknowledged_safety_checks":{"id":"cu_sc_1"}`), "Invalid JSON body"},
		{"a safety check that is null", answered(screenshot + `,"acknowledged_safety_checks":[null]`),
			"input[2].acknowledged_safety_checks[0] must be an object"},
		{"a safety check code that is not text", answered(screenshot + `,"acknowledged_safety_checks":[{"id":"cu_sc_1","code":7}]`), "Invalid JSON body"},
		{"pending safety checks without ID", request(`{"type":"computer"}`, `,{"type":"computer_call","call_id":"call_1","actions":[],"pending_safety_checks":[{}]}`),
			"input[1].pending_safety_checks[0].id is required"},
		{"computer items on Claude", model(request(`{"type":"function","name":"look"}`, `,`+call), "anthropic-claude-sonnet-4-6"),
			"computer_call input items are supported only for OpenAI deployments"},
		{"computer items on Azure", model(request(`{"type":"function","name":"look"}`, `,`+call), "azure-gpt-5.5-2026-04-23"),
			"computer_call input items are supported only for OpenAI deployments"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateResolvedResponses(t, test.body)
			if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// A screenshot that the client uploaded with its own key goes to OpenAI by its file ID, and the
// hold covers the deployment's whole input, because the gateway cannot count the image.
func TestComputerScreenshotByFileIDOnCustomerKey(t *testing.T) {
	snapshot, prepared := customerOpenAICredential(t)
	body := `{"model":"provider:openai gpt-5.5","max_output_tokens":100,"tools":[{"type":"computer"}],"input":[{"role":"user","content":"Click the button."},` +
		`{"type":"computer_call","call_id":"call_1","actions":[{"type":"screenshot"}]},{"type":"computer_call_output","call_id":"call_1","output":{"type":"computer_screenshot","file_id":"file-customer-owned"}}]}`
	resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	// One dollar per token makes the expected hold independent of catalog prices.
	resolved.Deployment.Pricing = billing.Pricing{billing.MeterInputTokens: {billing.RatePerMillionTokens: "1000000"}, billing.MeterOutputTokens: {billing.RatePerMillionTokens: "1000000"}}
	state := NewState(resolved, "sk-test", snapshot.Claims, AdapterFor(resolved.Provider))
	state.PreparedCredential = prepared
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatal(err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatal(err)
	}
	full := resolved.Deployment.MaxInputTokens
	if findMeter(state.Hold.Meters, billing.MeterInputTokens, strconv.Itoa(full)) == nil || state.Hold.EstimatedUpstreamCostUSD != strconv.Itoa(full+100) {
		t.Fatalf("full input plus output hold missing: %+v", state.Hold)
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
	request, err := resolved.ToBifrost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatal(err)
	}
	resolved.ReleaseInput()
	if !bytes.Contains(preparedProviderBody(t, ctx, request.ResponsesRequest), []byte(`"output":{"type":"computer_screenshot","file_id":"file-customer-owned"}`)) {
		t.Fatal("provider lost the screenshot's file ID")
	}
}

// The tool adds 811 input tokens to what OpenAI counts, which the hold takes whatever tool_choice
// says. A screenshot makes the hold cover the deployment's whole input.
func TestComputerToolHold(t *testing.T) {
	recorded, request := computerExchange(t, "a call")
	_, bare := computerExchange(t, "without the tool")
	withTool, _ := heldInputTokens(t, request)
	without, _ := heldInputTokens(t, bare)
	none, _ := heldInputTokens(t, changedRequest(t, request, func(body map[string]any) { body["tool_choice"] = "none" }))
	var usage struct {
		Usage struct {
			InputTokens int64 `json:"input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(recorded.Response.Body, &usage); err != nil {
		t.Fatal(err)
	}
	if withTool < usage.Usage.InputTokens || withTool-without < 811 || none != withTool {
		t.Fatalf("held %d with the tool, %d without it and %d with tools off; OpenAI counted %d", withTool, without, none, usage.Usage.InputTokens)
	}
	_, answered := computerExchange(t, "a screenshot returned")
	held, state := heldInputTokens(t, answered)
	if full := int64(state.Resolution.Deployment.MaxInputTokens); held < full {
		t.Fatalf("held %d input tokens for a screenshot, want the whole input %d", held, full)
	}
}
