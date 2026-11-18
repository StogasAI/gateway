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

// These tests cover Chat Completions clients of deployments that serve them through Responses: those
// that take only Responses, such as Pro, and those that take both, for requests with tools.

const chatBridgeTools = `"tools":[{"type":"function","function":{"name":"lookup","description":"Look up a value","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}}]`

// chatBridgeValidation resolves a Chat Completions request and checks it as a pair does.
func chatBridgeValidation(t *testing.T, body string) (*State, error) {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)})
	if err != nil {
		return nil, err
	}
	if !resolution.Bridged() {
		t.Fatalf("deployment %s serves the request on Chat Completions", resolution.Deployment.ID)
	}
	state := testPair(resolution)
	return state, state.Adapter.ValidateRequest(state)
}

// chatBridgeState prepares a Chat Completions request that reaches its deployment through Responses,
// as a pair does.
func chatBridgeState(t *testing.T, body string) *State {
	t.Helper()
	state, err := chatBridgeValidation(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatal(err)
	}
	return state
}

// chatBridgeProviderBody is the Responses body that the provider gets.
func chatBridgeProviderBody(t *testing.T, state *State) map[string]json.RawMessage {
	t.Helper()
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.WireRequestType())
	request, err := state.Resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if request.ResponsesRequest == nil || request.ChatRequest != nil || request.RequestType != state.Resolution.WireRequestType() {
		t.Fatalf("provider request = %#v", request)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(preparedProviderBody(t, ctx, request.ResponsesRequest), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestChatReachesResponsesOnlyDeploymentsThroughResponses(t *testing.T) {
	// Both take back the encrypted reasoning of their replies, which a Chat client cannot ask for.
	for _, model := range []string{"openai-gpt-5.6-sol-pro", "azure-gpt-6-astra-pro"} {
		t.Run(model, func(t *testing.T) {
			state := chatBridgeState(t, `{"model":"`+model+`","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"Find a1."},`+
				`{"role":"assistant","content":"Looking.","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]},`+
				`{"role":"tool","tool_call_id":"call_1","content":"42"},{"role":"user","content":"Answer."}],`+chatBridgeTools+
				`,"tool_choice":"auto","max_completion_tokens":300,"reasoning_effort":"high","stream":true,"stream_options":{"include_usage":true},`+
				`"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false},"strict":true}}}`)
			resolution := state.Resolution
			if resolution.RequestType != schemas.ChatCompletionStreamRequest || resolution.WireRoute() != catalog.RouteResponses ||
				resolution.WireRequestType() != schemas.ResponsesStreamRequest {
				t.Fatalf("request type %s, wire %s %s", resolution.RequestType, resolution.WireRoute(), resolution.WireRequestType())
			}
			body := chatBridgeProviderBody(t, state)
			want := map[string]string{
				"model":             `"` + resolution.Model + `"`,
				"input":             `[{"type":"message","role":"system","content":"Be brief."},{"type":"message","role":"user","content":"Find a1."},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Looking.","annotations":[],"logprobs":[]}]},{"arguments":"{\"id\":\"a1\"}","type":"function_call","call_id":"call_1","name":"lookup"},{"type":"function_call_output","call_id":"call_1","output":"42"},{"type":"message","role":"user","content":"Answer."}]`,
				"tools":             `[{"type":"function","name":"lookup","description":"Look up a value","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]},"strict":false}]`,
				"tool_choice":       `"auto"`,
				"max_output_tokens": `300`,
				"reasoning":         `{"effort":"high","mode":"pro","summary":null}`,
				"text":              `{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false},"strict":true}}`,
				"store":             `false`,
				"stream":            `true`,
				"service_tier":      `"default"`,
				"include":           `["reasoning.encrypted_content"]`,
			}
			for name, value := range want {
				if string(body[name]) != value {
					t.Errorf("%s = %s, want %s", name, body[name], value)
				}
			}
			for name := range body {
				if _, ok := want[name]; !ok {
					t.Errorf("unexpected field %s = %s", name, body[name])
				}
			}
		})
	}
}

func TestChatReachesDeploymentsThatTakeBothInterfacesOnOne(t *testing.T) {
	const (
		user    = `"messages":[{"role":"user","content":"hi"}]`
		history = `"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hi.","reasoning_details":[{"index":0,"type":"reasoning.encrypted","id":"rs_1","data":"openai:acct-test:opaque"}]},{"role":"user","content":"Go on."}]`
		// OpenAI's encrypted reasoning that the gateway did not bind to an account, which no
		// deployment takes back.
		unboundHistory = `"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hi.","reasoning_details":[{"index":0,"type":"reasoning.encrypted","id":"rs_1","data":"opaque","format":"openai-responses-v1"}]},{"role":"user","content":"Go on."}]`
		// Claude's reasoning, which OpenAI's deployments leave out on either interface.
		claudeHistory = `"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hi.","reasoning_details":[{"index":0,"type":"reasoning.text","text":"Greet.","signature":"sig"},{"index":1,"type":"reasoning.encrypted","data":"redacted"}]},{"role":"user","content":"Go on."}]`
	)
	for name, test := range map[string]struct{ body, route string }{
		"plain request":           {`"model":"provider:openai gpt-6-luna",` + user, "openai-chat-completions"},
		"tools":                   {`"model":"provider:openai gpt-6-luna",` + user + `,` + chatBridgeTools, "openai-responses"},
		"tools without reasoning": {`"model":"provider:openai gpt-6-luna",` + user + `,` + chatBridgeTools + `,"reasoning_effort":"none"`, "openai-chat-completions"},
		"tools, reasoning off":    {`"model":"provider:openai gpt-6-luna",` + user + `,` + chatBridgeTools + `,"reasoning":{"enabled":false}`, "openai-chat-completions"},
		"tools, reasoning low":    {`"model":"provider:openai gpt-6-luna",` + user + `,` + chatBridgeTools + `,"reasoning":{"effort":"low"}`, "openai-responses"},
		"tools without reasoning, with reasoning history": {`"model":"provider:openai gpt-6-luna",` + history + `,` + chatBridgeTools + `,"reasoning_effort":"none"`, "openai-responses"},
		"tools on Azure":            {`"model":"azure-gpt-5.6-sol",` + user + `,` + chatBridgeTools, "azure-responses"},
		"reasoning history":         {`"model":"provider:openai gpt-6-luna",` + history, "openai-responses"},
		"Claude reasoning history":  {`"model":"provider:openai gpt-6-luna",` + claudeHistory, "openai-chat-completions"},
		"unbound reasoning history": {`"model":"provider:openai gpt-6-luna",` + unboundHistory, "openai-chat-completions"},
		"empty tools":               {`"model":"provider:openai gpt-6-luna",` + user + `,"tools":[]`, "openai-chat-completions"},
		"tools with a seed":         {`"model":"provider:openai gpt-6-luna",` + user + `,` + chatBridgeTools + `,"seed":1`, "openai-chat-completions"},
		"tools on the Chat route":   {`"model":"route:openai-chat-completions gpt-6-luna",` + user + `,` + chatBridgeTools, "openai-chat-completions"},
	} {
		t.Run(name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte("{" + test.body + "}")})
			if err != nil {
				t.Fatal(err)
			}
			if resolution.Deployment.RouteID != test.route {
				t.Fatalf("route = %s, want %s", resolution.Deployment.RouteID, test.route)
			}
		})
	}
}

func TestChatBridgeRefusesWhatResponsesLackOrTheFormatRefuses(t *testing.T) {
	for _, test := range []struct{ name, fields, want string }{
		{"several choices", `"n":2`, "n: Responses deployments do not support several choices"},
		{"seed", `"seed":7`, "seed: Responses deployments do not support seeds"},
		{"stop sequences", `"stop":["END"]`, "stop: Responses deployments do not support stop sequences"},
		{"logit bias", `"logit_bias":{"50256":-100}`, "logit_bias: Responses deployments do not support logit biases"},
		{"predicted output", `"prediction":{"type":"content","content":"x"}`, "prediction: Responses deployments do not support predicted outputs"},
		{"message name", `"messages":[{"role":"user","name":"ann","content":"hi"}]`, "messages[0].name: Responses deployments do not support message names"},
		// OpenAI's format refuses these on Chat Completions, so the translation must not drop them.
		{"repetition penalty", `"repetition_penalty":1.1`, "repetition_penalty is not supported for OpenAI-format deployments"},
		{"reasoning display", `"reasoning":{"display":"updates"}`, "reasoning.display"},
		{"top_k", `"top_k":5`, "top_k"},
		{"prompt cache breakpoint member", `"messages":[{"role":"user","content":[{"type":"text","text":"hi","prompt_cache_breakpoint":{"mode":"explicit","ttl":"1h"}}]}]`, "prompt_cache_breakpoint.ttl must be 30m"},
		{"prompt cache option", `"prompt_cache_options":{"mode":"implicit","scope":"org"}`, "prompt_cache_options supports only mode and ttl"},
		{"breakpoint in a tool output", `"messages":[{"role":"user","content":"Find a1."},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]},` +
			`{"role":"tool","tool_call_id":"call_1","content":[{"type":"text","text":"42","prompt_cache_breakpoint":{"mode":"explicit"}}]}],` + chatBridgeTools,
			"messages[2].content[0].prompt_cache_breakpoint: Responses deployments do not support prompt cache breakpoints in tool outputs"},
		{"cache control in a tool output", `"messages":[{"role":"user","content":"Find a1."},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]},` +
			`{"role":"tool","tool_call_id":"call_1","content":[{"type":"text","text":"42","cache_control":{"type":"ephemeral"}}]}],` + chatBridgeTools, "cache_control"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"hi"}],` + test.fields + `}`
			if strings.Contains(test.fields, `"messages"`) {
				body = `{"model":"openai-gpt-5.6-sol-pro",` + test.fields + `}`
			}
			_, err := chatBridgeValidation(t, body)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// A Chat Completions client of OpenAI's models asks for reasoning summaries with the display
// summarized. Only Responses return them, so a request that reasons goes through Responses, which
// get the summary auto. A request that Responses cannot carry is refused rather than answered
// without them. Open models return their reasoning whole, so they take either display and stay on
// Chat Completions, and their provider gets no display.
func TestChatSummarizedReasoningGoesThroughResponses(t *testing.T) {
	const user = `"messages":[{"role":"user","content":"Find a1."}]`
	for name, test := range map[string]struct{ body, route, err string }{
		"summarized":                   {`"model":"provider:openai gpt-6-luna",` + user + `,"reasoning":{"display":"summarized"}`, "openai-responses", ""},
		"summarized on Azure":          {`"model":"azure-gpt-5.6-sol",` + user + `,"reasoning_display":"summarized"`, "azure-responses", ""},
		"summarized, with tools":       {`"model":"provider:openai gpt-6-luna",` + user + `,"reasoning_display":"summarized",` + chatBridgeTools, "openai-responses", ""},
		"summarized, reasoning off":    {`"model":"provider:openai gpt-6-luna",` + user + `,"reasoning":{"display":"summarized","effort":"none"}`, "openai-chat-completions", ""},
		"summarized, enabled false":    {`"model":"provider:openai gpt-6-luna",` + user + `,"reasoning":{"display":"summarized","enabled":false}`, "openai-chat-completions", ""},
		"omitted":                      {`"model":"provider:openai gpt-6-luna",` + user + `,"reasoning_display":"omitted"`, "openai-chat-completions", ""},
		"summarized with a seed":       {`"model":"provider:openai gpt-6-luna",` + user + `,"reasoning_display":"summarized","seed":1`, "openai-chat-completions", "reasoning_display summarized is not supported with seed"},
		"updates":                      {`"model":"provider:openai gpt-6-luna",` + user + `,"reasoning":{"display":"updates"}`, "openai-chat-completions", "reasoning.display must be summarized or omitted for the selected deployment"},
		"an open model on Azure":       {`"model":"azure-deepseek-v4-flash-0423",` + user + `,"reasoning":{"display":"summarized"}`, "", ""},
		"omitted on Chutes":            {`"model":"chutes-glm-5.2",` + user + `,"reasoning_display":"omitted"`, "", ""},
		"updates on an open model":     {`"model":"azure-deepseek-v4-flash-0423",` + user + `,"reasoning":{"display":"updates"}`, "", "reasoning.display must be summarized or omitted for the selected deployment"},
		"summarized on the Chat route": {`"model":"route:openai-chat-completions gpt-6-luna",` + user + `,"reasoning_display":"summarized"`, "openai-chat-completions", "reasoning_display summarized is not supported for the selected deployment"},
	} {
		t.Run(name, func(t *testing.T) {
			body := "{" + test.body + "}"
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)})
			if err != nil {
				t.Fatal(err)
			}
			if test.route != "" && resolution.Deployment.RouteID != test.route {
				t.Fatalf("route = %s, want %s", resolution.Deployment.RouteID, test.route)
			}
			if err := validateResolvedChat(t, body); test.err == "" && err != nil || test.err != "" && (err == nil || !strings.Contains(err.Error(), test.err)) {
				t.Fatalf("error = %v, want %q", err, test.err)
			}
		})
	}
	for _, body := range []string{
		`{"model":"azure-deepseek-v4-flash-0423",` + user + `,"reasoning":{"effort":"high","display":"summarized"}}`,
		`{"model":"chutes-glm-5.2",` + user + `,"reasoning":{"effort":"high"},"reasoning_display":"summarized"}`,
	} {
		wire, _, _ := providerBody(t, "/v1/chat/completions", body)
		if sent, _ := json.Marshal(wire); strings.Contains(string(sent), "display") || strings.Contains(string(sent), "summary") {
			t.Fatalf("%s: provider body = %s", body, sent)
		}
	}
	for body, want := range map[string]string{
		`{"model":"provider:openai gpt-6-luna",` + user + `,"reasoning":{"effort":"low","display":"summarized"}}`:   `{"effort":"low","summary":"auto"}`,
		`{"model":"openai-gpt-5.6-sol-pro",` + user + `,"reasoning_effort":"low","reasoning_display":"summarized"}`: `{"effort":"low","mode":"pro","summary":"auto"}`,
		// OpenAI and Azure take a null effort (testdata/provider/openai/reasoning-null-effort.json).
		`{"model":"azure-gpt-5.6-sol",` + user + `,"reasoning":{"display":"summarized"}}`: `{"effort":null,"summary":"auto"}`,
	} {
		if reasoning := string(chatBridgeProviderBody(t, chatBridgeState(t, body))["reasoning"]); reasoning != want {
			t.Fatalf("%s: reasoning sent = %s", body, reasoning)
		}
	}
}

// summaryRequest asks OpenAI's model of a recorded reply for its reasoning summaries, with the tool
// that the recorded reply calls.
const summaryRequest = `{"model":"provider:openai gpt-6-luna","messages":[{"role":"user","content":"Work it out."}],"reasoning":{"display":"summarized"},` +
	`"tools":[{"type":"function","function":{"name":"get_secret_number","description":"Returns the secret number.","parameters":{"type":"object","properties":{},"additionalProperties":false},"strict":true}}]`

// A recorded reply with a reasoning summary reaches a Chat Completions client with the summary as
// its reasoning text and in a summary detail, which goes back to no provider.
func TestChatSummarizedReasoningReplyHoldsTheSummary(t *testing.T) {
	mint := exchange(t, providerCapture(t, "openai/encrypted-reasoning-summary"), "openai mint")
	recorded := mint.responsesReply(t)
	var summary string
	for _, item := range recorded.Output {
		if item.ResponsesReasoning != nil && len(item.ResponsesReasoning.Summary) > 0 {
			summary = item.ResponsesReasoning.Summary[0].Text
		}
	}
	state := chatBridgeState(t, summaryRequest+`}`)
	response := &schemas.BifrostResponse{ResponsesResponse: recorded}
	if err := state.Adapter.IngestResponse(state, response, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompletedExecution(state); err != nil {
		t.Fatal(err)
	}
	converted, err := BridgedResponse(state, response)
	if err != nil {
		t.Fatal(err)
	}
	message := converted.ChatResponse.Choices[0].ChatNonStreamResponseChoice.Message
	assistant := message.ChatAssistantMessage
	if summary == "" || assistant.Reasoning == nil || *assistant.Reasoning != summary || len(assistant.ReasoningDetails) != 2 ||
		assistant.ReasoningDetails[0].Summary == nil || *assistant.ReasoningDetails[0].Summary != summary ||
		assistant.ReasoningDetails[1].Type != schemas.BifrostReasoningDetailsTypeEncrypted {
		t.Fatalf("message = %+v", assistant)
	}

	// The client sends the reply back, and OpenAI gets its encrypted reasoning without the summary.
	sent, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	next := chatBridgeState(t, strings.Replace(summaryRequest, `"content":"Work it out."}]`, `"content":"Work it out."},`+string(sent)+
		`,{"role":"tool","tool_call_id":"`+*assistant.ToolCalls[0].ID+`","content":"41"}]`, 1)+`}`)
	input := string(chatBridgeProviderBody(t, next)["input"])
	if strings.Contains(input, "Calculating") || !strings.Contains(input, `"type":"reasoning","summary":[],"encrypted_content":"gAAAA`) {
		t.Fatalf("input = %s", input)
	}
}

// A recorded stream with a reasoning summary reaches a Chat Completions client as reasoning deltas,
// each with its summary detail.
func TestChatSummarizedReasoningStreamHoldsTheSummary(t *testing.T) {
	for _, provider := range []string{"openai", "azure"} {
		recorded := exchange(t, providerCapture(t, "openai/reasoning-summary-stream"), provider+" stream")
		model := map[string]string{"openai": "provider:openai gpt-6-luna", "azure": "azure-gpt-5.6-sol"}[provider]
		state := chatBridgeState(t, strings.Replace(summaryRequest, `"provider:openai gpt-6-luna"`, `"`+model+`"`, 1)+`,"stream":true}`)
		stream := NewBridgedStream(state)
		var parts []string
		var reasoning, details strings.Builder
		for _, event := range recorded.responsesStream(t) {
			if event.Type == schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone {
				parts = append(parts, *event.Text)
			}
			chunk := &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}
			if err := state.Adapter.IngestChunk(state, chunk); err != nil {
				t.Fatalf("%s: recorded %s event refused: %v", provider, event.Type, err)
			}
			converted, err := stream.Convert(chunk)
			if err != nil {
				t.Fatalf("%s: %s: %v", provider, event.Type, err)
			}
			for _, chunk := range converted {
				for _, choice := range chunk.BifrostChatResponse.Choices {
					delta := choice.ChatStreamResponseChoice.Delta
					if delta.Reasoning != nil {
						reasoning.WriteString(*delta.Reasoning)
					}
					for _, detail := range delta.ReasoningDetails {
						if detail.Summary != nil {
							details.WriteString(*detail.Summary)
						}
					}
				}
			}
		}
		if len(parts) == 0 || reasoning.String() != strings.Join(parts, "\n\n") || details.String() != strings.Join(parts, "") {
			t.Fatalf("%s: reasoning = %q, details = %q, summary parts = %q", provider, reasoning.String(), details.String(), parts)
		}
	}
}

// A Chat Completions client gets an OpenAI-format deployment's reasoning as encrypted
// reasoning_details, which it sends back so that the model keeps its reasoning across turns. A
// deployment gets only the reasoning that it takes back: encrypted reasoning that its own account
// produced, never another account's, and neither Claude's nor plain reasoning.
func TestChatBridgeTakesBackEncryptedReasoning(t *testing.T) {
	history := func(data string) string {
		return `"messages":[{"role":"user","content":"Find a1."},{"role":"assistant","reasoning_details":[{"index":0,"type":"reasoning.encrypted","id":"rs_1","data":"` + data + `"}],` +
			`"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"42"}],` + chatBridgeTools
	}
	for _, model := range []string{"openai-gpt-5.6-sol-pro", "azure-gpt-6-astra-pro"} {
		input := string(chatBridgeProviderBody(t, chatBridgeState(t, `{"model":"`+model+`",`+history(boundReasoning("opaque"))+`}`))["input"])
		if !strings.Contains(input, `{"id":"rs_1","type":"reasoning","summary":[],"encrypted_content":"opaque"}`) {
			t.Fatalf("%s input = %s", model, input)
		}
	}
	// OpenAI takes back its reasoning without the ID too, which a client can drop.
	withoutID := strings.Replace(history(boundReasoning("opaque")), `"id":"rs_1",`, "", 1)
	if input := string(chatBridgeProviderBody(t, chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro",`+withoutID+`}`))["input"]); !strings.Contains(input, `{"type":"reasoning","summary":[],"encrypted_content":"opaque"}`) {
		t.Fatalf("input without the ID = %s", input)
	}
	for _, test := range []struct{ name, body, want string }{
		{"another account", `{"model":"openai-gpt-5.6-sol-pro",` + history("openai:acct-other:opaque") + `}`, `"type":"function_call"`},
		{"unbound", `{"model":"azure-gpt-6-astra-pro",` + history("opaque") + `}`, `"type":"function_call"`},
		{"Claude reasoning", `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hello.","reasoning":"Thinking.","reasoning_details":[{"index":0,"type":"reasoning.text","text":"Thinking.","signature":"sig"},{"index":1,"type":"reasoning.encrypted","data":"redacted"}]},{"role":"user","content":"again"}]}`, `"Hello."`},
		{"plain reasoning", `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hello.","reasoning":"Thinking."},{"role":"user","content":"again"}]}`, `"Hello."`},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := string(chatBridgeProviderBody(t, chatBridgeState(t, test.body))["input"])
			if strings.Contains(input, "reasoning") || !strings.Contains(input, test.want) {
				t.Fatalf("input = %s", input)
			}
		})
	}
}

func chatBridgeReply(output ...schemas.ResponsesMessage) *schemas.BifrostResponse {
	return &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		ID: schemas.Ptr("resp_bridge"), Object: "response", CreatedAt: 1_700_000_000,
		Status: schemas.Ptr(schemas.ResponsesResponseStatusCompleted), Output: output,
		Usage: &schemas.ResponsesResponseUsage{
			InputTokens: 20, OutputTokens: 15, TotalTokens: 35,
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{ReasoningTokens: 4},
		},
	}}
}

func encryptedReasoningItem(id, data string) schemas.ResponsesMessage {
	return schemas.ResponsesMessage{
		ID: schemas.Ptr(id), Type: schemas.Ptr(schemas.ResponsesMessageTypeReasoning),
		ResponsesReasoning: &schemas.ResponsesReasoning{Summary: []schemas.ResponsesReasoningSummary{}, EncryptedContent: schemas.Ptr(data)},
	}
}

func textItem(id, text string) schemas.ResponsesMessage {
	return schemas.ResponsesMessage{
		ID: schemas.Ptr(id), Type: schemas.Ptr(schemas.ResponsesMessageTypeMessage),
		Role: schemas.Ptr(schemas.ResponsesInputMessageRoleAssistant), Status: schemas.Ptr("completed"),
		Content: &schemas.ResponsesMessageContent{ContentBlocks: []schemas.ResponsesMessageContentBlock{{
			Type: schemas.ResponsesOutputMessageContentTypeText, Text: schemas.Ptr(text),
			ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{}},
		}}},
	}
}

func functionCallItem(id, callID, name, arguments string) schemas.ResponsesMessage {
	return schemas.ResponsesMessage{
		ID: schemas.Ptr(id), Type: schemas.Ptr(schemas.ResponsesMessageTypeFunctionCall), Status: schemas.Ptr("completed"),
		ResponsesToolMessage: &schemas.ResponsesToolMessage{CallID: schemas.Ptr(callID), Name: schemas.Ptr(name), Arguments: schemas.Ptr(arguments)},
	}
}

func TestChatBridgeReplyBecomesChatCompletions(t *testing.T) {
	state := chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Find a1."}],`+chatBridgeTools+`}`)
	response := chatBridgeReply(
		encryptedReasoningItem("rs_1", "opaque"),
		textItem("msg_1", "Looking it up."),
		functionCallItem("fc_1", "call_1", "lookup", `{"id":"a1"}`),
	)
	if err := state.Adapter.IngestResponse(state, response, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompletedExecution(state); err != nil {
		t.Fatal(err)
	}
	converted, err := BridgedResponse(state, response)
	if err != nil {
		t.Fatal(err)
	}
	if state.Response != response || converted.ResponsesResponse != nil || converted.ChatResponse == nil {
		t.Fatalf("the state lost the provider's reply, or the client got %#v", converted)
	}
	reply := converted.ChatResponse
	if reply.ID != "resp_bridge" || reply.Object != "chat.completion" || reply.Usage == nil || reply.Usage.PromptTokens != 20 ||
		reply.Usage.CompletionTokens != 15 || reply.Usage.CompletionTokensDetails == nil || reply.Usage.CompletionTokensDetails.ReasoningTokens != 4 {
		t.Fatalf("reply = %+v", reply)
	}
	choice := reply.Choices[0]
	message, err := json.Marshal(choice.ChatNonStreamResponseChoice.Message)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"role":"assistant","content":"Looking it up.","refusal":null,"reasoning_details":[{"id":"rs_1","index":0,"type":"reasoning.encrypted","data":"openai:acct-test:opaque"}],` +
		`"tool_calls":[{"index":0,"type":"function","id":"call_1","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]}`
	if *choice.FinishReason != "tool_calls" || string(message) != want {
		t.Fatalf("finish reason %s, message =\n%s\nwant\n%s", *choice.FinishReason, message, want)
	}

	// The client sends the reply back unchanged as history, with the tool's output in text parts, and
	// the provider gets its items again.
	next := chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Find a1."},`+string(message)+`,`+
		`{"role":"tool","tool_call_id":"call_1","content":[{"type":"text","text":"a1 is "},{"type":"text","text":"42"}]}],`+chatBridgeTools+`}`)
	input := string(chatBridgeProviderBody(t, next)["input"])
	if !strings.Contains(input, `{"id":"rs_1","type":"reasoning","summary":[],"encrypted_content":"opaque"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Looking it up.","annotations":[],"logprobs":[]}]},{"arguments":"{\"id\":\"a1\"}","type":"function_call","call_id":"call_1","name":"lookup"},{"type":"function_call_output","call_id":"call_1","output":"a1 is 42"}`) {
		t.Fatalf("input = %s", input)
	}
}

// OpenAI takes a prompt cache breakpoint on the assistant's text too.
func TestChatBridgeKeepsAssistantCacheBreakpoints(t *testing.T) {
	state := chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Say hi."},`+
		`{"role":"assistant","content":[{"type":"text","text":"Hi.","prompt_cache_breakpoint":{"mode":"explicit"}}]},{"role":"user","content":"Again."}]}`)
	input := string(chatBridgeProviderBody(t, state)["input"])
	if !strings.Contains(input, `{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi.","annotations":[],"logprobs":[],"prompt_cache_breakpoint":{"mode":"explicit"}}]}`) {
		t.Fatalf("input = %s", input)
	}
}

func TestChatBridgeRefusesBadReplies(t *testing.T) {
	body := `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Find a1."}],` + chatBridgeTools + `}`
	for _, test := range []struct {
		name     string
		response *schemas.BifrostResponse
	}{
		{"a Chat Completions reply", &schemas.BifrostResponse{ChatResponse: validUnaryChatProviderResponse()}},
		{"a call to an undeclared tool", chatBridgeReply(functionCallItem("fc_1", "call_1", "missing", `{}`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := chatBridgeState(t, body)
			if err := state.Adapter.IngestResponse(state, test.response, nil); !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// chatBridgeStream feeds a Responses stream, as OpenAI sends it, to a Chat Completions request's
// state and converter, as the HTTP stream does.
type chatBridgeStream struct {
	t        *testing.T
	state    *State
	stream   *BridgedStream
	sequence int
	output   []schemas.ResponsesMessage
	chunks   []*schemas.BifrostChatResponse
}

func newChatBridgeStream(t *testing.T, body string) *chatBridgeStream {
	t.Helper()
	state := chatBridgeState(t, body)
	stream := NewBridgedStream(state)
	if stream == nil {
		t.Fatal("no converter for a bridged stream")
	}
	s := &chatBridgeStream{t: t, state: state, stream: stream}
	for _, eventType := range []schemas.ResponsesStreamResponseType{schemas.ResponsesStreamResponseTypeCreated, schemas.ResponsesStreamResponseTypeInProgress} {
		event := validResponsesProviderEvent(eventType, 0, "resp_stream")
		event.Response.CreatedAt = 1_700_000_000
		s.send(event)
	}
	return s
}

func (s *chatBridgeStream) send(event *schemas.BifrostResponsesStreamResponse) {
	s.t.Helper()
	event.SequenceNumber = s.sequence
	s.sequence++
	chunk := &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}
	if err := s.state.Adapter.IngestChunk(s.state, chunk); err != nil {
		s.t.Fatalf("%s: %v", event.Type, err)
	}
	converted, err := s.stream.Convert(chunk)
	if err != nil {
		s.t.Fatalf("%s: %v", event.Type, err)
	}
	for _, chunk := range converted {
		s.chunks = append(s.chunks, chunk.BifrostChatResponse)
	}
}

func (s *chatBridgeStream) item(added, done schemas.ResponsesMessage, events func(output int, id *string)) {
	output := len(s.output)
	s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: &output, Item: &added})
	if events != nil {
		events(output, added.ID)
	}
	s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &output, Item: &done})
	s.output = append(s.output, done)
}

func (s *chatBridgeStream) reasoning(id, data string) {
	added := encryptedReasoningItem(id, data)
	added.ResponsesReasoning.EncryptedContent = nil
	s.item(added, encryptedReasoningItem(id, data), nil)
}

func (s *chatBridgeStream) text(id string, deltas ...string) {
	added := textItem(id, "")
	added.Status = schemas.Ptr("in_progress")
	added.Content.ContentBlocks = []schemas.ResponsesMessageContentBlock{}
	text := strings.Join(deltas, "")
	s.item(added, textItem(id, text), func(output int, id *string) {
		content := 0
		part := func(text string) *schemas.ResponsesMessageContentBlock {
			return &schemas.ResponsesMessageContentBlock{
				Type: schemas.ResponsesOutputMessageContentTypeText, Text: schemas.Ptr(text),
				ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{}},
			}
		}
		s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeContentPartAdded, OutputIndex: &output, ContentIndex: &content, ItemID: id, Part: part("")})
		for _, delta := range deltas {
			s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDelta, OutputIndex: &output, ContentIndex: &content, ItemID: id, Delta: schemas.Ptr(delta)})
		}
		s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDone, OutputIndex: &output, ContentIndex: &content, ItemID: id, Text: schemas.Ptr(text)})
		s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeContentPartDone, OutputIndex: &output, ContentIndex: &content, ItemID: id, Part: part(text)})
	})
}

func (s *chatBridgeStream) call(id, callID, name string, fragments ...string) {
	added := functionCallItem(id, callID, name, "")
	added.Status = schemas.Ptr("in_progress")
	arguments := strings.Join(fragments, "")
	s.item(added, functionCallItem(id, callID, name, arguments), func(output int, id *string) {
		for _, fragment := range fragments {
			s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta, OutputIndex: &output, ItemID: id, Delta: schemas.Ptr(fragment)})
		}
		s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone, OutputIndex: &output, ItemID: id, Arguments: schemas.Ptr(arguments)})
	})
}

func (s *chatBridgeStream) end(eventType schemas.ResponsesStreamResponseType) {
	terminal := validResponsesProviderEvent(eventType, 0, "resp_stream")
	terminal.Response.CreatedAt = 1_700_000_000
	terminal.Response.Output = s.output
	terminal.Response.Usage = chatBridgeReply().ResponsesResponse.Usage
	s.send(terminal)
}

// deltas describes the chunks that the client got, one line each.
func (s *chatBridgeStream) deltas() string {
	lines := make([]string, len(s.chunks))
	for i, chunk := range s.chunks {
		if len(chunk.Choices) == 0 {
			lines[i] = "usage"
			continue
		}
		choice := chunk.Choices[0]
		encoded, err := json.Marshal(choice.ChatStreamResponseChoice.Delta)
		if err != nil {
			s.t.Fatal(err)
		}
		lines[i] = string(encoded)
		if choice.FinishReason != nil {
			lines[i] += " " + *choice.FinishReason
		}
	}
	return strings.Join(lines, "\n")
}

func TestChatBridgeStreamBecomesChatChunks(t *testing.T) {
	s := newChatBridgeStream(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Find a1."}],"stream":true,`+chatBridgeTools+`}`)
	s.reasoning("rs_1", "opaque")
	s.text("msg_1", "Looking", " it up.")
	s.call("fc_1", "call_1", "lookup", `{"id":`, `"a1"}`)
	if ProviderStreamTerminal(s.state) {
		t.Fatal("the stream ended before its terminal event")
	}
	s.end(schemas.ResponsesStreamResponseTypeCompleted)
	if !ProviderStreamTerminal(s.state) {
		t.Fatal("the stream did not end with its terminal event")
	}
	// Chunks that carry nothing stay out, and the usage follows the finish reason in its own chunk.
	want := strings.Join([]string{
		`{"role":"assistant"}`,
		`{"reasoning_details":[{"id":"rs_1","index":0,"type":"reasoning.encrypted","data":"openai:acct-test:opaque"}]}`,
		`{"content":"Looking"}`,
		`{"content":" it up."}`,
		`{"tool_calls":[{"index":0,"type":"function","id":"call_1","function":{"name":"lookup","arguments":""}}]}`,
		`{"tool_calls":[{"index":0,"function":{"arguments":"{\"id\":"}}]}`,
		`{"tool_calls":[{"index":0,"function":{"arguments":"\"a1\"}"}}]}`,
		`{} tool_calls`,
		`usage`,
	}, "\n")
	if got := s.deltas(); got != want {
		t.Fatalf("chunks =\n%s\nwant\n%s", got, want)
	}
	for _, chunk := range s.chunks {
		if chunk.ID != "resp_stream" || chunk.Object != "chat.completion.chunk" || chunk.Created != 1_700_000_000 {
			t.Fatalf("chunk = %+v", chunk)
		}
	}
	if usage := s.chunks[len(s.chunks)-1].Usage; usage == nil || usage.PromptTokens != 20 || usage.CompletionTokens != 15 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestChatBridgeStreamCutShortEndsForLength(t *testing.T) {
	s := newChatBridgeStream(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Count."}],"max_completion_tokens":16,"stream":true}`)
	s.text("msg_1", "One, two")
	s.end(schemas.ResponsesStreamResponseTypeIncomplete)
	want := `{"role":"assistant"}` + "\n" + `{"content":"One, two"}` + "\n" + `{} length` + "\nusage"
	if got := s.deltas(); got != want {
		t.Fatalf("chunks =\n%s\nwant\n%s", got, want)
	}
}

func TestChatBridgeRefusesChatStreams(t *testing.T) {
	state := chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostChatResponse: validChatProviderChunk("chatcmpl_1", false),
	}); !errors.Is(err, ErrProviderResponseMalformed) {
		t.Fatalf("streamed Chat Completions reply error = %v", err)
	}
}
