package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// customerState resolves and checks a request that a customer's own OpenAI credential serves.
func customerState(t *testing.T, route, fields string) (*State, error) {
	t.Helper()
	return customerRequestState(t, route, []byte(`{"model":"provider:openai gpt-5.5",`+fields+`}`))
}

// customerRequestState resolves and checks a request body that a customer's own credential serves.
func customerRequestState(t *testing.T, route string, body []byte) (*State, error) {
	t.Helper()
	_, customer := customerOpenAICredential(t)
	resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + route, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
	state.PreparedCredential = customer
	return state, state.Adapter.ValidateRequest(state)
}

// A customer's own OpenAI account gets the store value that the request asks for, and the
// request's metadata only when it stores, which the metadata then labels. A request that
// continues a stored reply stores its own unless it says not to, as OpenAI's default does, and
// nothing else stays at the provider.
func TestCustomerRequestBodyKeepsProviderState(t *testing.T) {
	for _, tc := range []struct {
		name, route, fields string
		store, metadata     bool
		continues           string
	}{
		{name: "a stored completion", route: "chat/completions", fields: `"messages":[{"role":"user","content":"hi"}],"store":true,"metadata":{"team":"evals"}`, store: true, metadata: true},
		{name: "a completion", route: "chat/completions", fields: `"messages":[{"role":"user","content":"hi"}],"metadata":{"team":"evals"}`},
		{name: "a stored reply", route: "responses", fields: `"input":"hi","store":true,"metadata":{"team":"evals"}`, store: true, metadata: true},
		{name: "a reply", route: "responses", fields: `"input":"hi","metadata":{"team":"evals"}`},
		{name: "a continued reply", route: "responses", fields: `"input":"hi","previous_response_id":"resp_1"`, store: true, continues: `"previous_response_id":"resp_1"`},
		{name: "a continued reply that stores nothing", route: "responses", fields: `"input":"hi","previous_response_id":"resp_1","store":false,"metadata":{"team":"evals"}`,
			continues: `"previous_response_id":"resp_1"`},
		{name: "a conversation", route: "responses", fields: `"input":"hi","conversation":{"id":"conv_1"}`, store: true, continues: `"conversation":{"id":"conv_1"}`},
		{name: "a conversation by ID", route: "responses", fields: `"input":"hi","conversation":"conv_1"`, store: true, continues: `"conversation":"conv_1"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, err := customerState(t, tc.route, tc.fields)
			if err != nil {
				t.Fatal(err)
			}
			resolved := state.Resolution
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatal(err)
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
			var body []byte
			if request.ChatRequest != nil {
				body = preparedProviderBody(t, ctx, request.ChatRequest)
			} else {
				body = preparedProviderBody(t, ctx, request.ResponsesRequest)
			}
			var wire struct {
				Store    *bool             `json:"store"`
				Metadata map[string]string `json:"metadata"`
			}
			if err := json.Unmarshal(body, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.Store == nil || *wire.Store != tc.store || (wire.Metadata["team"] == "evals") != tc.metadata {
				t.Fatalf("store %v and metadata %v, want %t and %t: %s", wire.Store, wire.Metadata, tc.store, tc.metadata, body)
			}
			if tc.continues != "" && !strings.Contains(string(body), tc.continues) {
				t.Fatalf("provider lost %s: %s", tc.continues, body)
			}
			// The request log names the fields, never their IDs.
			if logged := state.RequestSettings.ProviderState; !slices.Equal(logged, resolved.ProviderState().Fields) || tc.store != slices.Contains(logged, "store") {
				t.Fatalf("request settings name %v", logged)
			}
		})
	}
}

// A request that continues what the provider holds answers calls that only the provider has, and
// the provider matches them. Calls in the input still need their own outputs.
func TestContinuedResponsesAnswerCallsThatTheProviderHolds(t *testing.T) {
	const (
		output   = `{"type":"function_call_output","call_id":"call_1","output":"42"}`
		approval = `{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true}`
	)
	for _, tc := range []struct{ name, fields, want string }{
		{"a tool result", `"previous_response_id":"resp_1","tools":[{"type":"function","name":"lookup"}],"input":[` + output + `]`, ""},
		{"a tool result in a conversation", `"conversation":"conv_1","tools":[{"type":"function","name":"lookup"}],"input":[` + output + `]`, ""},
		{"an approval", `"previous_response_id":"resp_1","tools":[` + mcpServerTool + `],"input":[` + approval + `]`, ""},
		{"a screenshot", `"previous_response_id":"resp_1","tools":[{"type":"computer"}],"input":[{"type":"computer_call_output","call_id":"call_1",` +
			`"output":{"type":"computer_screenshot","image_url":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}}]`, ""},
		{"a screenshot for a function call", `"previous_response_id":"resp_1","tools":[{"type":"function","name":"lookup"},{"type":"computer"}],"input":[` +
			`{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"computer_call_output","call_id":"call_1",` +
			`"output":{"type":"computer_screenshot","image_url":"https://example.com/screen.png"}}]`, "selects a different client tool type"},
		{"a stateless tool result", `"tools":[{"type":"function","name":"lookup"}],"input":[` + output + `]`, "must match an earlier client tool call"},
		{"a stateless approval", `"tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},` + approval + `]`, "must answer an mcp_approval_request in the same input"},
		{"a result of another kind", `"previous_response_id":"resp_1","tools":[{"type":"function","name":"lookup"},{"type":"custom","name":"edit"}],"input":[` +
			`{"type":"custom_tool_call","call_id":"call_1","name":"edit","input":"x"},` + output + `]`, "selects a different client tool type"},
		{"a call without its result", `"previous_response_id":"resp_1","tools":[{"type":"function","name":"lookup"}],"input":[` +
			`{"type":"function_call","call_id":"call_2","name":"lookup","arguments":"{}"},` + output + `]`, "require one matching output"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := customerState(t, "responses", tc.fields)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// A reply keeps only the provider state that its request asked for, which the gateway echoes from
// the request.
func TestProviderResponsesEchoOnlyTheRequestedProviderState(t *testing.T) {
	stored := func(response *schemas.BifrostResponsesResponse) { response.Store = schemas.Ptr(true) }
	continued := func(response *schemas.BifrostResponsesResponse) { response.PreviousResponseID = schemas.Ptr("resp_1") }
	conversation := func(response *schemas.BifrostResponsesResponse) {
		response.Conversation = &schemas.ResponsesResponseConversation{
			ResponsesResponseConversationStruct: &schemas.ResponsesResponseConversationStruct{ID: "conv_1"},
		}
	}
	for _, tc := range []struct {
		name, fields string
		reply        func(*schemas.BifrostResponsesResponse)
		valid        bool
	}{
		{"a stored reply", `"store":true`, stored, true},
		{"a continued reply", `"previous_response_id":"resp_1"`, continued, true},
		{"a conversation", `"conversation":"conv_1"`, conversation, true},
		{"a reply stored unasked", ``, stored, false},
		{"a continuation unasked", `"store":true`, continued, false},
		{"a conversation unasked", `"previous_response_id":"resp_1"`, conversation, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, err := customerState(t, "responses", strings.TrimSuffix(`"input":"hi",`+tc.fields, ","))
			if err != nil {
				t.Fatal(err)
			}
			response := validUnaryResponsesProviderResponse("resp_2")
			tc.reply(response)
			err = validateProviderResponsesResponse(state, response)
			if !tc.valid {
				if !errors.Is(err, ErrProviderResponseMalformed) {
					t.Fatalf("error = %v, want malformed provider response", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			asked := state.Resolution.ProviderState()
			if response.Store == nil || *response.Store != asked.Store {
				t.Fatalf("store = %v, want %t", response.Store, asked.Store)
			}
			echo, _ := json.Marshal(response)
			if !strings.Contains(string(echo), strings.ReplaceAll(tc.fields, `"conversation":"conv_1"`, `"conversation":{"id":"conv_1"}`)) {
				t.Fatalf("reply does not echo %s: %s", tc.fields, echo)
			}
		})
	}
}

// The replies that OpenAI and Azure gave to requests that keep or continue a stored response pass
// the checks of the same requests through the gateway, which echo what each asked for (capture
// openai/stored-responses).
func TestRecordedStoredResponsesPassTheReplyChecks(t *testing.T) {
	exchanges := providerCapture(t, "openai/stored-responses")
	for name, model := range map[string]string{
		"openai stored reply": "provider:openai gpt-5.5", "openai continued reply": "provider:openai gpt-5.5",
		"azure stored reply": "azure-gpt-5.6-sol", "azure continued reply": "azure-gpt-5.6-sol",
		"conversation turn": "provider:openai gpt-5.5",
	} {
		t.Run(name, func(t *testing.T) {
			recorded := exchange(t, exchanges, name)
			var body map[string]json.RawMessage
			if err := json.Unmarshal(recorded.Request.Body, &body); err != nil {
				t.Fatal(err)
			}
			body["model"], _ = json.Marshal(model)
			request, _ := json.Marshal(body)
			state, err := customerRequestState(t, "responses", request)
			if err != nil {
				t.Fatal(err)
			}
			reply := recorded.responsesReply(t)
			provided := *reply
			if err := validateProviderResponsesResponse(state, reply); err != nil {
				t.Fatal(err)
			}
			if reply.Store == nil || !*reply.Store || !state.Resolution.ProviderState().Store {
				t.Fatalf("store = %v for a request that stores", reply.Store)
			}
			if (provided.PreviousResponseID == nil) != (reply.PreviousResponseID == nil) ||
				reply.PreviousResponseID != nil && *reply.PreviousResponseID != *provided.PreviousResponseID {
				t.Fatalf("previous_response_id = %v, provider gave %v", reply.PreviousResponseID, provided.PreviousResponseID)
			}
			if provided.Conversation != nil && (reply.Conversation == nil || reply.Conversation.ResponsesResponseConversationStruct == nil ||
				reply.Conversation.ResponsesResponseConversationStruct.ID != provided.Conversation.ResponsesResponseConversationStruct.ID) {
				t.Fatalf("conversation = %+v, provider gave %+v", reply.Conversation, provided.Conversation)
			}
		})
	}
}
