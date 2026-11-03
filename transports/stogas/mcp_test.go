package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const mcpServerTool = `{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com/sse","authorization":"token-must-stay-private","headers":{"X-Api-Key":"header-must-stay-private"}}`

func TestResponsesPolicyAcceptsOpenAIRemoteMCP(t *testing.T) {
	for _, body := range []string{
		`{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `]}`,
		`{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"calendar","connector_id":"connector_googlecalendar","authorization":"oauth","require_approval":"never"}],"max_tool_calls":3}`,
		`{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"tunnel","tunnel_id":"tun_1","server_description":"Internal docs","allowed_tools":["search","fetch"],"require_approval":"always"}]}`,
		`{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","allowed_tools":{"tool_names":["search"],"read_only":true},"require_approval":{"never":{"tool_names":["search"]},"always":{"read_only":false}},"allowed_callers":["direct"],"defer_loading":false}]}`,
		`{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,{"type":"mcp","server_label":"docs","server_url":"https://docs.example.com/mcp"},{"type":"function","name":"search"}],"tool_choice":{"type":"mcp","server_label":"docs","name":"lookup"}}`,
		`{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,{"type":"web_search"}],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"mcp","server_label":"wiki"},{"type":"web_search"}]}}`,
		// A stateless continuation replays the listing and the approval request, then answers it.
		`{"model":"openai/gpt-5.5","tools":[` + mcpServerTool + `],"input":[
			{"role":"user","content":"Look it up"},
			{"type":"mcp_list_tools","id":"mcpl_1","server_label":"wiki","tools":[{"name":"ask","input_schema":{"type":"object"},"description":"Ask the wiki"}]},
			{"type":"mcp_approval_request","id":"mcpr_1","server_label":"wiki","name":"ask","arguments":"{\"q\":\"x\"}"},
			{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true,"reason":"fine"}]}`,
		`{"model":"openai/gpt-5.5","tools":[` + mcpServerTool + `],"input":[
			{"role":"user","content":"Look it up"},
			{"type":"mcp_call","id":"mcp_1","server_label":"wiki","name":"ask","arguments":"{}","output":"answer","error":null,"status":"completed","approval_request_id":"mcpr_1"},
			{"type":"mcp_call","id":"mcp_2","server_label":"wiki","name":"ask","arguments":"","error":{"type":"http_error","code":500,"message":"down"},"status":"failed"},
			{"role":"user","content":"Thanks"}]}`,
		// MCP items can sit between a client call and its output, as a response returns them.
		`{"model":"openai/gpt-5.5","tools":[` + mcpServerTool + `,{"type":"function","name":"lookup"}],"input":[
			{"role":"user","content":"Both"},
			{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},
			{"type":"mcp_approval_request","id":"mcpr_1","server_label":"wiki","name":"ask","arguments":"{}"},
			{"type":"function_call_output","call_id":"call_1","output":"done"},
			{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":false}]}`,
	} {
		if err := validateResolvedResponses(t, body); err != nil {
			t.Fatalf("expected the MCP request to pass: %v\nbody=%s", err, body)
		}
	}
}

func TestResponsesPolicyRefusesUnsupportedRemoteMCP(t *testing.T) {
	for _, item := range []struct{ name, body, want string }{
		{"missing label", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_url":"https://mcp.example.com"}]}`, "server_label must name the server"},
		{"padded label", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":" wiki","server_url":"https://mcp.example.com"}]}`, "server_label must name the server"},
		{"duplicate label", `{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,` + mcpServerTool + `]}`, "duplicates another MCP server"},
		{"unknown key", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","future":true}]}`, "tools[0].future is not supported"},
		{"header values", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","headers":{"X":1}}]}`, "Invalid JSON body"},
		{"approval setting", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"sometimes"}]}`, "require_approval must be always, never"},
		{"approval filter key", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":{"maybe":{}}}]}`, "require_approval.maybe is not supported"},
		{"approval list", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":{"never":["search"]}}]}`, "Invalid JSON body"},
		// The forwarded filter would leave an empty tool_names out and so cover every tool.
		{"empty allowed filter", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","allowed_tools":{"tool_names":[]}}]}`, "allowed_tools.tool_names must name at least one tool"},
		{"empty never filter", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":{"never":{"tool_names":[],"read_only":true}}}]}`, "require_approval.never.tool_names must name at least one tool"},
		{"programmatic callers", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","allowed_callers":["programmatic"]}]}`, "programmatic calls need code execution"},
		{"deferred loading", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","defer_loading":true}]}`, "defer_loading needs tool_search"},
		{"undeclared server choice", `{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `],"tool_choice":{"type":"mcp","server_label":"docs"}}`, "selects an undeclared MCP server"},
		{"undeclared allowed server", `{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"mcp","server_label":"docs"}]}}`, "selects an undeclared MCP server"},
		{"approval without decision", `{"model":"openai/gpt-5.5","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},{"type":"mcp_approval_response","approval_request_id":"mcpr_1"}]}`, "approve must be a boolean"},
		{"listing without tools", `{"model":"openai/gpt-5.5","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},{"type":"mcp_list_tools","id":"mcpl_1","server_label":"wiki"}]}`, "tools must list the server's tools"},
		{"call without name", `{"model":"openai/gpt-5.5","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},{"type":"mcp_call","id":"mcp_1","server_label":"wiki","arguments":"{}"}]}`, "name is required"},
		{"azure", `{"model":"azure/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `]}`, "supported only for OpenAI deployments"},
		{"anthropic", `{"model":"anthropic-claude-sonnet-4-6","input":"hi","tools":[` + mcpServerTool + `]}`, "provider execution cannot be bounded or approved"},
		{"anthropic replayed item", `{"model":"anthropic-claude-sonnet-4-6","input":[{"role":"user","content":"hi"},{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true}]}`, "supported only for OpenAI deployments"},
	} {
		t.Run(item.name, func(t *testing.T) {
			err := validateResolvedResponses(t, item.body)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("error = %v, want %q", err, item.want)
			}
		})
	}
}

// heldInputTokens sums the input tokens of every hold meter, at any rate.
func heldInputTokens(t *testing.T, body string) (int64, *State) {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
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
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatal(err)
	}
	total := new(big.Int)
	for _, meter := range state.Hold.Meters {
		if meter.MeterKey != billing.MeterInputTokens {
			continue
		}
		quantity, ok := new(big.Int).SetString(meter.Quantity, 10)
		if !ok {
			t.Fatalf("bad quantity %q", meter.Quantity)
		}
		total.Add(total, quantity)
	}
	return total.Int64(), state
}

func TestRemoteMCPHoldsEveryModelPassThatCallsCanAdd(t *testing.T) {
	plain, plainState := heldInputTokens(t, `{"model":"openai/gpt-5.5","input":"hi"}`)
	limit := int64(plainState.Resolution.Deployment.MaxInputTokens)
	if limit <= 0 || plain <= 0 || plain >= limit {
		t.Fatalf("unexpected base hold %d for input limit %d", plain, limit)
	}
	approval := func(approve bool) string {
		if approve {
			return `{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true}`
		}
		return `{"type":"mcp_approval_response","approval_request_id":"mcpr_2","approve":false}`
	}
	for _, item := range []struct {
		name   string
		body   string
		passes int64
	}{
		// A listing can fill the first pass, so the hold covers that pass at the input limit.
		{"approval required", `{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `]}`, 1},
		{"one approved call", `{"model":"openai/gpt-5.5","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},` + approval(true) + `,` + approval(false) + `]}`, 2},
		{"calls without approval up to the default", `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"never"}]}`, 1 + defaultResponsesHostedToolCalls},
		{"calls without approval up to the cap", `{"model":"openai/gpt-5.5","input":"hi","max_tool_calls":3,"tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":{"never":{"read_only":true}}}]}`, 4},
	} {
		t.Run(item.name, func(t *testing.T) {
			held, _ := heldInputTokens(t, item.body)
			if want := item.passes * limit; held != want {
				t.Fatalf("held input = %d, want %d passes of %d", held, item.passes, limit)
			}
		})
	}
	// Without a callable MCP server, nothing more is held.
	for _, body := range []string{
		`{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `],"tool_choice":"none"}`,
		`{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`,
	} {
		if held, _ := heldInputTokens(t, body); held >= limit {
			t.Fatalf("held input %d reaches the input limit for a request that allows no MCP call\n%s", held, body)
		}
	}
}

func TestRemoteMCPCallsWithoutApprovalGetTheDefaultCap(t *testing.T) {
	for body, want := range map[string]*int{
		`{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `]}`:                                                                                  schemas.Ptr(defaultResponsesHostedToolCap),
		`{"model":"openai/gpt-5.5","input":"hi","max_tool_calls":2,"tools":[` + mcpServerTool + `]}`:                                                               schemas.Ptr(2),
		`{"model":"openai/gpt-5.5","input":"hi","tool_choice":"none","tools":[` + mcpServerTool + `]}`:                                                             nil,
		`{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"never"}]}`: schemas.Ptr(defaultResponsesHostedToolCap),
	} {
		resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
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
		request, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
		if err != nil {
			t.Fatal(err)
		}
		got := request.ResponsesRequest.Params.MaxToolCalls
		if (got == nil) != (want == nil) || got != nil && *got != *want {
			t.Fatalf("max_tool_calls = %v, want %v\n%s", got, want, body)
		}
		// The provider receives the server's credentials as the client sent them.
		tools := request.ResponsesRequest.Params.Tools
		if len(tools) != 1 || tools[0].ResponsesToolMCP == nil || tools[0].ResponsesToolMCP.ServerLabel != "wiki" {
			t.Fatalf("provider tools = %#v", tools)
		}
	}
}

// OpenAI receives each MCP tool as the client sent it, so no allowlist or approval setting
// widens on the way.
func TestRemoteMCPToolsReachOpenAIAsSent(t *testing.T) {
	for _, tool := range []string{
		`{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","allowed_tools":[],"require_approval":"never"}`,
		`{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","allowed_tools":["search"],"require_approval":"always","headers":{},"authorization":""}`,
		`{"type":"mcp","server_label":"wiki","connector_id":"connector_dropbox","allowed_tools":{"read_only":false},"require_approval":{"never":{"read_only":true},"always":{"tool_names":["delete"]}}}`,
		`{"type":"mcp","server_label":"wiki","tunnel_id":"tun_1","server_description":"Docs","allowed_tools":{"tool_names":["search"],"read_only":true},"require_approval":{"always":{}},"allowed_callers":["direct"]}`,
	} {
		body := `{"model":"openai/gpt-5.5","input":"hi","tools":[` + tool + `]}`
		resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
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
		request, err := resolution.ToBifrost(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wire, bifrostErr := prepareOpenAIResponsesBody(ctx, request.ResponsesRequest, false)
		if bifrostErr != nil {
			t.Fatal(bifrostErr.Error)
		}
		var sent struct {
			Tools []any `json:"tools"`
		}
		var want any
		if err := json.Unmarshal(wire, &sent); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(tool), &want); err != nil {
			t.Fatal(err)
		}
		if len(sent.Tools) != 1 || !reflect.DeepEqual(sent.Tools[0], want) {
			t.Fatalf("OpenAI receives %v, want %s", sent.Tools, tool)
		}
	}
}

func mcpOutputItem(itemType schemas.ResponsesMessageType, id, label string, tool schemas.ResponsesToolMessage) schemas.ResponsesMessage {
	tool.ServerLabel = schemas.Ptr(label)
	return schemas.ResponsesMessage{ID: schemas.Ptr(id), Type: schemas.Ptr(itemType), ResponsesToolMessage: &tool}
}

func mcpListing(id, label string) schemas.ResponsesMessage {
	return mcpOutputItem(schemas.ResponsesMessageTypeMCPListTools, id, label, schemas.ResponsesToolMessage{
		ResponsesMCPListTools: &schemas.ResponsesMCPListTools{Tools: []schemas.ResponsesMCPTool{
			{Name: "ask", InputSchema: map[string]any{"type": "object"}, Description: schemas.Ptr("Ask the wiki")},
		}},
	})
}

func mcpCall(id, label string) schemas.ResponsesMessage {
	item := mcpOutputItem(schemas.ResponsesMessageTypeMCPCall, id, label, schemas.ResponsesToolMessage{
		Name: schemas.Ptr("ask"), Arguments: schemas.Ptr(`{"q":"x"}`),
		Output: &schemas.ResponsesToolMessageOutputStruct{ResponsesToolCallOutputStr: schemas.Ptr("answer")},
	})
	item.Status = schemas.Ptr("completed")
	return item
}

func mcpApprovalRequest(id, label string) schemas.ResponsesMessage {
	return mcpOutputItem(schemas.ResponsesMessageTypeMCPApprovalRequest, id, label, schemas.ResponsesToolMessage{
		Name: schemas.Ptr("ask"), Arguments: schemas.Ptr(`{"q":"x"}`),
	})
}

func TestProviderResponsesAcceptRemoteMCPItemsFromDeclaredServers(t *testing.T) {
	approvalRequest := `{"model":"openai/gpt-5.5","input":"hi","tool_choice":"required","tools":[` + mcpServerTool + `]}`
	state := resolvedResponseValidationState(t, approvalRequest)
	response := validUnaryResponsesProviderResponse("resp_mcp_approval")
	response.Output = []schemas.ResponsesMessage{mcpListing("mcpl_1", "wiki"), mcpApprovalRequest("mcpr_1", "wiki")}
	if err := validateProviderResponsesResponse(state, response); err != nil {
		t.Fatalf("listing and approval request rejected: %v", err)
	}
	// The approval request satisfies a required tool_choice, but no call ran.
	if state.responsesHostedCalls != 0 || state.responsesDeclaredCalls != 1 {
		t.Fatalf("hosted calls %d, declared calls %d", state.responsesHostedCalls, state.responsesDeclaredCalls)
	}
	// The echo of the request never repeats the server's credentials.
	if len(response.Tools) != 1 || response.Tools[0].ResponsesToolMCP == nil ||
		response.Tools[0].ResponsesToolMCP.Authorization != nil || response.Tools[0].ResponsesToolMCP.Headers != nil ||
		response.Tools[0].ResponsesToolMCP.ServerURL == nil {
		t.Fatalf("echoed tools = %#v", response.Tools)
	}

	unattended := `{"model":"openai/gpt-5.5","input":"hi","max_tool_calls":2,"tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"never"}]}`
	state = resolvedResponseValidationState(t, unattended)
	response = validUnaryResponsesProviderResponse("resp_mcp_calls")
	failed := mcpCall("mcp_2", "wiki")
	failed.Status = schemas.Ptr("failed")
	failed.ResponsesToolMessage.Output = nil
	failed.ResponsesToolMessage.Error = &schemas.ResponsesToolMessageError{ResponsesToolMessageErrorStruct: &schemas.ResponsesToolMessageErrorStruct{
		Type: "mcp_protocol_error", Code: schemas.Ptr(-32600), Message: schemas.Ptr("bad request"),
	}}
	response.Output = []schemas.ResponsesMessage{mcpListing("mcpl_1", "wiki"), mcpCall("mcp_1", "wiki"), failed}
	if err := validateProviderResponsesResponse(state, response); err != nil {
		t.Fatalf("calls within the cap rejected: %v", err)
	}
	if state.responsesHostedCalls != 2 {
		t.Fatalf("hosted calls = %d, want 2", state.responsesHostedCalls)
	}

	changed := func(item schemas.ResponsesMessage, change func(*schemas.ResponsesMessage)) []schemas.ResponsesMessage {
		change(&item)
		return []schemas.ResponsesMessage{item}
	}
	for name, item := range map[string]struct {
		request string
		output  []schemas.ResponsesMessage
	}{
		"undeclared server":   {unattended, []schemas.ResponsesMessage{mcpCall("mcp_1", "docs")}},
		"server not chosen":   {`{"model":"openai/gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,{"type":"mcp","server_label":"docs","server_url":"https://docs.example.com"}],"tool_choice":{"type":"mcp","server_label":"docs"}}`, []schemas.ResponsesMessage{mcpCall("mcp_1", "wiki")}},
		"no MCP tool":         {`{"model":"openai/gpt-5.5","input":"hi"}`, []schemas.ResponsesMessage{mcpListing("mcpl_1", "wiki")}},
		"calls above the cap": {unattended, []schemas.ResponsesMessage{mcpCall("mcp_1", "wiki"), mcpCall("mcp_2", "wiki"), mcpCall("mcp_3", "wiki")}},
		"call still running":  {unattended, changed(mcpCall("mcp_1", "wiki"), func(call *schemas.ResponsesMessage) { call.Status = schemas.Ptr("calling") })},
		"call without name":   {unattended, changed(mcpCall("mcp_1", "wiki"), func(call *schemas.ResponsesMessage) { call.ResponsesToolMessage.Name = nil })},
		"array arguments":     {unattended, changed(mcpCall("mcp_1", "wiki"), func(call *schemas.ResponsesMessage) { call.ResponsesToolMessage.Arguments = schemas.Ptr("[]") })},
		"approval with output": {approvalRequest, changed(mcpApprovalRequest("mcpr_1", "wiki"), func(request *schemas.ResponsesMessage) {
			request.ResponsesToolMessage.Output = &schemas.ResponsesToolMessageOutputStruct{ResponsesToolCallOutputStr: schemas.Ptr("x")}
		})},
		"listing with a call id": {unattended, changed(mcpListing("mcpl_1", "wiki"), func(listing *schemas.ResponsesMessage) { listing.ResponsesToolMessage.CallID = schemas.Ptr("call_1") })},
	} {
		t.Run(name, func(t *testing.T) {
			response := validUnaryResponsesProviderResponse("resp_mcp_bad")
			response.Output = item.output
			if err := validateProviderResponsesResponse(resolvedResponseValidationState(t, item.request), response); !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v, want malformed provider response", err)
			}
		})
	}
}

func TestProviderResponsesStreamFollowsRemoteMCPLifecycles(t *testing.T) {
	request := `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"never"}]}`
	run := func(argumentFragments []string, doneArguments, finalArguments string, skipCallEvents bool) error {
		state := resolvedResponseValidationState(t, request)
		sequence := 0
		send := func(event *schemas.BifrostResponsesStreamResponse) error {
			event.SequenceNumber = sequence
			sequence++
			if err := validateProviderResponsesStream(state, event); err != nil {
				return fmt.Errorf("%s: %w", event.Type, err)
			}
			return nil
		}
		if err := send(validResponsesProviderEvent(schemas.ResponsesStreamResponseTypeCreated, 0, "resp_mcp_stream")); err != nil {
			return err
		}
		listIndex, callIndex := 0, 1
		listing := mcpListing("mcpl_1", "wiki")
		addedListing := listing
		addedListing.ResponsesToolMessage = &schemas.ResponsesToolMessage{ServerLabel: schemas.Ptr("wiki"), ResponsesMCPListTools: &schemas.ResponsesMCPListTools{Tools: []schemas.ResponsesMCPTool{}}}
		for _, event := range []*schemas.BifrostResponsesStreamResponse{
			{Type: schemas.ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: &listIndex, Item: &addedListing},
			{Type: schemas.ResponsesStreamResponseTypeMCPListToolsInProgress, OutputIndex: &listIndex, ItemID: itemIDPtr("mcpl_1")},
			{Type: schemas.ResponsesStreamResponseTypeMCPListToolsCompleted, OutputIndex: &listIndex, ItemID: itemIDPtr("mcpl_1")},
			{Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &listIndex, Item: &listing},
		} {
			if err := send(event); err != nil {
				return err
			}
		}
		call := mcpCall("mcp_1", "wiki")
		call.ResponsesToolMessage.Arguments = schemas.Ptr(finalArguments)
		added := mcpOutputItem(schemas.ResponsesMessageTypeMCPCall, "mcp_1", "wiki", schemas.ResponsesToolMessage{Name: schemas.Ptr("ask"), Arguments: schemas.Ptr("")})
		added.Status = schemas.Ptr("in_progress")
		if err := send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: &callIndex, Item: &added}); err != nil {
			return err
		}
		if !skipCallEvents {
			if err := send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeMCPCallInProgress, OutputIndex: &callIndex, ItemID: itemIDPtr("mcp_1")}); err != nil {
				return err
			}
			for _, fragment := range argumentFragments {
				if err := send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeMCPCallArgumentsDelta, OutputIndex: &callIndex, ItemID: itemIDPtr("mcp_1"), Delta: schemas.Ptr(fragment), Obfuscation: schemas.Ptr("pad")}); err != nil {
					return err
				}
			}
			if err := send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeMCPCallArgumentsDone, OutputIndex: &callIndex, ItemID: itemIDPtr("mcp_1"), Arguments: schemas.Ptr(doneArguments)}); err != nil {
				return err
			}
			if err := send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeMCPCallCompleted, OutputIndex: &callIndex, ItemID: itemIDPtr("mcp_1")}); err != nil {
				return err
			}
		}
		if err := send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &callIndex, Item: &call}); err != nil {
			return err
		}
		terminal := validResponsesProviderEvent(schemas.ResponsesStreamResponseTypeCompleted, sequence, "resp_mcp_stream")
		terminal.Response.Output = []schemas.ResponsesMessage{listing, call}
		if err := send(terminal); err != nil {
			return err
		}
		if state.responsesHostedCalls != 1 {
			return errors.New("the call was not counted once")
		}
		return nil
	}
	if err := run([]string{`{"q":`, `"x"}`}, `{"q":"x"}`, `{"q":"x"}`, false); err != nil {
		t.Fatalf("valid MCP stream rejected: %v", err)
	}
	// A call that ran after an approval can come without lifecycle or argument events.
	if err := run(nil, "", `{"q":"x"}`, true); err != nil {
		t.Fatalf("approved call without events rejected: %v", err)
	}
	for name, item := range map[string]struct {
		fragments   []string
		done, final string
	}{
		"done differs from the deltas":  {[]string{`{"q":"x"}`}, `{"q":"y"}`, `{"q":"y"}`},
		"final differs from the deltas": {[]string{`{"q":"x"}`}, `{"q":"x"}`, `{"q":"y"}`},
		"arguments are not an object":   {[]string{`[1]`}, `[1]`, `[1]`},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(item.fragments, item.done, item.final, false); !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v, want malformed provider response", err)
			}
		})
	}

	// Lifecycle events cannot repeat, and an MCP event needs an MCP item.
	state := resolvedResponseValidationState(t, request)
	index := 0
	listing := mcpListing("mcpl_1", "wiki")
	for position, event := range []*schemas.BifrostResponsesStreamResponse{
		validResponsesProviderEvent(schemas.ResponsesStreamResponseTypeCreated, 0, "resp_mcp_repeat"),
		{Type: schemas.ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: &index, Item: &listing},
		{Type: schemas.ResponsesStreamResponseTypeMCPListToolsInProgress, OutputIndex: &index, ItemID: itemIDPtr("mcpl_1")},
	} {
		event.SequenceNumber = position
		if err := validateProviderResponsesStream(state, event); err != nil {
			t.Fatalf("event %d rejected: %v", position, err)
		}
	}
	for _, event := range []*schemas.BifrostResponsesStreamResponse{
		{Type: schemas.ResponsesStreamResponseTypeMCPListToolsInProgress, OutputIndex: &index, ItemID: itemIDPtr("mcpl_1"), SequenceNumber: 3},
		{Type: schemas.ResponsesStreamResponseTypeMCPCallInProgress, OutputIndex: &index, ItemID: itemIDPtr("mcpl_1"), SequenceNumber: 3},
		{Type: schemas.ResponsesStreamResponseTypeMCPCallArgumentsDelta, OutputIndex: &index, ItemID: itemIDPtr("mcpl_1"), Delta: schemas.Ptr("{"), SequenceNumber: 3},
	} {
		if err := validateProviderResponsesStream(state, event); !errors.Is(err, ErrProviderResponseMalformed) {
			t.Fatalf("%s error = %v, want malformed provider response", event.Type, err)
		}
	}
}
