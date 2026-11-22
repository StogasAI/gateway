package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const mcpServerTool = `{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com/sse","authorization":"token-must-stay-private","headers":{"X-Api-Key":"header-must-stay-private"}}`

func TestResponsesPolicyAcceptsOpenAIRemoteMCP(t *testing.T) {
	for _, body := range []string{
		`{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + mcpServerTool + `]}`,
		`{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"calendar","connector_id":"connector_googlecalendar","authorization":"oauth","require_approval":"never"}],"max_tool_calls":3}`,
		`{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"tunnel","tunnel_id":"tun_1","server_description":"Internal docs","allowed_tools":["search","fetch"],"require_approval":"always"}]}`,
		`{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","allowed_tools":{"tool_names":["search"],"read_only":true},"require_approval":{"never":{"tool_names":["search"]},"always":{"read_only":false}},"allowed_callers":["direct"],"defer_loading":false}]}`,
		`{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,{"type":"mcp","server_label":"docs","server_url":"https://docs.example.com/mcp"},{"type":"function","name":"search"}],"tool_choice":{"type":"mcp","server_label":"docs","name":"lookup"}}`,
		`{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,{"type":"web_search"}],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"mcp","server_label":"wiki"},{"type":"web_search"}]}}`,
		// A stateless continuation replays the listing and the approval request, then answers it.
		`{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `],"input":[
			{"role":"user","content":"Look it up"},
			{"type":"mcp_list_tools","id":"mcpl_1","server_label":"wiki","tools":[{"name":"ask","input_schema":{"type":"object"},"description":"Ask the wiki"}]},
			{"type":"mcp_approval_request","id":"mcpr_1","server_label":"wiki","name":"ask","arguments":"{\"q\":\"x\"}"},
			{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true,"reason":"fine"}]}`,
		`{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `],"input":[
			{"role":"user","content":"Look it up"},
			{"type":"mcp_call","id":"mcp_1","server_label":"wiki","name":"ask","arguments":"{}","output":"answer","error":null,"status":"completed","approval_request_id":"mcpr_1"},
			{"type":"mcp_call","id":"mcp_2","server_label":"wiki","name":"ask","arguments":"","error":{"type":"http_error","code":500,"message":"down"},"status":"failed"},
			{"role":"user","content":"Thanks"}]}`,
		// An approval answers the model as a tool result does, so it needs no new message.
		`{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `],"input":[
			{"type":"mcp_list_tools","id":"mcpl_1","server_label":"wiki","tools":[{"name":"ask","input_schema":{"type":"object"}}]},
			{"type":"mcp_approval_request","id":"mcpr_1","server_label":"wiki","name":"ask","arguments":"{}"},
			{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true}]}`,
		// History can name a server that the request no longer declares, once its calls ran.
		`{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `],"input":[
			{"role":"user","content":"Look it up"},
			{"type":"mcp_approval_request","id":"mcpr_1","server_label":"docs","name":"ask","arguments":"{}"},
			{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true},
			{"type":"mcp_call","id":"mcp_1","server_label":"docs","name":"ask","arguments":"{}","output":"answer","approval_request_id":"mcpr_1"},
			{"type":"mcp_approval_request","id":"mcpr_2","server_label":"docs","name":"ask","arguments":"{}"},
			{"type":"mcp_approval_response","approval_request_id":"mcpr_2","approve":false},
			{"role":"user","content":"Thanks"}]}`,
		// MCP items can sit between a client call and its output, as a response returns them.
		`{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `,{"type":"function","name":"lookup"}],"input":[
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
		{"missing label", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_url":"https://mcp.example.com"}]}`, "server_label must name the server"},
		{"padded label", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":" wiki","server_url":"https://mcp.example.com"}]}`, "server_label must name the server"},
		// A server that no policy can name would pass every rule that denies servers by name.
		{"no server", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki"}]}`, "tools[0] must name its server"},
		{"a path another reader resolves", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com/allowed/../denied"}]}`, "tools[0] must name its server"},
		{"an unnamed URL beside a connector", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","connector_id":"connector_gmail","server_url":"https://mcp.example.com\\@evil.example/"}]}`, "tools[0] must name its server"},
		{"a connector ID that is no ID", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","connector_id":"connector_gmail#*"}]}`, "tools[0] must name its server"},
		{"duplicate label", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,` + mcpServerTool + `]}`, "duplicates another MCP server"},
		{"unknown key", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","future":true}]}`, "tools[0].future is not supported"},
		{"header values", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","headers":{"X":1}}]}`, "Invalid JSON body"},
		{"approval setting", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"sometimes"}]}`, "require_approval must be always, never"},
		{"approval filter key", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":{"maybe":{}}}]}`, "require_approval.maybe is not supported"},
		{"approval list", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":{"never":["search"]}}]}`, "Invalid JSON body"},
		// The forwarded filter would leave an empty tool_names out and so cover every tool.
		{"empty allowed filter", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","allowed_tools":{"tool_names":[]}}]}`, "allowed_tools.tool_names must name at least one tool"},
		{"empty never filter", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":{"never":{"tool_names":[],"read_only":true}}}]}`, "require_approval.never.tool_names must name at least one tool"},
		{"programmatic callers", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","allowed_callers":["programmatic"]}]}`, "programmatic calls are not supported"},
		{"deferred loading", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","defer_loading":true}]}`, "tools[0].defer_loading is not supported for MCP tools"},
		{"undeclared server choice", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + mcpServerTool + `],"tool_choice":{"type":"mcp","server_label":"docs"}}`, "selects an undeclared MCP server"},
		{"undeclared allowed server", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + mcpServerTool + `],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"mcp","server_label":"docs"}]}}`, "selects an undeclared MCP server"},
		{"approval without decision", `{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},{"type":"mcp_approval_response","approval_request_id":"mcpr_1"}]}`, "approve must be a boolean"},
		{"approval without its request", `{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true}]}`, "must answer an mcp_approval_request in the same input"},
		{"approval for an undeclared server", `{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},{"type":"mcp_approval_request","id":"mcpr_1","server_label":"docs","name":"ask","arguments":"{}"},{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true}]}`, "approves a call to an MCP server that tools does not declare"},
		{"listing without tools", `{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},{"type":"mcp_list_tools","id":"mcpl_1","server_label":"wiki"}]}`, "tools must list the server's tools"},
		{"call without name", `{"model":"provider:openai gpt-5.5","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},{"type":"mcp_call","id":"mcp_1","server_label":"wiki","arguments":"{}"}]}`, "name is required"},
		{"azure", `{"model":"provider:azure gpt-5.5","input":"hi","tools":[` + mcpServerTool + `]}`, "No deployment for this request runs mcp."},
		{"anthropic", `{"model":"anthropic-claude-sonnet-4-6","input":"hi","tools":[` + mcpServerTool + `]}`, "No deployment for this request runs mcp."},
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
	return heldInputTokensOf(t, state), state
}

// heldInputTokensOf sums the input tokens of every hold meter of a checked request, at any rate.
func heldInputTokensOf(t *testing.T, state *State) int64 {
	t.Helper()
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
	return total.Int64()
}

// The hold takes one typical hosted call's content for each tool list that OpenAI fetches and
// each call that the request lets run.
func TestRemoteMCPHoldsATypicalResultForEachListingAndCall(t *testing.T) {
	const model = `"model":"provider:openai gpt-5.5"`
	const unattended = `{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"never"}`
	listing := `{"type":"mcp_list_tools","id":"mcpl_1","server_label":"wiki","tools":[]}`
	request := func(id string) string {
		return `{"type":"mcp_approval_request","id":"` + id + `","server_label":"wiki","name":"ask","arguments":"{}"}`
	}
	approval := func(id string, approve bool) string {
		return `{"type":"mcp_approval_response","approval_request_id":"` + id + `","approve":` + strconv.FormatBool(approve) + `}`
	}
	ran := func(id string) string {
		return `{"type":"mcp_call","id":"mcp_` + id + `","server_label":"wiki","name":"ask","arguments":"{}","output":"x","approval_request_id":"` + id + `"}`
	}
	for _, item := range []struct {
		name  string
		body  string
		reads int64
	}{
		{"a listing", `{` + model + `,"input":"hi","tools":[` + mcpServerTool + `]}`, 1},
		{"a replayed listing", `{` + model + `,"tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},` + listing + `]}`, 0},
		{"one approved call", `{` + model + `,"tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},` + listing + `,` +
			request("mcpr_1") + `,` + request("mcpr_2") + `,` + approval("mcpr_1", true) + `,` + approval("mcpr_2", false) + `]}`, 1},
		// A replay repeats earlier approvals with the calls that ran, and only the new one runs.
		{"replayed approvals", `{` + model + `,"tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},` + listing + `,` +
			request("mcpr_1") + `,` + approval("mcpr_1", true) + `,` + ran("mcpr_1") + `,` + request("mcpr_2") + `,` + approval("mcpr_2", true) + `,` + ran("mcpr_2") +
			`,{"role":"assistant","content":"Done"},{"role":"user","content":"Again"},` + request("mcpr_3") + `,` + approval("mcpr_3", true) + `,` + approval("mcpr_3", true) + `]}`, 1},
		// An approved call answers an earlier request, whatever tool_choice now selects.
		{"approved call without a choice of MCP", `{` + model + `,"tool_choice":"none","tools":[` + mcpServerTool + `],"input":[{"role":"user","content":"hi"},` +
			request("mcpr_1") + `,` + approval("mcpr_1", true) + `]}`, 2},
		{"calls without approval up to the default", `{` + model + `,"input":"hi","tools":[` + unattended + `]}`, 1 + defaultResponsesHostedToolCalls},
		{"calls without approval up to the cap", `{` + model + `,"input":"hi","max_tool_calls":3,"tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":{"never":{"read_only":true}}}]}`, 4},
		// Hosted tools share max_tool_calls, so the web search hold already covers these calls.
		{"calls without approval beside a web search", `{` + model + `,"input":"hi","tools":[` + unattended + `,{"type":"web_search"}]}`, 1},
		// OpenAI fetches a declared server's tool list whatever tool_choice says.
		{"no callable server", `{` + model + `,"input":"hi","tools":[` + unattended + `],"tool_choice":"none"}`, 1},
		{"another tool forced", `{` + model + `,"input":"hi","tools":[` + unattended + `,{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`, 1},
	} {
		t.Run(item.name, func(t *testing.T) {
			_, state := heldInputTokens(t, item.body)
			var held int64
			for _, meter := range openAIResponsesMCPHoldMeters(openAIAdapterContextForHold(state)) {
				quantity, err := strconv.ParseInt(meter.Quantity, 10, 64)
				if err != nil || meter.MeterKey != billing.MeterInputTokens || !meter.HoldRequired {
					t.Fatalf("unexpected meter %+v", meter)
				}
				held += quantity
			}
			if want := item.reads * hostedCallContentTokens; held != want {
				t.Fatalf("held input = %d, want %d reads of %d", held, item.reads, hostedCallContentTokens)
			}
		})
	}
}

func TestRemoteMCPRequestsSendOnlyTheClientsCap(t *testing.T) {
	for body, want := range map[string]*int{
		`{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + mcpServerTool + `]}`:                                                                                  nil,
		`{"model":"provider:openai gpt-5.5","input":"hi","max_tool_calls":2,"tools":[` + mcpServerTool + `]}`:                                                               schemas.Ptr(2),
		`{"model":"provider:openai gpt-5.5","input":"hi","tool_choice":"none","tools":[` + mcpServerTool + `]}`:                                                             nil,
		`{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"never"}]}`: nil,
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
		body := `{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + tool + `]}`
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
	approvalRequest := `{"model":"provider:openai gpt-5.5","input":"hi","tool_choice":"required","tools":[` + mcpServerTool + `]}`
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
	// The reply's copy of the tool reads as OpenAI writes it: no credential, and the URL as sent.
	echoed, err := json.Marshal(response.Tools)
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"type":"mcp","server_label":"wiki","authorization":"\u003credacted\u003e","headers":{"X-Api-Key":"\u003credacted\u003e"},"server_url":"https://mcp.example.com/sse"}]`; !sameJSON(t, echoed, []byte(want)) {
		t.Fatalf("echoed tools = %s", echoed)
	}

	unattended := `{"model":"provider:openai gpt-5.5","input":"hi","max_tool_calls":2,"tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"never"}]}`
	state = resolvedResponseValidationState(t, unattended)
	response = validUnaryResponsesProviderResponse("resp_mcp_calls")
	failed := mcpCall("mcp_2", "wiki")
	failed.Status = schemas.Ptr("failed")
	failed.ResponsesToolMessage.Output = nil
	failed.ResponsesToolMessage.Error = &schemas.ResponsesToolMessageError{ResponsesToolMessageErrorStruct: &schemas.ResponsesToolMessageErrorStruct{
		Type: "mcp_protocol_error", Code: json.RawMessage(`-32600`), Message: schemas.Ptr("bad request"),
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
		"server not chosen":   {`{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,{"type":"mcp","server_label":"docs","server_url":"https://docs.example.com"}],"tool_choice":{"type":"mcp","server_label":"docs"}}`, []schemas.ResponsesMessage{mcpCall("mcp_1", "wiki")}},
		"no MCP tool":         {`{"model":"provider:openai gpt-5.5","input":"hi"}`, []schemas.ResponsesMessage{mcpListing("mcpl_1", "wiki")}},
		"hosted tool chosen":  {`{"model":"provider:openai gpt-5.5","input":"hi","tools":[` + mcpServerTool + `,{"type":"web_search"}],"tool_choice":{"type":"web_search"}}`, []schemas.ResponsesMessage{mcpCall("mcp_1", "wiki")}},
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
	request := `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"wiki","server_url":"https://mcp.example.com","require_approval":"never"}]}`
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

// OpenAI's own replies pass the gateway's checks, and each call counts toward max_tool_calls as
// OpenAI counts it (captures openai/mcp-approval-replay, openai/mcp-listing and
// openai/mcp-max-tool-calls).
func TestRecordedRemoteMCPRepliesPass(t *testing.T) {
	for _, item := range []struct {
		capture, name string
		hostedCalls   int
	}{
		{"openai/mcp-approval-replay", "approval request", 0},
		// The server refused the call, which still ran and counts.
		{"openai/mcp-approval-replay", "approved call", 1},
		{"openai/mcp-listing", "tool_choice none", 0},
		{"openai/mcp-listing", "replayed listing", 0},
		{"openai/mcp-max-tool-calls", "three calls under a cap of one", 1},
	} {
		t.Run(item.name, func(t *testing.T) {
			recorded := exchange(t, providerCapture(t, item.capture), item.name)
			state := resolvedResponseValidationState(t, cutToolCallRequest(t, recorded))
			if err := validateProviderResponsesResponse(state, recorded.responsesReply(t)); err != nil {
				t.Fatalf("recorded reply refused: %v", err)
			}
			if state.responsesHostedCalls != item.hostedCalls {
				t.Fatalf("hosted calls = %d, want %d", state.responsesHostedCalls, item.hostedCalls)
			}
		})
	}
}
