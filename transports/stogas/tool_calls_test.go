package stogas

import (
	"slices"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestRequestLogFindsTheResultsOfTheLatestTurn(t *testing.T) {
	const chatTools = `"tools":[{"type":"function","function":{"name":"lookup"}}]`
	chatCalls := func(ids ...string) string {
		calls := ""
		for index, id := range ids {
			if index > 0 {
				calls += ","
			}
			calls += `{"id":"` + id + `","type":"function","function":{"name":"lookup","arguments":"{}"}}`
		}
		return `{"role":"assistant","tool_calls":[` + calls + `]}`
	}
	chatResult := func(id string) string { return `{"role":"tool","tool_call_id":"` + id + `","content":"x"}` }
	const user = `{"role":"user","content":"hi"}`
	for name, test := range map[string]struct {
		messages string
		want     []string
	}{
		"first message":               {user, nil},
		"results of the latest turn":  {user + "," + chatCalls("c1", "c2") + "," + chatResult("c1") + "," + chatResult("c2"), []string{"c1", "c2"}},
		"results of earlier turns":    {user + "," + chatCalls("c1") + "," + chatResult("c1") + "," + chatCalls("c2") + "," + chatResult("c2"), []string{"c2"}},
		"a message after the results": {user + "," + chatCalls("c1") + "," + chatResult("c1") + `,{"role":"user","content":"and?"}`, []string{"c1"}},
		"a reply after the results":   {user + "," + chatCalls("c1") + "," + chatResult("c1") + `,{"role":"assistant","content":"done"},` + user, nil},
		"a prefill after the results": {user + "," + chatCalls("c1") + "," + chatResult("c1") + `,{"role":"assistant","content":"Sure"}`, nil},
		"a system message after them": {user + "," + chatCalls("c1") + "," + chatResult("c1") + `,{"role":"system","content":"brief"}`, []string{"c1"}},
	} {
		t.Run("chat "+name, func(t *testing.T) {
			state := resolvedChatValidationState(t, `{"model":"openai/gpt-5.5",`+chatTools+`,"messages":[`+test.messages+`]}`)
			if !slices.Equal(state.answeredCallIDs, test.want) {
				t.Fatalf("answered = %v, want %v", state.answeredCallIDs, test.want)
			}
		})
	}

	const responsesTools = `"tools":[` + mcpServerTool + `,{"type":"function","name":"lookup"}]`
	call := func(id string) string {
		return `{"type":"function_call","call_id":"` + id + `","name":"lookup","arguments":"{}"}`
	}
	output := func(id string) string { return `{"type":"function_call_output","call_id":"` + id + `","output":"x"}` }
	const listing = `{"type":"mcp_list_tools","id":"mcpl_1","server_label":"wiki","tools":[{"name":"ask","input_schema":{"type":"object"}}]}`
	const approvalRequest = `{"type":"mcp_approval_request","id":"mcpr_1","server_label":"wiki","name":"ask","arguments":"{}"}`
	const approval = `{"type":"mcp_approval_response","approval_request_id":"mcpr_1","approve":true}`
	for name, test := range map[string]struct {
		input string
		want  []string
	}{
		"text":                        {`"hi"`, nil},
		"results after their calls":   {`[` + user + "," + call("c1") + "," + call("c2") + "," + output("c1") + "," + output("c2") + `]`, []string{"c1", "c2"}},
		"results between their calls": {`[` + user + "," + call("c1") + "," + output("c1") + "," + call("c2") + "," + output("c2") + `]`, []string{"c1", "c2"}},
		"results of earlier turns": {`[` + user + "," + call("c1") + "," + output("c1") + `,{"role":"assistant","content":"checking"},` +
			call("c2") + "," + output("c2") + `,{"role":"user","content":"more"}]`, []string{"c2"}},
		"a message between turns": {`[` + user + "," + call("c1") + "," + output("c1") + `,{"role":"user","content":"again"},` +
			call("c2") + "," + output("c2") + `]`, []string{"c2"}},
		"an approval":            {`[` + user + "," + listing + "," + approvalRequest + "," + approval + `]`, []string{"mcpr_1"}},
		"a call and an approval": {`[` + user + "," + call("c1") + "," + approvalRequest + "," + output("c1") + "," + approval + `]`, []string{"c1", "mcpr_1"}},
		"a reply after results":  {`[` + user + "," + call("c1") + "," + output("c1") + `,{"role":"assistant","content":"done"}]`, nil},
	} {
		t.Run("responses "+name, func(t *testing.T) {
			state := resolvedResponseValidationState(t, `{"model":"openai/gpt-5.5",`+responsesTools+`,"input":`+test.input+`}`)
			if !slices.Equal(state.answeredCallIDs, test.want) {
				t.Fatalf("answered = %v, want %v", state.answeredCallIDs, test.want)
			}
		})
	}
}

// A streamed call runs from the event that adds it to the one that ends it, and a call that the
// client answers keeps the ID that its result names.
func TestRequestLogTimesStreamedToolCalls(t *testing.T) {
	state := resolvedResponseValidationState(t, `{"model":"openai/gpt-5.5","input":"hi","tools":[`+mcpServerTool+`,{"type":"function","name":"lookup"}]}`)
	sequence := 0
	send := func(event *schemas.BifrostResponsesStreamResponse) {
		t.Helper()
		event.SequenceNumber = sequence
		sequence++
		if err := validateProviderResponsesStream(state, event); err != nil {
			t.Fatalf("%s: %v", event.Type, err)
		}
	}
	send(validResponsesProviderEvent(schemas.ResponsesStreamResponseTypeCreated, 0, "resp_tools"))
	listIndex, callIndex := 0, 1
	listing := mcpListing("mcpl_1", "wiki")
	addedListing := listing
	addedListing.ResponsesToolMessage = &schemas.ResponsesToolMessage{ServerLabel: schemas.Ptr("wiki"), ResponsesMCPListTools: &schemas.ResponsesMCPListTools{Tools: []schemas.ResponsesMCPTool{}}}
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: &listIndex, Item: &addedListing})
	if len(state.toolCalls) != 1 || state.toolCalls[0].startedAt.IsZero() || !state.toolCalls[0].doneAt.IsZero() {
		t.Fatalf("listing after it was added = %+v, want started and not done", state.toolCalls)
	}
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &listIndex, Item: &listing})
	itemType, inProgress, completed := schemas.ResponsesMessageTypeFunctionCall, "in_progress", "completed"
	added := schemas.ResponsesMessage{
		ID: schemas.Ptr("fc_1"), Type: &itemType, Status: &inProgress,
		ResponsesToolMessage: &schemas.ResponsesToolMessage{CallID: schemas.Ptr("call_1"), Name: schemas.Ptr("lookup"), Arguments: schemas.Ptr("")},
	}
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: &callIndex, Item: &added})
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta, OutputIndex: &callIndex, ItemID: schemas.Ptr("fc_1"), Delta: schemas.Ptr("{}")})
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone, OutputIndex: &callIndex, ItemID: schemas.Ptr("fc_1"), Arguments: schemas.Ptr("{}")})
	done := added
	done.Status = &completed
	done.ResponsesToolMessage = &schemas.ResponsesToolMessage{CallID: schemas.Ptr("call_1"), Name: schemas.Ptr("lookup"), Arguments: schemas.Ptr("{}")}
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &callIndex, Item: &done})
	terminal := validResponsesProviderEvent(schemas.ResponsesStreamResponseTypeCompleted, sequence, "resp_tools")
	terminal.Response.Output = []schemas.ResponsesMessage{listing, done}
	send(terminal)

	calls := state.loggedToolCalls()
	if len(calls) != 2 || calls[0].Type != "mcp_list_tools" || calls[0].CallID != "" ||
		calls[1].Type != "function_call" || calls[1].CallID != "call_1" {
		t.Fatalf("logged calls = %+v, want the listing and the function call", calls)
	}
	for _, call := range calls {
		if call.StartedAt.IsZero() || call.DoneAt.Before(call.StartedAt) {
			t.Fatalf("%s ran from %v to %v, want both events' times", call.Type, call.StartedAt, call.DoneAt)
		}
	}
	if calls[1].StartedAt.Before(calls[0].DoneAt) {
		t.Fatal("the call started before the listing ended")
	}
}

func TestRequestLogKeepsWholeResponsesUntimed(t *testing.T) {
	state := resolvedResponseValidationState(t, `{"model":"openai/gpt-5.5","input":"hi","tool_choice":"required","tools":[`+mcpServerTool+`]}`)
	response := validUnaryResponsesProviderResponse("resp_mcp_approval")
	response.Output = []schemas.ResponsesMessage{mcpListing("mcpl_1", "wiki"), mcpApprovalRequest("mcpr_1", "wiki")}
	if err := validateProviderResponsesResponse(state, response); err != nil {
		t.Fatal(err)
	}
	// Validating the same response again records nothing twice.
	if err := validateProviderResponsesResponse(state, response); err != nil {
		t.Fatal(err)
	}
	calls := state.loggedToolCalls()
	if len(calls) != 2 || calls[0].Type != "mcp_list_tools" || calls[1].Type != "mcp_approval_request" || calls[1].CallID != "mcpr_1" {
		t.Fatalf("logged calls = %+v, want the listing and the approval request", calls)
	}
	for _, call := range calls {
		if !call.StartedAt.IsZero() || !call.DoneAt.IsZero() {
			t.Fatalf("%s has times in a whole response", call.Type)
		}
	}
}

func TestRequestLogTimesChatToolCallsFromTheirDeltas(t *testing.T) {
	state := resolvedChatValidationState(t, `{"model":"openai/gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}]}`)
	role := string(schemas.ChatMessageRoleAssistant)
	for index, arguments := range []string{`{"q":`, `"x"}`} {
		chunk := validChatProviderChunk("chatcmpl_tool", false)
		call := schemas.ChatAssistantMessageToolCall{Function: schemas.ChatAssistantMessageToolCallFunction{Arguments: arguments}}
		chunk.Choices[0].ChatStreamResponseChoice.Delta.Role = nil
		if index == 0 {
			call.Type, call.ID, call.Function.Name = schemas.Ptr("function"), schemas.Ptr("call_1"), schemas.Ptr("lookup")
			chunk.Choices[0].ChatStreamResponseChoice.Delta.Role = &role
		}
		chunk.Choices[0].ChatStreamResponseChoice.Delta.ToolCalls = []schemas.ChatAssistantMessageToolCall{call}
		if err := validateProviderChatResponse(state, chunk, true); err != nil {
			t.Fatal(err)
		}
		if index == 0 && !state.chatToolCalls[0].doneAt.Equal(state.chatToolCalls[0].startedAt) {
			t.Fatal("the first delta both starts and, so far, ends the call")
		}
	}
	calls := state.loggedToolCalls()
	if len(calls) != 1 || calls[0].Type != "function_call" || calls[0].CallID != "call_1" ||
		calls[0].StartedAt.IsZero() || calls[0].DoneAt.Before(calls[0].StartedAt) {
		t.Fatalf("logged calls = %+v, want the streamed function call", calls)
	}
}
