package stogas

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

const (
	localShellRequest = `{"model":"provider:openai gpt-5.5","input":"run it","reasoning":{"effort":"low"},"tools":[{"type":"shell","environment":{"type":"local"}}],"tool_choice":{"type":"shell"}}`
	localPatchRequest = `{"model":"provider:openai gpt-5.5","input":"patch it","reasoning":{"effort":"low"},"tools":[{"type":"apply_patch"}],"tool_choice":{"type":"apply_patch"}}`
	localBothRequest  = `{"model":"provider:openai gpt-5.5","input":"do both","reasoning":{"effort":"low"},"tools":[{"type":"shell","environment":{"type":"local"}},{"type":"apply_patch"}],"tool_choice":"required"}`
)

// localToolStream reads the events of a whole OpenAI stream (gpt-5.5, November 12, 2026) from
// testdata/openai-local-tools, decoded as core decodes each event.
func localToolStream(t *testing.T, name string) []*schemas.BifrostResponsesStreamResponse {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "openai-local-tools", name+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var events []*schemas.BifrostResponsesStreamResponse
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		event := &schemas.BifrostResponsesStreamResponse{}
		if err := sonic.Unmarshal(line, event); err != nil {
			t.Fatalf("decode %s: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

// replayLocalToolStream sends the events in order with their place in the stream as sequence
// number, so that a test can drop or repeat one, and stops at the first that the gateway refuses.
func replayLocalToolStream(state *State, events []*schemas.BifrostResponsesStreamResponse) error {
	for sequence, event := range events {
		event.SequenceNumber = sequence
		if err := validateProviderResponsesStream(state, event); err != nil {
			return err
		}
		state.observeResponsesStreamTextMaterial(event)
	}
	return nil
}

func TestProviderResponsesStreamAcceptsLiveShellAndPatchCalls(t *testing.T) {
	for _, test := range []struct {
		name, request, itemType string
		outputBytes             string
	}{
		// The commands "echo a" and "echo b".
		{"shell-stream", localShellRequest, "shell_call", "12"},
		// The diff "+hi\n" and the path "hello.txt".
		{"patch-stream", localPatchRequest, "apply_patch_call", "13"},
		// A patch that deletes a file streams no diff; its path is "old.txt".
		{"patch-delete-stream", localPatchRequest, "apply_patch_call", "7"},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := resolvedResponseValidationState(t, test.request)
			if err := replayLocalToolStream(state, localToolStream(t, test.name)); err != nil {
				t.Fatalf("live stream refused: %v", err)
			}
			calls := state.loggedToolCalls()
			if len(calls) != 1 || calls[0].Type != test.itemType || calls[0].CallID == "" || calls[0].StartedAt.IsZero() || calls[0].DoneAt.Before(calls[0].StartedAt) {
				t.Fatalf("logged calls = %+v, want one timed %s", calls, test.itemType)
			}
			if state.responsesClientCalls != 1 || state.responsesHostedCalls != 0 {
				t.Fatalf("client calls %d, hosted calls %d", state.responsesClientCalls, state.responsesHostedCalls)
			}
			if got := metersForState(state)[billing.MeterOutputTextBytes].Quantity; got != test.outputBytes {
				t.Fatalf("output text bytes = %s, want %s", got, test.outputBytes)
			}
		})
	}
}

func TestProviderResponsesAcceptsLiveShellReply(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "openai-local-tools", "shell-reply.json"))
	if err != nil {
		t.Fatal(err)
	}
	decode := func() *schemas.BifrostResponsesResponse {
		response := &schemas.BifrostResponsesResponse{}
		if err := sonic.Unmarshal(data, response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	state := resolvedResponseValidationState(t, localBothRequest)
	if err := validateProviderResponsesResponse(state, decode()); err != nil {
		t.Fatalf("live reply refused: %v", err)
	}
	if calls := state.loggedToolCalls(); len(calls) != 1 || calls[0].Type != "shell_call" || calls[0].CallID == "" {
		t.Fatalf("logged calls = %+v, want the shell call", calls)
	}

	shellCall := func(response *schemas.BifrostResponsesResponse) *schemas.ResponsesMessage {
		for index := range response.Output {
			if *response.Output[index].Type == schemas.ResponsesMessageTypeShellCall {
				return &response.Output[index]
			}
		}
		t.Fatal("no shell call in the reply")
		return nil
	}
	patchCall := func(operation schemas.ResponsesApplyPatchOperation) func(*schemas.ResponsesMessage) {
		return func(item *schemas.ResponsesMessage) {
			itemType := schemas.ResponsesMessageTypeApplyPatchCall
			item.Type = &itemType
			item.ResponsesToolMessage = &schemas.ResponsesToolMessage{
				CallID:                  item.ResponsesToolMessage.CallID,
				ResponsesApplyPatchCall: &schemas.ResponsesApplyPatchCall{Operation: &operation},
			}
		}
	}
	for name, test := range map[string]struct {
		request string
		change  func(*schemas.ResponsesMessage)
		refused bool
	}{
		"local environment": {localBothRequest, func(item *schemas.ResponsesMessage) {
			item.ResponsesToolMessage.ResponsesShellCall = &schemas.ResponsesShellCall{Environment: &schemas.ResponsesShellCallEnvironment{Type: "local"}}
		}, false},
		"a patch in place of the shell call": {localBothRequest, patchCall(schemas.ResponsesApplyPatchOperation{Type: "update_file", Path: "a.txt", Diff: schemas.Ptr("@@\n-x\n+z\n")}), false},
		"a patch without diff":               {localBothRequest, patchCall(schemas.ResponsesApplyPatchOperation{Type: "delete_file", Path: "a.txt"}), false},
		"shell not declared":                 {localPatchRequest, func(*schemas.ResponsesMessage) {}, true},
		"shell not chosen": {`{"model":"provider:openai gpt-5.5","input":"x","tools":[{"type":"shell"},{"type":"apply_patch"}],"tool_choice":{"type":"apply_patch"}}`,
			func(*schemas.ResponsesMessage) {}, true},
		"tools turned off": {`{"model":"provider:openai gpt-5.5","input":"x","tools":[{"type":"shell"}],"tool_choice":"none"}`,
			func(*schemas.ResponsesMessage) {}, true},
		"patch not declared": {localShellRequest, patchCall(schemas.ResponsesApplyPatchOperation{Type: "delete_file", Path: "a.txt"}), true},
		// A call that ran in a container would be a hosted shell, which bills by the minute.
		"container environment": {localBothRequest, func(item *schemas.ResponsesMessage) {
			item.ResponsesToolMessage.ResponsesShellCall = &schemas.ResponsesShellCall{Environment: &schemas.ResponsesShellCallEnvironment{Type: "container_reference", ContainerID: schemas.Ptr("cntr_1")}}
		}, true},
		"still running": {localBothRequest, func(item *schemas.ResponsesMessage) { item.Status = schemas.Ptr("in_progress") }, true},
		"no call id":    {localBothRequest, func(item *schemas.ResponsesMessage) { item.ResponsesToolMessage.CallID = nil }, true},
		"a tool name":   {localBothRequest, func(item *schemas.ResponsesMessage) { item.ResponsesToolMessage.Name = schemas.Ptr("shell") }, true},
		"no action":     {localBothRequest, func(item *schemas.ResponsesMessage) { item.ResponsesToolMessage.Action = nil }, true},
		"a patch without operation": {localBothRequest, func(item *schemas.ResponsesMessage) {
			patchCall(schemas.ResponsesApplyPatchOperation{})(item)
			item.ResponsesToolMessage.ResponsesApplyPatchCall.Operation = nil
		}, true},
		"a patch without operation type": {localBothRequest, patchCall(schemas.ResponsesApplyPatchOperation{Path: "a.txt"}), true},
	} {
		t.Run(name, func(t *testing.T) {
			response := decode()
			test.change(shellCall(response))
			err := validateProviderResponsesResponse(resolvedResponseValidationState(t, test.request), response)
			if test.refused && !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v, want malformed provider response", err)
			}
			if !test.refused && err != nil {
				t.Fatalf("reply refused: %v", err)
			}
		})
	}
}

func TestProviderResponsesStreamRefusesInconsistentShellAndPatchCalls(t *testing.T) {
	// Places in the live streams: the shell call is added at 2, its first command runs from 3
	// to 6 and its second from 7 to 10, and the call is done at 11. The patch is added at 2,
	// its diff runs from 3 to 5 and is done at 6, and the call is done at 7.
	without := func(events []*schemas.BifrostResponsesStreamResponse, places ...int) []*schemas.BifrostResponsesStreamResponse {
		var kept []*schemas.BifrostResponsesStreamResponse
		for place, event := range events {
			dropped := false
			for _, drop := range places {
				dropped = dropped || place == drop
			}
			if !dropped {
				kept = append(kept, event)
			}
		}
		return kept
	}
	for name, test := range map[string]struct {
		fixture, request string
		change           func([]*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse
	}{
		"a command that ends with other text": {"shell-stream", localShellRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			events[6].Command = schemas.Ptr("echo evil")
			return events
		}},
		"a final command that differs from the stream": {"shell-stream", localShellRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			events[11].Item.ResponsesToolMessage.Action.ResponsesShellToolCallAction.Commands[1] = "rm -rf /"
			return events
		}},
		"a final command that was not streamed": {"shell-stream", localShellRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			return without(events, 7, 8, 9, 10)
		}},
		"a command that never ends": {"shell-stream", localShellRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			return without(events, 10)
		}},
		"a command out of order": {"shell-stream", localShellRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			return without(events, 3, 4, 5, 6)
		}},
		"text for a command that ended": {"shell-stream", localShellRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			events[8].CommandIndex = schemas.Ptr(0)
			return events
		}},
		"a call added with commands": {"shell-stream", localShellRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			events[2].Item.ResponsesToolMessage.Action.ResponsesShellToolCallAction.Commands = []string{"echo a"}
			return events
		}},
		"shell commands without the shell tool": {"shell-stream", localPatchRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			return events
		}},
		"a diff that ends with other text": {"patch-stream", localPatchRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			events[6].Diff = schemas.Ptr("+evil\n")
			return events
		}},
		"a final diff that differs from the stream": {"patch-stream", localPatchRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			events[7].Item.ResponsesToolMessage.ResponsesApplyPatchCall.Operation.Diff = schemas.Ptr("+evil\n")
			return events
		}},
		"a diff that never ends": {"patch-stream", localPatchRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			return without(events, 6)
		}},
		"a final diff that was not streamed": {"patch-stream", localPatchRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			return without(events, 3, 4, 5, 6)
		}},
		"a diff for another item": {"patch-stream", localPatchRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			events[3].ItemID = schemas.Ptr("apc_other")
			return events
		}},
		"a patch without the apply_patch tool": {"patch-stream", localShellRequest, func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			return events
		}},
	} {
		t.Run(name, func(t *testing.T) {
			state := resolvedResponseValidationState(t, test.request)
			if err := replayLocalToolStream(state, test.change(localToolStream(t, test.fixture))); !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v, want malformed provider response", err)
			}
		})
	}
}

// OpenAI adds its own instructions for each tool, which the request does not show, so the hold
// reserves them. The counts are live input tokens (November 12, 2026), equal on gpt-5.5,
// gpt-5.6-luna, gpt-6-astra and gpt-6.1-sol: 13 for the prompt alone.
func TestHoldCoversOpenAIShellAndPatchInstructions(t *testing.T) {
	const prompt = `{"model":"provider:openai gpt-5.5","input":"Reply with the single word ok."`
	const skill = `{"name":"lint","description":"Lint the repository","path":"/skills/lint"}`
	plain, _ := heldInputTokens(t, prompt+`}`)
	for _, test := range []struct {
		name, tools string
		live        int64
	}{
		{"shell", `{"type":"shell","environment":{"type":"local"}}`, 250},
		{"shell without environment", `{"type":"shell"}`, 250},
		{"shell without skills", `{"type":"shell","environment":{"type":"local","skills":[]}}`, 250},
		{"shell with a skill", `{"type":"shell","environment":{"type":"local","skills":[` + skill + `]}}`, 782},
		{"shell with three skills", `{"type":"shell","environment":{"type":"local","skills":[` + skill + `,` + skill + `,` + skill + `]}}`, 806},
		{"apply_patch", `{"type":"apply_patch"}`, 636},
		{"both", `{"type":"shell","environment":{"type":"local"}},{"type":"apply_patch"}`, 857},
	} {
		t.Run(test.name, func(t *testing.T) {
			held, _ := heldInputTokens(t, prompt+`,"tools":[`+test.tools+`]}`)
			if held < test.live || held-plain < test.live-13 {
				t.Fatalf("held %d input tokens, %d more than without the tool; OpenAI counted %d, %d more", held, held-plain, test.live, test.live-13)
			}
			// tool_choice none still sends the instructions (live: 250 with shell, 636 with apply_patch).
			if off, _ := heldInputTokens(t, prompt+`,"tools":[`+test.tools+`],"tool_choice":"none"}`); off < test.live {
				t.Fatalf("held %d input tokens with tool_choice none, OpenAI counted %d", off, test.live)
			}
			// Turning parallel calls off adds 78 tokens to a request with any tool (live: 328 with
			// shell, 714 with apply_patch, 935 with both, 113 against 35 with one function).
			if serial, _ := heldInputTokens(t, prompt+`,"tools":[`+test.tools+`],"parallel_tool_calls":false}`); serial < test.live+78 {
				t.Fatalf("held %d input tokens without parallel calls, OpenAI counted %d", serial, test.live+78)
			}
		})
	}
}
