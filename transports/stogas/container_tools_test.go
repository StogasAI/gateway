package stogas

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// hostedToolExchange returns an exchange of a provider capture of OpenAI's hosted tools
// (gpt-6-luna, November 22, 2026), such as openai/code-interpreter, and its request, sent to an
// OpenAI deployment of the test catalog, whose model takes other reasoning efforts.
func hostedToolExchange(t *testing.T, capture, name string) (providerExchange, string) {
	t.Helper()
	recorded := exchange(t, providerCapture(t, "openai/"+capture), name)
	var body map[string]any
	if err := json.Unmarshal(recorded.Request.Body, &body); err != nil {
		t.Fatal(err)
	}
	body["model"] = "provider:openai gpt-5.5"
	delete(body, "reasoning")
	request, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return recorded, string(request)
}

// ingestHostedToolReply checks a recorded reply against the state of its request.
func ingestHostedToolReply(state *State, reply *schemas.BifrostResponsesResponse) error {
	// The test deployment runs another model than the recording.
	reply.Model = state.Resolution.Deployment.Upstream.Model
	state.Signals = &StandardSignals{Prompt: 10, Completion: 10}
	return state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: reply}, nil)
}

// Each recorded reply passes. OpenAI runs every call, so the log keeps none for the client to
// answer, and no call bills anything of its own: OpenAI bills containers by session.
func TestOpenAIContainerRepliesPass(t *testing.T) {
	for _, test := range []struct {
		capture, name string
		calls         []string
	}{
		{"code-interpreter", "a run", []string{"code_interpreter_call"}},
		{"code-interpreter", "a run without its outputs", []string{"code_interpreter_call"}},
		{"code-interpreter", "a forced run", []string{"code_interpreter_call"}},
		{"code-interpreter", "a container by its ID", []string{"code_interpreter_call"}},
		{"code-interpreter", "a file in the container", []string{"code_interpreter_call", "code_interpreter_call"}},
		{"code-interpreter", "a file that the code writes", []string{"code_interpreter_call"}},
		{"code-interpreter", "a run sent back", []string{"code_interpreter_call"}},
		{"container-tool-calls", "two runs", []string{"code_interpreter_call", "code_interpreter_call"}},
		// The second call, which max_tool_calls stops, ends interpreting.
		{"container-tool-calls", "two runs under max_tool_calls 1", []string{"code_interpreter_call", "code_interpreter_call"}},
		{"hosted-shell", "a hosted run", []string{"shell_call"}},
		{"hosted-shell", "a forced hosted run", []string{"shell_call"}},
		{"hosted-shell", "a container by reference", []string{"shell_call"}},
		{"hosted-shell", "an inline skill", []string{"shell_call"}},
		// The model runs its next command in the container of the call sent back.
		{"hosted-shell", "a hosted run sent back", []string{"shell_call"}},
		{"container-tool-calls", "two hosted runs", []string{"shell_call", "shell_call"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorded, request := hostedToolExchange(t, test.capture, test.name)
			state := customerFileSearchState(t, request)
			if err := ingestHostedToolReply(state, recorded.responsesReply(t)); err != nil {
				t.Fatalf("recorded reply refused: %v", err)
			}
			var logged []string
			for _, call := range state.loggedToolCalls() {
				if call.CallID != "" {
					t.Fatalf("logged %+v as a call that the client answers", call)
				}
				logged = append(logged, call.Type)
			}
			if !slices.Equal(logged, test.calls) {
				t.Fatalf("logged calls %v, want %v", logged, test.calls)
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatal(err)
			}
			for _, meter := range state.FinalMeters {
				if strings.HasPrefix(meter.MeterKey, "openai_responses_") {
					t.Fatalf("a container call billed %+v", meter)
				}
			}
		})
	}
}

// A stream passes with the events that OpenAI sent, and with code interpreter's lifecycle events
// left out, which a call that max_tool_calls stops never finishes, but not out of order or with
// code that its deltas did not write.
func TestOpenAIContainerStreamsAsRecorded(t *testing.T) {
	for _, test := range []struct{ capture, name, call string }{
		{"code-interpreter", "a streamed run", "code_interpreter_call"},
		{"hosted-shell", "a streamed hosted run", "shell_call"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorded, request := hostedToolExchange(t, test.capture, test.name)
			state := customerFileSearchState(t, request)
			state.Signals = &StandardSignals{Prompt: 10, Completion: 10}
			for sequence, event := range recorded.responsesStream(t) {
				event.SequenceNumber = sequence
				if event.Response != nil {
					event.Response.Model = state.Resolution.Deployment.Upstream.Model
				}
				if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}); err != nil {
					t.Fatalf("recorded event %s refused: %v", event.Type, err)
				}
			}
			calls := state.loggedToolCalls()
			if len(calls) != 1 || calls[0].Type != test.call || calls[0].CallID != "" || calls[0].DoneAt.Before(calls[0].StartedAt) {
				t.Fatalf("logged calls = %+v, want one timed %s that OpenAI ran", calls, test.call)
			}
		})
	}

	recorded, request := hostedToolExchange(t, "code-interpreter", "a streamed run")
	replay := func(change func([]*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse) error {
		return replayLocalToolStream(customerFileSearchState(t, request), change(recorded.responsesStream(t)))
	}
	withoutLifecycle := func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
		return slices.DeleteFunc(events, func(event *schemas.BifrostResponsesStreamResponse) bool {
			return event.Type == schemas.ResponsesStreamResponseTypeCodeInterpreterCallInProgress ||
				event.Type == schemas.ResponsesStreamResponseTypeCodeInterpreterCallInterpreting
		})
	}
	if err := replay(withoutLifecycle); err != nil {
		t.Fatalf("a stream without the lifecycle events got %v", err)
	}
	for name, change := range map[string]func([]*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse{
		"interpreting before in progress": func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			for index, event := range events {
				if event.Type == schemas.ResponsesStreamResponseTypeCodeInterpreterCallInProgress {
					event.Type = schemas.ResponsesStreamResponseTypeCodeInterpreterCallInterpreting
				} else if event.Type == schemas.ResponsesStreamResponseTypeCodeInterpreterCallInterpreting {
					events[index].Type = schemas.ResponsesStreamResponseTypeCodeInterpreterCallInProgress
				}
			}
			return events
		},
		"code that the deltas did not write": func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			for _, event := range events {
				if event.Type == schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDone {
					event.Code = schemas.Ptr("print(1)\n")
				}
			}
			return events
		},
		"a call on a request without the tool": func(events []*schemas.BifrostResponsesStreamResponse) []*schemas.BifrostResponsesStreamResponse {
			return events
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := customerFileSearchState(t, request)
			if name == "a call on a request without the tool" {
				state = customerFileSearchState(t, changedRequest(t, request, func(body map[string]any) { body["tool_choice"] = "none" }))
			}
			if err := replayLocalToolStream(state, change(recorded.responsesStream(t))); err == nil {
				t.Fatal("the stream passed")
			}
		})
	}
}

// A reply's calls must run where the request lets them: a hosted shell's in a container, a local
// shell's at the client, and output only for a hosted call of the reply.
func TestOpenAIContainerReplyChecks(t *testing.T) {
	hosted, hostedRequest := hostedToolExchange(t, "hosted-shell", "a hosted run")
	local := changedRequest(t, hostedRequest, func(body map[string]any) {
		body["tools"] = []any{map[string]any{"type": "shell", "environment": map[string]any{"type": "local"}}}
	})
	if err := ingestHostedToolReply(customerFileSearchState(t, local), hosted.responsesReply(t)); err == nil {
		t.Fatal("a hosted run passed a request whose shell is local")
	}
	reply := hosted.responsesReply(t)
	reply.Output[0].ResponsesShellCall.Environment = &schemas.ResponsesShellCallEnvironment{Type: "local"}
	reply.Output = reply.Output[:1]
	if err := ingestHostedToolReply(customerFileSearchState(t, hostedRequest), reply); err == nil {
		t.Fatal("a local call passed a request whose shell is hosted")
	}
	reply = hosted.responsesReply(t)
	reply.Output[1].ResponsesToolMessage.CallID = schemas.Ptr("call_other")
	if err := ingestHostedToolReply(customerFileSearchState(t, hostedRequest), reply); err == nil {
		t.Fatal("output of no call of the reply passed")
	}

	// A file citation of a container belongs to a reply whose request lets the model run code.
	written, writtenRequest := hostedToolExchange(t, "code-interpreter", "a file that the code writes")
	for choice, allowed := range map[string]bool{"auto": true, "none": false} {
		state := customerFileSearchState(t, changedRequest(t, writtenRequest, func(body map[string]any) { body["tool_choice"] = choice }))
		reply := written.responsesReply(t)
		reply.Output = reply.Output[len(reply.Output)-1:]
		if err := ingestHostedToolReply(state, reply); (err == nil) != allowed {
			t.Fatalf("a container's file citation under tool_choice %s: %v", choice, err)
		}
	}
}

// max_tool_calls caps code interpreter's calls, but no hosted shell's (capture
// openai/container-tool-calls), so a request whose only hosted tool is a shell cannot ask for it.
func TestOpenAIContainerMaxToolCalls(t *testing.T) {
	_, request := hostedToolExchange(t, "container-tool-calls", "two hosted runs under max_tool_calls 1")
	if err := customerRequestError(t, []byte(request)); err == nil || !strings.Contains(err.Error(), "max_tool_calls needs a hosted tool whose calls it caps") {
		t.Fatalf("max_tool_calls with a hosted shell got %v", err)
	}
	_, request = hostedToolExchange(t, "container-tool-calls", "two runs under max_tool_calls 1")
	customerFileSearchState(t, request)
}

// Calls sent back reach OpenAI as the reply gave them, without their status, which core leaves out
// and OpenAI takes back without (capture openai/container-replay), and without the images that
// code interpreter showed, which OpenAI ignores in input. Claude reads none of them, so it gets
// none.
func TestOpenAIContainerCallsSentBack(t *testing.T) {
	for _, test := range []struct{ capture, name string }{
		{"code-interpreter", "a run sent back"},
		{"hosted-shell", "a hosted run sent back"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, request := hostedToolExchange(t, test.capture, test.name)
			var sent, wire struct {
				Input []json.RawMessage `json:"input"`
			}
			if err := json.Unmarshal([]byte(request), &sent); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(fileSearchProviderBody(t, customerFileSearchState(t, request)), &wire); err != nil {
				t.Fatal(err)
			}
			if len(wire.Input) != len(sent.Input) {
				t.Fatalf("OpenAI got %d items of %d", len(wire.Input), len(sent.Input))
			}
			for index := range sent.Input {
				if want := withoutStatus(t, sent.Input[index]); !sameJSON(t, withoutStatus(t, wire.Input[index]), want) {
					t.Fatalf("input[%d] sent as %s, want %s", index, wire.Input[index], want)
				}
			}
			claude := changedRequest(t, request, func(body map[string]any) {
				body["model"] = "anthropic-claude-sonnet-4-6"
				delete(body, "tools")
				delete(body, "include")
			})
			body := string(fileSearchProviderBody(t, resolvedResponseValidationState(t, claude)))
			if strings.Contains(body, "cntr_") || strings.Contains(body, "tool_use") || strings.Contains(body, "tool_result") {
				t.Fatalf("Claude got a call that it does not read: %s", body)
			}
		})
	}

	_, request := hostedToolExchange(t, "container-replay", "an image output sent back")
	body := string(fileSearchProviderBody(t, customerFileSearchState(t, request)))
	if strings.Contains(body, "data:image/png") || !strings.Contains(body, `"outputs":null`) {
		t.Fatalf("OpenAI got %s", body)
	}
}

// The tools reach OpenAI as the client sent them, with every option of a container.
func TestOpenAIContainerToolsReachOpenAIExactly(t *testing.T) {
	const tools = `[{"type":"code_interpreter","container":{"type":"auto","file_ids":["file-1"],"memory_limit":"4g",` +
		`"network_policy":{"type":"allowlist","allowed_domains":["example.com"],"domain_secrets":[{"domain":"example.com","name":"TOKEN","value":"secret-value-1"}]}}},` +
		`{"type":"shell","environment":{"type":"container_auto","file_ids":["file-2"],"memory_limit":"1g","network_policy":{"type":"disabled"},` +
		`"skills":[{"type":"skill_reference","skill_id":"skill_1","version":"2"},{"type":"inline","name":"greet","description":"Greets","source":{"type":"base64","media_type":"application/zip","data":"UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA=="}}]}}]`
	state := customerFileSearchState(t, `{"model":"provider:openai gpt-5.5","input":"hi","tools":`+tools+`}`)
	var wire struct {
		Tools json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(fileSearchProviderBody(t, state), &wire); err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, wire.Tools, []byte(tools)) {
		t.Fatalf("OpenAI got tools %s", wire.Tools)
	}
	named := customerFileSearchState(t, `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"code_interpreter","container":"cntr_1"}]}`)
	if err := json.Unmarshal(fileSearchProviderBody(t, named), &wire); err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, wire.Tools, []byte(`[{"type":"code_interpreter","container":"cntr_1"}]`)) {
		t.Fatalf("OpenAI got tools %s", wire.Tools)
	}
}

// Each key that the gateway does not know could name content in the account, so the gateway
// refuses it at any depth, and a caller other than the model.
func TestOpenAIContainerToolShapes(t *testing.T) {
	for _, test := range []struct{ name, tool, want string }{
		{"a container option that the gateway does not know", `{"type":"code_interpreter","container":{"type":"auto","volumes":["v"]}}`, "tools[0].container.volumes is not supported"},
		{"a container without a type", `{"type":"code_interpreter","container":{}}`, "tools[0].container.type must be auto"},
		{"no container", `{"type":"code_interpreter"}`, "tools[0].container must be a container ID or an object"},
		{"an empty container ID", `{"type":"code_interpreter","container":" "}`, "tools[0].container must name a container"},
		{"files as text", `{"type":"code_interpreter","container":{"type":"auto","file_ids":"file-1"}}`, "tools[0].container.file_ids"},
		{"another network policy", `{"type":"code_interpreter","container":{"type":"auto","network_policy":{"type":"open"}}}`, "tools[0].container.network_policy.type must be disabled or allowlist"},
		{"domains as text", `{"type":"code_interpreter","container":{"type":"auto","network_policy":{"type":"allowlist","allowed_domains":"example.com"}}}`, "tools[0].container.network_policy.allowed_domains"},
		{"a domain secret of another shape", `{"type":"shell","environment":{"type":"container_auto","network_policy":{"type":"allowlist","allowed_domains":["example.com"],"domain_secrets":[{"domain":"example.com","name":"TOKEN","value":"secret","header":"X-Token"}]}}}`, "tools[0].environment.network_policy.domain_secrets[0].header is not supported"},
		{"a disabled policy with domains", `{"type":"shell","environment":{"type":"container_auto","network_policy":{"type":"disabled","allowed_domains":["example.com"]}}}`, "tools[0].environment.network_policy.allowed_domains is not supported"},
		{"a container reference without its ID", `{"type":"shell","environment":{"type":"container_reference"}}`, "tools[0].environment.container_id is required"},
		{"a container reference with options", `{"type":"shell","environment":{"type":"container_reference","container_id":"cntr_1","file_ids":["file-1"]}}`, "tools[0].environment.file_ids is not supported"},
		{"a stored skill without its ID", `{"type":"shell","environment":{"type":"container_auto","skills":[{"type":"skill_reference"}]}}`, "tools[0].environment.skills[0].skill_id is required"},
		{"a skill of another kind", `{"type":"shell","environment":{"type":"container_auto","skills":[{"name":"lint","description":"Lint","path":"/skills/lint"}]}}`, "tools[0].environment.skills[0].type must be skill_reference or inline"},
		{"an inline skill without its archive", `{"type":"shell","environment":{"type":"container_auto","skills":[{"type":"inline","name":"greet","description":"Greets","source":{"type":"base64","media_type":"application/zip"}}]}}`, "tools[0].environment.skills[0].source.data is required"},
		{"programmatic calls", `{"type":"code_interpreter","container":{"type":"auto"},"allowed_callers":["code_execution"]}`, "tools[0].allowed_callers can only be direct"},
		{"an empty list of callers", `{"type":"shell","environment":{"type":"container_auto"},"allowed_callers":[]}`, "tools[0].allowed_callers must list callers"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := customerRequestError(t, []byte(`{"model":"provider:openai gpt-5.5","input":"hi","tools":[`+test.tool+`]}`))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want %q", err, test.want)
			}
		})
	}
	for _, tool := range []string{
		`{"type":"code_interpreter","container":{"type":"auto"},"allowed_callers":["direct"]}`,
		`{"type":"shell","environment":{"type":"container_auto","network_policy":{"type":"allowlist","allowed_domains":["example.com"]}}}`,
	} {
		customerFileSearchState(t, `{"model":"provider:openai gpt-5.5","input":"hi","tools":[`+tool+`]}`)
	}
	// Only OpenAI's own Responses API runs either tool.
	for _, tool := range []string{`{"type":"code_interpreter","container":{"type":"auto"}}`, `{"type":"shell","environment":{"type":"container_auto"}}`} {
		err := customerRequestError(t, []byte(`{"model":"anthropic-claude-sonnet-4-6","input":"hi","tools":[`+tool+`]}`))
		if err == nil || !strings.Contains(err.Error(), "No deployment for this request runs") {
			t.Fatalf("Claude with %s got %v", tool, err)
		}
	}
}

// A container's code that can reach the network sends content where the catalog knows nothing,
// as a remote MCP server does: through an allowlist, from a container that the request names,
// whose policy no request shows, or from a container of a call sent back while a container tool
// is listed, which OpenAI runs the next calls in. A hosted shell runs where OpenAI does not say.
func TestOpenAIContainerNetworkReadsAsUnknownDestination(t *testing.T) {
	_, sentBack := hostedToolExchange(t, "code-interpreter", "a run sent back")
	_, withoutTool := hostedToolExchange(t, "container-replay", "a run sent back without the tool")
	for _, test := range []struct {
		name, request   string
		location, share bool
	}{
		{"a container that the request makes", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"code_interpreter","container":{"type":"auto"}}]}`, false, false},
		{"a disabled network", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"code_interpreter","container":{"type":"auto","network_policy":{"type":"disabled"}}}]}`, false, false},
		{"an allowlist", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"code_interpreter","container":{"type":"auto","network_policy":{"type":"allowlist","allowed_domains":["example.com"]}}}]}`, true, true},
		{"a named container", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"code_interpreter","container":"cntr_1"}]}`, true, true},
		{"a call sent back with the tool", sentBack, true, true},
		{"a call sent back without the tool", withoutTool, false, false},
		{"a hosted shell", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			handling := customerFileSearchState(t, test.request).Resolution.EffectiveDataHandling()
			unknown := handling.ProcessingLocation == "unknown" && handling.StorageLocation == "unknown"
			shared := slices.Contains(handling.SharedWith, "unknown") && handling.RetentionDays == nil && handling.TrainingUse == nil &&
				len(handling.Certifications) == 0
			if unknown != test.location || shared != test.share {
				t.Fatalf("data handling %+v", handling)
			}
		})
	}
}

// Each container tool keeps state in the customer's account, so only the account's owner can use
// it, and a container, a file or a stored skill that the request names is content that no input
// check reads.
func TestOpenAIContainerProviderState(t *testing.T) {
	_, sentBack := hostedToolExchange(t, "code-interpreter", "a run sent back")
	for _, test := range []struct{ name, request, reads string }{
		{"a container that the request makes", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"code_interpreter","container":{"type":"auto"}}]}`, ""},
		{"a named container", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"code_interpreter","container":"cntr_1"}]}`, "tools[0].container"},
		{"files", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"code_interpreter","container":{"type":"auto","file_ids":["file-1"]}}]}`, "tools[0].container.file_ids"},
		{"a stored skill", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"shell","environment":{"type":"container_auto","skills":[{"type":"skill_reference","skill_id":"skill_1"}]}}]}`, "tools[0].environment.skills"},
		{"a container reference", `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"shell","environment":{"type":"container_reference","container_id":"cntr_1"}}]}`, "tools[0].environment.container_id"},
		{"a call sent back", sentBack, "input[1]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := customerFileSearchState(t, test.request).Resolution.ProviderState()
			if !slices.Contains(provider.Fields, "container") || !provider.Keeps || !strings.HasPrefix(provider.Reads, test.reads) || (test.reads == "") != (provider.Reads == "") {
				t.Fatalf("provider state %+v, want reads %q", provider, test.reads)
			}
		})
	}
}

// OpenAI adds its own instructions for each tool to the input, under tool_choice none too, and the
// hold takes them whatever tool_choice says. The hold also covers the output of each call that
// the model reads: a hosted shell's calls, which no cap limits, and code interpreter's.
func TestOpenAIContainerHold(t *testing.T) {
	for _, test := range []struct {
		capture      string
		instructions int64
	}{
		{"code-interpreter", 1211},
		{"hosted-shell", 655},
	} {
		t.Run(test.capture, func(t *testing.T) {
			recorded, declared := hostedToolExchange(t, test.capture, "the tool under tool_choice none")
			_, bare := hostedToolExchange(t, test.capture, "without the tool")
			held := heldInputTokensOf(t, customerFileSearchState(t, declared))
			without := heldInputTokensOf(t, customerFileSearchState(t, bare))
			var usage struct {
				Usage struct {
					InputTokens int64 `json:"input_tokens"`
				} `json:"usage"`
			}
			if err := json.Unmarshal(recorded.Response.Body, &usage); err != nil {
				t.Fatal(err)
			}
			if held < usage.Usage.InputTokens || held-without < test.instructions {
				t.Fatalf("held %d with the tool and %d without it; OpenAI counted %d", held, without, usage.Usage.InputTokens)
			}
		})
	}
	for _, test := range []struct {
		name, tools string
		reads       int
	}{
		{"code interpreter", `[{"type":"code_interpreter","container":{"type":"auto"}}],"max_tool_calls":3`, 3},
		{"a hosted shell", `[{"type":"shell","environment":{"type":"container_auto"}}]`, defaultResponsesHostedToolCalls},
		{"both", `[{"type":"shell","environment":{"type":"container_auto"}},{"type":"code_interpreter","container":{"type":"auto"}}],"max_tool_calls":2`, defaultResponsesHostedToolCalls + 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			bare := heldInputTokensOf(t, customerFileSearchState(t, `{"model":"provider:openai gpt-5.5","input":"hi","tools":`+test.tools+`,"tool_choice":"none"}`))
			held := heldInputTokensOf(t, customerFileSearchState(t, `{"model":"provider:openai gpt-5.5","input":"hi","tools":`+test.tools+`}`))
			if held-bare != int64(test.reads*hostedCallContentTokens) {
				t.Fatalf("held %d more than under tool_choice none, want %d reads", held-bare, test.reads)
			}
		})
	}
}

// A domain secret is a credential that only the container needs: the reply's copy of the tools
// redacts it as OpenAI redacts an MCP server's, and failures and exports leave it out.
func TestContainerDomainSecretsStayOut(t *testing.T) {
	const request = `{"model":"provider:openai gpt-5.5","input":"hi","tools":[` +
		`{"type":"shell","environment":{"type":"container_auto","network_policy":{"type":"allowlist","allowed_domains":["example.com"],"domain_secrets":[{"domain":"example.com","name":"TOKEN","value":"shell-secret-value"}]}}},` +
		`{"type":"code_interpreter","container":{"type":"auto","network_policy":{"type":"allowlist","allowed_domains":["example.com"],"domain_secrets":[{"domain":"example.com","name":"TOKEN","value":"code-secret-value"}]}}}]}`
	state := customerFileSearchState(t, request)
	secrets := ToolSecrets(state.Resolution.RawTools())
	if !slices.Contains(secrets, "shell-secret-value") || !slices.Contains(secrets, "code-secret-value") {
		t.Fatalf("secrets %q", secrets)
	}
	reply := &schemas.BifrostResponsesResponse{}
	if err := sanitizeProviderResponsesEcho(state, reply); err != nil {
		t.Fatal(err)
	}
	echo, err := json.Marshal(reply.Tools)
	if err != nil {
		t.Fatal(err)
	}
	var tools []struct {
		Environment, Container struct {
			NetworkPolicy struct {
				DomainSecrets []struct{ Name, Value string } `json:"domain_secrets"`
			} `json:"network_policy"`
		}
	}
	if err := json.Unmarshal(echo, &tools); err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 || strings.Contains(string(echo), "secret-value") {
		t.Fatalf("the reply's tools are %s", echo)
	}
	for _, secrets := range [][]struct{ Name, Value string }{tools[0].Environment.NetworkPolicy.DomainSecrets, tools[1].Container.NetworkPolicy.DomainSecrets} {
		if len(secrets) != 1 || secrets[0].Name != "TOKEN" || secrets[0].Value != "<redacted>" {
			t.Fatalf("the reply's tools are %s", echo)
		}
	}
	// The request keeps its secrets for OpenAI.
	if !strings.Contains(string(fileSearchProviderBody(t, state)), "shell-secret-value") {
		t.Fatal("OpenAI got no domain secret")
	}
}

// A container's file citation reaches only OpenAI's own Responses API, as a file search's does.
func TestContainerFileCitationsReachOnlyOpenAI(t *testing.T) {
	const citation = `{"type":"container_file_citation","container_id":"cntr_1","file_id":"cfile_1","filename":"chart.png","start_index":77,"end_index":104}`
	reply := `"input":[{"role":"user","content":"Plot it."},{"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text",` +
		`"text":"The chart is saved as chart.png.","annotations":[` + citation + `],"logprobs":[]}]},{"role":"user","content":"Thanks."}]`
	body := string(fileSearchProviderBody(t, resolvedResponseValidationState(t, `{"model":"anthropic-claude-sonnet-4-6",`+reply+`}`)))
	if !strings.Contains(body, "The chart is saved as chart.png.") || strings.Contains(body, "cfile_1") {
		t.Fatalf("Claude got %s", body)
	}
	body = string(fileSearchProviderBody(t, resolvedResponseValidationState(t, `{"model":"provider:openai gpt-5.5",`+reply+`}`)))
	if !strings.Contains(body, `"container_id":"cntr_1"`) || !strings.Contains(body, `"file_id":"cfile_1"`) {
		t.Fatalf("OpenAI got %s", body)
	}
	for name, annotation := range map[string]string{
		"without its container": `{"type":"container_file_citation","file_id":"cfile_1","filename":"chart.png","start_index":0,"end_index":0}`,
		"a range backwards":     `{"type":"container_file_citation","container_id":"cntr_1","file_id":"cfile_1","filename":"chart.png","start_index":5,"end_index":4}`,
		"another field":         `{"type":"container_file_citation","container_id":"cntr_1","file_id":"cfile_1","filename":"chart.png","start_index":0,"end_index":0,"url":"https://example.com"}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := `{"model":"provider:openai gpt-5.5","input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[` +
				annotation + `]}]},{"role":"user","content":"continue"}]}`
			if err := customerRequestError(t, []byte(request)); err == nil {
				t.Fatalf("%s passed", annotation)
			}
		})
	}
}

// The containers that code interpreter and hosted shells run in hold the request's content, so
// policy can refuse them by name.
func TestContainerToolsInPolicy(t *testing.T) {
	for tool, want := range map[string]catalog.HostedTool{
		`{"type":"code_interpreter","container":{"type":"auto"}}`:  catalog.HostedToolCodeInterpreter,
		`{"type":"shell","environment":{"type":"container_auto"}}`: catalog.HostedToolShell,
	} {
		state := customerFileSearchState(t, `{"model":"provider:openai gpt-5.5","input":"hi","tools":[`+tool+`]}`)
		if got := state.Resolution.HostedTools(); !slices.Equal(got, []catalog.HostedTool{want}) {
			t.Fatalf("hosted tools of %s = %v", tool, got)
		}
	}
	local := customerFileSearchState(t, `{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"shell","environment":{"type":"local"}}]}`)
	if got := local.Resolution.HostedTools(); len(got) != 0 {
		t.Fatalf("a local shell reads as hosted tools %v", got)
	}
}

// withoutStatus returns an item without its status and the members whose value is null, which
// OpenAI reads as absent.
func withoutStatus(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var item map[string]any
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	delete(item, "status")
	var drop func(any)
	drop = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, member := range value {
				if member == nil {
					delete(value, key)
				}
				drop(member)
			}
		case []any:
			for _, member := range value {
				drop(member)
			}
		}
	}
	drop(item)
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
