package stogas

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// fileSearchExchange returns an exchange of the provider capture openai/file-search (gpt-6-luna,
// November 22, 2026) and its request, sent to an OpenAI deployment of the test catalog, whose
// model takes other reasoning efforts. A result of a search sent back loses the vector_store_id
// that OpenAI adds, as the gateway's replies never carry it.
func fileSearchExchange(t *testing.T, name string) (providerExchange, string) {
	t.Helper()
	recorded := exchange(t, providerCapture(t, "openai/file-search"), name)
	var body map[string]any
	if err := json.Unmarshal(recorded.Request.Body, &body); err != nil {
		t.Fatal(err)
	}
	body["model"] = "provider:openai gpt-5.5"
	delete(body, "reasoning")
	if input, ok := body["input"].([]any); ok {
		for _, item := range input {
			results, _ := item.(map[string]any)["results"].([]any)
			for _, result := range results {
				delete(result.(map[string]any), "vector_store_id")
			}
		}
	}
	request, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return recorded, string(request)
}

// customerFileSearchState resolves and checks a request that a customer's own OpenAI credential
// serves, which the request must pass.
func customerFileSearchState(t *testing.T, request string) *State {
	t.Helper()
	state, err := customerRequestState(t, "responses", []byte(request))
	if err != nil {
		t.Fatalf("request refused: %v", err)
	}
	return state
}

// customerRequestError returns the refusal of a request that a customer's own OpenAI credential
// serves, from parsing and resolving it or from checking it.
func customerRequestError(t *testing.T, body []byte) error {
	t.Helper()
	if _, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: body}); err != nil {
		return err
	}
	_, err := customerRequestState(t, "responses", body)
	return err
}

// fileSearchProviderBody returns the body that the gateway sends to OpenAI for a request.
func fileSearchProviderBody(t *testing.T, state *State) []byte {
	t.Helper()
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatal(err)
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.RequestType)
	request, err := state.Resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatal(err)
	}
	return preparedProviderBody(t, ctx, request.ResponsesRequest)
}

// fileSearchCalls returns the quantity of the file search meter, or "" when meters bill none.
func fileSearchCalls(meters []catalog.MeterEstimate) string {
	if meter := findMeterEstimate(meters, MeterOpenAIResponsesFileSearchCalls); meter != nil {
		return meter.Quantity
	}
	return ""
}

// Each recorded reply passes, logs its search as a call that the provider runs and bills one
// search, with or without the results that include asks for.
func TestOpenAIFileSearchRepliesPass(t *testing.T) {
	for _, name := range []string{"a search", "a search without its results", "a forced search", "ranking options and a filter", "a search sent back"} {
		t.Run(name, func(t *testing.T) {
			recorded, request := fileSearchExchange(t, name)
			state := customerFileSearchState(t, request)
			reply := recorded.responsesReply(t)
			// The test deployment runs another model than the recording.
			reply.Model = state.Resolution.Deployment.Upstream.Model
			state.Signals = &StandardSignals{Prompt: 10, Completion: 10}
			if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: reply}, nil); err != nil {
				t.Fatalf("recorded reply refused: %v", err)
			}
			if calls := state.loggedToolCalls(); len(calls) != 1 || calls[0].Type != "file_search_call" || calls[0].CallID != "" {
				t.Fatalf("logged calls = %+v, want one file search", calls)
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatal(err)
			}
			if got := fileSearchCalls(state.FinalMeters); got != "1" {
				t.Fatalf("file search calls = %q, want 1 in %+v", got, state.FinalMeters)
			}
		})
	}
}

// A stream bills its search once, although its completed event, its done item and the completed
// response all show it, and passes only with its stages in order.
func TestOpenAIFileSearchStreamsAsRecorded(t *testing.T) {
	recorded, request := fileSearchExchange(t, "a streamed search")
	events := recorded.responsesStream(t)
	state := customerFileSearchState(t, request)
	state.Signals = &StandardSignals{Prompt: 10, Completion: 10}
	for sequence, event := range events {
		event.SequenceNumber = sequence
		if event.Response != nil {
			// The test deployment runs another model than the recording.
			event.Response.Model = state.Resolution.Deployment.Upstream.Model
		}
		if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}); err != nil {
			t.Fatalf("recorded event %s refused: %v", event.Type, err)
		}
	}
	if calls := state.loggedToolCalls(); len(calls) != 1 || calls[0].Type != "file_search_call" || calls[0].DoneAt.Before(calls[0].StartedAt) {
		t.Fatalf("logged calls = %+v, want one timed file search", calls)
	}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatal(err)
	}
	if got := fileSearchCalls(state.FinalMeters); got != "1" {
		t.Fatalf("file search calls = %q, want 1", got)
	}
	for _, skipped := range []schemas.ResponsesStreamResponseType{
		schemas.ResponsesStreamResponseTypeFileSearchCallInProgress,
		schemas.ResponsesStreamResponseTypeFileSearchCallSearching,
	} {
		t.Run("without "+string(skipped), func(t *testing.T) {
			state := customerFileSearchState(t, request)
			var kept []*schemas.BifrostResponsesStreamResponse
			for _, event := range recorded.responsesStream(t) {
				if event.Type != skipped {
					kept = append(kept, event)
				}
			}
			if err := replayLocalToolStream(state, kept); err == nil {
				t.Fatal("a file search stream out of order passed")
			}
		})
	}
}

// A search that ends without completing is not billed, as a web search that ends so is not.
func TestOpenAIFileSearchBillsOnlyCompletedSearches(t *testing.T) {
	recorded, request := fileSearchExchange(t, "a search")
	for status, want := range map[string]string{"completed": "1", "failed": "", "incomplete": ""} {
		t.Run(status, func(t *testing.T) {
			state := customerFileSearchState(t, request)
			reply := recorded.responsesReply(t)
			reply.Model = state.Resolution.Deployment.Upstream.Model
			reply.Output[0].Status = schemas.Ptr(status)
			state.Signals = &StandardSignals{Prompt: 10, Completion: 10}
			if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: reply}, nil); err != nil {
				t.Fatalf("reply refused: %v", err)
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatal(err)
			}
			if got := fileSearchCalls(state.FinalMeters); got != want {
				t.Fatalf("file search calls = %q, want %q", got, want)
			}
		})
	}
}

// A file citation, as a URL citation, belongs to a reply whose request lets the model search.
func TestOpenAIFileCitationsNeedFileSearch(t *testing.T) {
	recorded, request := fileSearchExchange(t, "a search")
	for choice, allowed := range map[string]bool{`"auto"`: true, `"none"`: false} {
		t.Run(choice, func(t *testing.T) {
			state := customerFileSearchState(t, changedRequest(t, request, func(body map[string]any) {
				body["tool_choice"] = json.RawMessage(choice)
			}))
			reply := recorded.responsesReply(t)
			reply.Model = state.Resolution.Deployment.Upstream.Model
			// The message alone, with its citation of the searched file.
			reply.Output = reply.Output[1:]
			state.Signals = &StandardSignals{Prompt: 10, Completion: 10}
			err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: reply}, nil)
			if (err == nil) != allowed {
				t.Fatalf("citation with tool_choice %s: %v", choice, err)
			}
		})
	}
}

// A search sent back reaches OpenAI with its results exactly as the reply gave them. One without
// its results names a stored reply's search, which OpenAI would read where no check can, so it
// goes, and the request passes where OpenAI would refuse it.
func TestOpenAIFileSearchCallsSentBack(t *testing.T) {
	_, request := fileSearchExchange(t, "a search sent back")
	var sent struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal([]byte(request), &sent); err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(fileSearchProviderBody(t, customerFileSearchState(t, request)), &wire); err != nil {
		t.Fatal(err)
	}
	// The search, and the reply that cites its file.
	for _, index := range []int{1, 2} {
		if len(wire.Input) != len(sent.Input) || !sameJSON(t, wire.Input[index], sent.Input[index]) {
			t.Fatalf("input[%d] sent as %s, want %s", index, wire.Input[index], sent.Input[index])
		}
	}

	// The recorded refusal of the same search without its results.
	if refused := exchange(t, providerCapture(t, "openai/file-search"), "a search sent back without its results"); refused.Response.Status != 404 {
		t.Fatalf("recorded status %d", refused.Response.Status)
	}
	withoutResults := changedRequest(t, request, func(body map[string]any) {
		delete(body["input"].([]any)[1].(map[string]any), "results")
	})
	if err := json.Unmarshal(fileSearchProviderBody(t, customerFileSearchState(t, withoutResults)), &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Input) != len(sent.Input)-1 || strings.Contains(fmt.Sprint(wire.Input), "file_search_call") {
		t.Fatalf("a search without its results reached OpenAI: %s", wire.Input)
	}

	// The gateway's replies drop the vector_store_id that OpenAI adds to each result, and a
	// result that holds one would lose it.
	withStore := changedRequest(t, request, func(body map[string]any) {
		results := body["input"].([]any)[1].(map[string]any)["results"].([]any)
		results[0].(map[string]any)["vector_store_id"] = ""
	})
	if _, err := customerRequestState(t, "responses", []byte(withStore)); err == nil || !strings.Contains(err.Error(), "vector_store_id") {
		t.Fatalf("a result with vector_store_id got %v", err)
	}
}

// Only OpenAI's own Responses API takes back a file citation, so Claude gets the reply without it.
// Core would send it as a citation of a document that Claude never saw.
func TestFileCitationsReachOnlyOpenAI(t *testing.T) {
	const reply = `"input":[{"role":"user","content":"Search the files: what is the capital of Zorbia?"},` +
		`{"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"The capital of Zorbia is Quillmont.",` +
		`"annotations":[{"type":"file_citation","file_id":"file-LL2wh1jbYJUxuAWkK8z1tJ","filename":"zorbia.txt","index":34}],"logprobs":[]}]},` +
		`{"role":"user","content":"And its national animal?"}]`
	body := string(fileSearchProviderBody(t, resolvedResponseValidationState(t, `{"model":"anthropic-claude-sonnet-4-6",`+reply+`}`)))
	if !strings.Contains(body, "The capital of Zorbia is Quillmont.") || strings.Contains(body, "zorbia.txt") || strings.Contains(body, "citations") {
		t.Fatalf("Claude got %s", body)
	}
	body = string(fileSearchProviderBody(t, resolvedResponseValidationState(t, `{"model":"provider:openai gpt-5.5",`+reply+`}`)))
	if !strings.Contains(body, `"file_id":"file-LL2wh1jbYJUxuAWkK8z1tJ"`) || !strings.Contains(body, `"filename":"zorbia.txt"`) {
		t.Fatalf("OpenAI got %s", body)
	}
	for name, annotation := range map[string]string{
		"without a file":     `{"type":"file_citation","filename":"zorbia.txt","index":34}`,
		"a negative index":   `{"type":"file_citation","file_id":"file-1","filename":"zorbia.txt","index":-1}`,
		"another field":      `{"type":"file_citation","file_id":"file-1","filename":"zorbia.txt","index":34,"url":"https://example.com"}`,
		"another annotation": `{"type":"file_path","file_id":"file-1","index":34}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := `{"model":"provider:openai gpt-5.5","input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[` +
				annotation + `]}]},{"role":"user","content":"continue"}]}`
			if err := customerRequestError(t, []byte(request)); err == nil {
				t.Fatalf("%s passed", annotation)
			}
		})
	}
	// A reply may cite a file whose name is empty, and the citation comes back as it was.
	unnamed := `{"model":"provider:openai gpt-5.5","input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[` +
		`{"type":"file_citation","file_id":"file-1","filename":"","index":0}]}]},{"role":"user","content":"continue"}]}`
	if err := customerRequestError(t, []byte(unnamed)); err != nil {
		t.Fatalf("a citation of a file without a name got %v", err)
	}
}

// The tool reaches OpenAI as the client sent it: ranking options, hybrid search and filters,
// including a comparison without a type, an operator that core does not name and a number that a
// float would round.
func TestOpenAIFileSearchToolReachesOpenAIExactly(t *testing.T) {
	_, recorded := fileSearchExchange(t, "ranking options and a filter")
	unusual := changedRequest(t, recorded, func(body map[string]any) {
		body["tools"].([]any)[0].(map[string]any)["filters"] = json.RawMessage(
			`{"type":"or","filters":[{"key":"version","value":9007199254740993},{"type":"contains","key":"tags","value":["a",1,true]}]}`)
	})
	for name, request := range map[string]string{"recorded": recorded, "unusual": unusual} {
		t.Run(name, func(t *testing.T) {
			var sent, wire struct {
				Tools []json.RawMessage `json:"tools"`
			}
			if err := json.Unmarshal([]byte(request), &sent); err != nil {
				t.Fatal(err)
			}
			body := fileSearchProviderBody(t, customerFileSearchState(t, request))
			if err := json.Unmarshal(body, &wire); err != nil {
				t.Fatal(err)
			}
			if len(wire.Tools) != 1 || !sameJSON(t, wire.Tools[0], sent.Tools[0]) {
				t.Fatalf("tool sent as %s, want %s", wire.Tools, sent.Tools[0])
			}
			if name == "unusual" && !strings.Contains(string(body), "9007199254740993") {
				t.Fatalf("filter value changed: %s", body)
			}
		})
	}
}

// Core rebuilds the tool, so a key that it drops, at any depth, or an empty filter type, which it
// leaves out, is refused, and its own parse refuses a value of the wrong kind or a filter without
// its parts. OpenAI's own rules on the values stay OpenAI's.
func TestOpenAIFileSearchRefusesWhatCoreWouldChange(t *testing.T) {
	tool := func(fields string) []byte {
		return []byte(`{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"file_search",` + fields + `}]}`)
	}
	for _, test := range []struct{ name, fields, want string }{
		{"an unknown key", `"vector_store_ids":["vs_1"],"max_results":2`, "tools[0].max_results is not supported"},
		{"an unknown ranking key", `"vector_store_ids":["vs_1"],"ranking_options":{"rank":"auto"}`, "tools[0].ranking_options.rank is not supported"},
		{"an unknown hybrid search key", `"vector_store_ids":["vs_1"],"ranking_options":{"hybrid_search":{"weight":1}}`, "tools[0].ranking_options.hybrid_search.weight is not supported"},
		{"a comparison with an unknown key", `"vector_store_ids":["vs_1"],"filters":{"type":"eq","key":"a","value":1,"case":true}`, "tools[0].filters.case is not supported"},
		{"a compound filter with a key", `"vector_store_ids":["vs_1"],"filters":{"type":"and","key":"a","filters":[{"key":"a","value":1}]}`, "tools[0].filters.key is not supported"},
		{"a nested comparison with an unknown key", `"vector_store_ids":["vs_1"],"filters":{"type":"and","filters":[{"type":"or","filters":[{"key":"a","value":1,"x":1}]}]}`, "tools[0].filters.filters[0].filters[0].x is not supported"},
		{"an empty filter type", `"vector_store_ids":["vs_1"],"filters":{"type":"","key":"a","value":1}`, "tools[0].filters.type must not be empty"},
		{"a vector store that is not a string", `"vector_store_ids":[1]`, "Invalid JSON body"},
		{"a fractional result count", `"vector_store_ids":["vs_1"],"max_num_results":2.5`, "Invalid JSON body"},
		{"a ranker that is not a string", `"vector_store_ids":["vs_1"],"ranking_options":{"ranker":1}`, "Invalid JSON body"},
		{"a compound filter of nothing", `"vector_store_ids":["vs_1"],"filters":{"type":"and","filters":[]}`, "Invalid JSON body"},
		{"a comparison without a value", `"vector_store_ids":["vs_1"],"filters":{"type":"eq","key":"a"}`, "Invalid JSON body"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := customerRequestError(t, tool(test.fields)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("want %q, got %v", test.want, err)
			}
		})
	}
	twice := []byte(`{"model":"provider:openai gpt-5.5","input":"hi","tools":[{"type":"file_search","vector_store_ids":["vs_1"]},{"type":"file_search","vector_store_ids":["vs_2"]}]}`)
	if _, err := customerRequestState(t, "responses", twice); err == nil {
		t.Fatal("two file search tools passed")
	}
}

// Only OpenAI's own Responses API runs file search, so the refusal for another deployment names
// the tool, before the vector stores that only OpenAI's and Azure's accounts could hold.
func TestOpenAIFileSearchRoutesOnlyToOpenAI(t *testing.T) {
	for _, model := range []string{"anthropic-claude-sonnet-4-6", "provider:azure gpt-5.5"} {
		body := `{"model":"` + model + `","input":"hi","tools":[{"type":"file_search","vector_store_ids":["vs_1"]}]}`
		if err := customerRequestError(t, []byte(body)); err == nil || !strings.Contains(err.Error(), "No deployment for this request runs file_search.") {
			t.Fatalf("%s: %v", model, err)
		}
	}
}

// tool_choice can force a search or allow it, but only for a declared file search tool.
func TestOpenAIFileSearchToolChoice(t *testing.T) {
	const declared = `"tools":[{"type":"file_search","vector_store_ids":["vs_1"]}]`
	for _, test := range []struct {
		name, fields string
		allowed      bool
	}{
		{"forced", declared + `,"tool_choice":{"type":"file_search"}`, true},
		{"allowed", declared + `,"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"file_search"}]}`, true},
		{"forced without the tool", `"tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"file_search"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := customerRequestState(t, "responses", []byte(`{"model":"provider:openai gpt-5.5","input":"hi",`+test.fields+`}`))
			if (err == nil) != test.allowed {
				t.Fatalf("tool_choice %s: %v", test.fields, err)
			}
		})
	}
}

// OpenAI adds its own instructions for the tool to the input, under tool_choice none too, and the
// hold takes them whatever tool_choice says.
func TestOpenAIFileSearchInstructionsHeld(t *testing.T) {
	recorded, declared := fileSearchExchange(t, "the tool under tool_choice none")
	_, bare := fileSearchExchange(t, "without the tool")
	held := heldInputTokensOf(t, customerFileSearchState(t, declared))
	without, _ := heldInputTokens(t, bare)
	var usage struct {
		Usage struct {
			InputTokens int64 `json:"input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(recorded.Response.Body, &usage); err != nil {
		t.Fatal(err)
	}
	if held < usage.Usage.InputTokens || held-without < 1483 {
		t.Fatalf("held %d with the tool and %d without it; OpenAI counted %d", held, without, usage.Usage.InputTokens)
	}
}

// The hold covers each search that max_tool_calls allows, which hosted tools share, with its fee
// and the content of one call, as web search does. A request that can search the web too holds
// the costlier search for every call.
func TestOpenAIFileSearchHold(t *testing.T) {
	for _, test := range []struct{ name, fields, meter, calls string }{
		{"at most two calls", `"tools":[{"type":"file_search","vector_store_ids":["vs_1"]}],"max_tool_calls":2`, MeterOpenAIResponsesFileSearchCalls, "2"},
		{"OpenAI's default", `"tools":[{"type":"file_search","vector_store_ids":["vs_1"]}]`, MeterOpenAIResponsesFileSearchCalls, strconv.Itoa(defaultResponsesHostedToolCalls)},
		{"with web search", `"tools":[{"type":"file_search","vector_store_ids":["vs_1"]},{"type":"web_search"}],"max_tool_calls":3`, MeterOpenAIResponsesWebSearchCalls, "3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := customerFileSearchState(t, `{"model":"provider:openai gpt-5.5","input":"hi",`+test.fields+`}`)
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatal(err)
			}
			meter := findMeterEstimate(state.Hold.Meters, test.meter)
			if meter == nil || meter.Quantity != test.calls || !meter.HoldRequired {
				t.Fatalf("search hold %+v in %+v, want %s calls of %s", meter, state.Hold.Meters, test.calls, test.meter)
			}
			if test.meter != MeterOpenAIResponsesFileSearchCalls && findMeterEstimate(state.Hold.Meters, MeterOpenAIResponsesFileSearchCalls) != nil {
				t.Fatalf("both searches held: %+v", state.Hold.Meters)
			}
			calls, _ := strconv.Atoi(test.calls)
			estimate, _ := state.Resolution.EstimatedInputTokens()
			if findMeterEstimateQuantity(state.Hold.Meters, billing.MeterInputTokens, strconv.Itoa(estimate+calls*hostedCallContentTokens)) == nil {
				t.Fatalf("input hold %+v, want %d plus %d calls of content", state.Hold.Meters, estimate, calls)
			}
		})
	}
}
