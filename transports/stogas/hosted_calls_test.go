package stogas

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

// openAISearchCall is a web search as OpenAI returns it, which Codex sends back as it is.
const openAISearchCall = `{"type":"web_search_call","id":"ws_68f0c2a1b3d4e5f6","status":"completed",` +
	`"action":{"type":"search","query":"bifrost gateway","queries":["bifrost gateway"],"sources":[{"type":"url","url":"https://example.com/a"}]}}`

// claudeSearchCall is a web search as Claude returns it through the gateway, with the encrypted
// content of its result.
const claudeSearchCall = `{"type":"web_search_call","id":"srvtoolu_01ws","call_id":"srvtoolu_01ws","status":"completed",` +
	`"action":{"type":"search","query":"bifrost gateway","queries":["bifrost gateway"],` +
	`"sources":[{"type":"url","url":"https://example.com/a","title":"A","encrypted_content":"EqQBresult","page_age":"2 days ago"}]}}`

// claudeFetchCall is a web fetch as Claude returns it through the gateway, with the page it got.
const claudeFetchCall = `{"type":"web_fetch_call","id":"srvtoolu_01wf","call_id":"srvtoolu_01wf","status":"completed",` +
	`"action":{"type":"fetch","url":"https://example.com/a"},"web_fetch_result_type":"web_fetch_result",` +
	`"web_fetch_result_url":"https://example.com/a","web_fetch_retrieved_at":"2026-11-16T01:00:00Z",` +
	`"web_fetch_document":{"type":"document","title":"A","source":{"type":"text","media_type":"text/plain","data":"Page text."}}}`

func hostedCallConversation(model string, calls ...string) string {
	return `{"model":"` + model + `","input":[{"role":"user","content":"Search for the gateway."},` + strings.Join(calls, ",") +
		`,{"type":"message","role":"assistant","content":[{"type":"output_text","text":"It routes requests.","annotations":[]}]},` +
		`{"role":"user","content":"Tell me more."}]}`
}

// A conversation can move between providers after a web search: each deployment gets only the
// calls that its own provider made and reads, on a route that runs the tool, and the rest of the
// history stays.
func TestHostedCallsGoOnlyToTheProviderThatReadsThem(t *testing.T) {
	request := hostedCallConversation("provider:openai gpt-5.5", claudeSearchCall, openAISearchCall, claudeFetchCall)
	body, _, _ := providerBody(t, "/v1/responses", request)
	if input := string(body["input"]); !strings.Contains(input, `"id":"ws_68f0c2a1b3d4e5f6"`) ||
		!strings.Contains(input, `"status":"completed"`) || strings.Contains(input, "srvtoolu_") {
		t.Fatalf("OpenAI input = %s", input)
	}

	body, _, _ = providerBody(t, "/v1/responses", strings.Replace(request, "provider:openai gpt-5.5", "anthropic-claude-sonnet-4-6", 1))
	got := blockFields(assistantBlocks(t, body)[0], "type", "id", "name", "input", "tool_use_id", "content", "text")
	want := strings.Join([]string{
		`type="server_tool_use" id="srvtoolu_01ws" name="web_search" input={"query":"bifrost gateway"}`,
		`type="web_search_tool_result" tool_use_id="srvtoolu_01ws" content=[{"type":"web_search_result","title":"A","url":"https://example.com/a","encrypted_content":"EqQBresult","page_age":"2 days ago"}]`,
		`type="server_tool_use" id="srvtoolu_01wf" name="web_fetch" input={"url":"https://example.com/a"}`,
		`type="web_fetch_tool_result" tool_use_id="srvtoolu_01wf" content={"type":"web_fetch_result","content":{"type":"document","source":{"type":"text","media_type":"text/plain","data":"Page text."},"title":"A"},"url":"https://example.com/a","retrieved_at":"2026-11-16T01:00:00Z"}`,
		`type="text" text="It routes requests."`,
	}, "\n")
	if got != want {
		t.Fatalf("Claude assistant blocks =\n%s\nwant\n%s", got, want)
	}

	// Codex keeps only the query of a search, which Claude cannot read back.
	codexSearch := `{"type":"web_search_call","id":"srvtoolu_01ws","status":"completed","action":{"type":"search","query":"bifrost gateway"}}`
	body, _, _ = providerBody(t, "/v1/responses", hostedCallConversation("anthropic-claude-sonnet-4-6", codexSearch))
	if got := blockFields(assistantBlocks(t, body)[0], "type"); got != `type="text"` {
		t.Fatalf("Claude assistant blocks for a search without results = %s", got)
	}

	// Azure's route runs no hosted tool.
	body, _, _ = providerBody(t, "/v1/responses", strings.Replace(request, "provider:openai gpt-5.5", "azure-gpt-5.5-2026-04-23", 1))
	if input := string(body["input"]); strings.Contains(input, "web_search_call") || strings.Contains(input, "web_fetch_call") {
		t.Fatalf("Azure input = %s", input)
	}
}

// OpenAI gets each recorded search that it took back as it took it, and none that it refused.
func TestRecordedSearchReplaysReachOpenAIAsTheyWereTaken(t *testing.T) {
	capture := providerCapture(t, "openai/web-search-call-replay")
	for _, name := range []string{"search as Codex sends it back", "search with sources", "search with Claude's ID"} {
		recorded := exchange(t, capture, name)
		var fields struct {
			Input []map[string]any `json:"input"`
		}
		if err := json.Unmarshal(recorded.Request.Body, &fields); err != nil {
			t.Fatal(err)
		}
		input, _ := json.Marshal(fields.Input)
		body, _, _ := providerBody(t, "/v1/responses", `{"model":"provider:openai gpt-5.5","store":false,"input":`+string(input)+`}`)
		var sent []map[string]any
		if err := json.Unmarshal(body["input"], &sent); err != nil {
			t.Fatal(err)
		}
		searches := slices.DeleteFunc(slices.Clone(sent), func(item map[string]any) bool { return item["type"] != "web_search_call" })
		switch {
		case recorded.Response.Status == 200 && (len(searches) != 1 || !reflect.DeepEqual(searches[0], fields.Input[1])):
			t.Fatalf("%s: OpenAI took %v, the gateway sends %v", name, fields.Input[1], searches)
		case recorded.Response.Status != 200 && len(searches) != 0:
			t.Fatalf("%s: OpenAI refused the search, the gateway sends %v", name, searches)
		}
	}
}

func TestHostedCallInputChecks(t *testing.T) {
	call := func(item string) string {
		return `{"model":"provider:openai gpt-5.5","input":[{"role":"user","content":"hi"},` + item + `]}`
	}
	for _, tc := range []struct{ name, item, want string }{
		{"no id", `{"type":"web_search_call","status":"completed"}`, "input[1].id is required"},
		{"unknown status", `{"type":"web_search_call","id":"ws_a1","status":"done"}`, "input[1].status is not supported"},
		{"unknown key", `{"type":"web_search_call","id":"ws_a1","status":"completed","results":[]}`, "input[1].results is not supported"},
		{"action not an object", `{"type":"web_search_call","id":"ws_a1","status":"completed","action":"search"}`, "input[1].action must be an object"},
		{"action without type", `{"type":"web_search_call","id":"ws_a1","status":"completed","action":{"query":"q"}}`, "input[1].action.type is required"},
		{"unknown source key", `{"type":"web_search_call","id":"ws_a1","status":"completed","action":{"type":"search","sources":[{"type":"url","url":"https://a.example","snippet":"s"}]}}`, "input[1].action.sources[0].snippet is not supported"},
		{"caller in code execution", `{"type":"web_search_call","id":"srvtoolu_01","status":"completed","tool_caller":{"type":"code_execution_20260120"}}`, "input[1].tool_caller.type must be direct"},
		{"fetch document text", `{"type":"web_fetch_call","id":"srvtoolu_01","status":"completed","web_fetch_document":{"type":"document","text":"t"}}`, "input[1].web_fetch_document.text is not supported"},
		{"fetch result on a search", `{"type":"web_search_call","id":"ws_a1","status":"completed","web_fetch_result_type":"web_fetch_result"}`, "input[1].web_fetch_result_type is not supported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateResolvedResponses(t, call(tc.item)); err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// A hosted call is the provider's own step, so it can sit between client calls and their outputs,
// and a system message can follow a server tool result that ends Claude's turn.
func TestHostedCallsTakeTheirPlaceInTurns(t *testing.T) {
	interleaved := `{"model":"provider:openai gpt-5.5",` + weatherTool + `,"input":[{"role":"user","content":"Weather in Paris?"},` +
		`{"type":"function_call","call_id":"call_1","name":"get_weather","arguments":"{\"city\":\"Paris\"}"},` + openAISearchCall +
		`,{"type":"function_call_output","call_id":"call_1","output":"18 C"}]}`
	if err := validateResolvedResponses(t, interleaved); err != nil {
		t.Fatalf("search between a call and its output: %v", err)
	}
	afterSearch := `{"model":"anthropic-claude-opus-4-8","input":[{"role":"user","content":"Search."},` + claudeSearchCall +
		`,{"role":"developer","content":"Cite every source."}]}`
	if err := validateResolvedResponses(t, afterSearch); err != nil {
		t.Fatalf("system message after a server tool result: %v", err)
	}
	// A call that Claude does not read never reaches it, so a system message after the call
	// follows the assistant's message, where Claude takes none.
	for _, call := range []string{openAISearchCall, `{"type":"file_search_call","id":"fs_1","status":"completed","queries":["gateway"]}`} {
		afterDroppedCall := `{"model":"anthropic-claude-opus-4-8","input":[{"role":"user","content":"Search."},` +
			`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Found it.","annotations":[]}]},` + call +
			`,{"role":"developer","content":"Cite every source."}]}`
		if err := validateResolvedResponses(t, afterDroppedCall); err == nil ||
			!strings.Contains(err.Error(), "input[3].role must immediately follow a user message or tool result") {
			t.Fatalf("system message after %s: %v", call, err)
		}
	}
}

// Redaction leaves Claude's encrypted search results as Claude returned them, since Claude refuses
// changed ones, and redacts the text that the provider reads plainly.
func TestRedactionKeepsClaudeSearchResults(t *testing.T) {
	policy, err := redaction.CompilePolicy(redaction.Options{Patterns: []redaction.Pattern{redaction.PatternEmailAddress}})
	if err != nil {
		t.Fatal(err)
	}
	search := strings.NewReplacer(`"title":"A"`, `"title":"Mail owner@corp.io"`, `"EqQBresult"`, `"cipher@corp.io"`).Replace(claudeSearchCall)
	body, _, _ := providerBodyOf(t, catalog.RequestInput{Method: "POST", Path: "/v1/responses", RedactionPolicy: policy,
		Body: []byte(hostedCallConversation("anthropic-claude-sonnet-4-6", search))})
	messages := string(body["messages"])
	if !strings.Contains(messages, `"encrypted_content":"cipher@corp.io"`) || strings.Contains(messages, "owner@corp.io") {
		t.Fatalf("Claude messages = %s", messages)
	}
}

// A Claude turn that searches, streamed as Anthropic streams it. The query can come in the
// search's first event or after it, as Anthropic's example of a streamed search shows.
func claudeSearchTurnStream(queryFirst bool) []string {
	start := `{"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","id":"srvtoolu_01ws","name":"web_search","input":{"query":"bifrost gateway"}}}`
	query := []string{start}
	if !queryFirst {
		query = []string{strings.Replace(start, `{"query":"bifrost gateway"}`, "{}", 1),
			`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"bifrost gateway\"}"}}`}
	}
	return slices.Concat([]string{
		`{"type":"message_start","message":{"id":"msg_01search","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":1}}}`,
	}, query, []string{
		`{"type":"content_block_stop","index":0}`,
		`{"type":"content_block_start","index":1,"content_block":{"type":"web_search_tool_result","tool_use_id":"srvtoolu_01ws","content":[{"type":"web_search_result","url":"https://example.com/a","title":"A","encrypted_content":"EqQBresult","page_age":"2 days ago"}]}}`,
		`{"type":"content_block_stop","index":1}`,
		`{"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"It routes requests."}}`,
		`{"type":"content_block_stop","index":2}`,
		`{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":20,"server_tool_use":{"web_search_requests":1}}}`,
		`{"type":"message_stop"}`,
	})
}

// A Responses client gets Claude's search as a web_search_call item that passes the gateway's
// checks of the reply, and the next request sends it back to Anthropic as Claude returned it.
func TestClaudeSearchRoundTripsThroughResponses(t *testing.T) {
	for _, queryFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "query first", false: "query streamed"}[queryFirst], func(t *testing.T) {
			claudeSearchRoundTrip(t, claudeSearchTurnStream(queryFirst))
		})
	}
}

func claudeSearchRoundTrip(t *testing.T, stream []string) {
	request := `{"model":"anthropic-claude-sonnet-4-6","max_output_tokens":2048,"stream":true,"tools":[{"type":"web_search"}],` +
		`"input":[{"role":"user","content":"Search for the gateway."}]}`
	_, ctx, state := providerBody(t, "/v1/responses", request)
	streamState := anthropic.AcquireAnthropicResponsesStreamState()
	defer anthropic.ReleaseAnthropicResponsesStreamState(streamState)
	var output []schemas.ResponsesMessage
	sequence := 0
	for _, line := range stream {
		var event anthropic.AnthropicStreamEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		chunks, bifrostErr, _ := event.ToBifrostResponsesStream(ctx, sequence, streamState)
		if bifrostErr != nil {
			t.Fatalf("convert %s: %v", event.Type, bifrostErr.Error)
		}
		for _, chunk := range chunks {
			if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: chunk}); err != nil {
				t.Fatalf("ingest %s: %v", chunk.Type, err)
			}
			if chunk.Type == schemas.ResponsesStreamResponseTypeCompleted {
				output = chunk.Response.Output
			}
		}
		sequence += len(chunks)
	}
	items := make([]string, 0, len(output))
	for _, item := range output {
		encoded, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, string(encoded))
	}
	next := `{"model":"anthropic-claude-sonnet-4-6","max_output_tokens":2048,"tools":[{"type":"web_search"}],` +
		`"input":[{"role":"user","content":"Search for the gateway."},` + strings.Join(items, ",") + `,{"role":"user","content":"Tell me more."}]}`
	body, _, _ := providerBody(t, "/v1/responses", next)
	got := blockFields(assistantBlocks(t, body)[0], "type", "id", "name", "input", "tool_use_id", "content", "text")
	want := strings.Join([]string{
		`type="server_tool_use" id="srvtoolu_01ws" name="web_search" input={"query":"bifrost gateway"}`,
		`type="web_search_tool_result" tool_use_id="srvtoolu_01ws" content=[{"type":"web_search_result","title":"A","url":"https://example.com/a","encrypted_content":"EqQBresult","page_age":"2 days ago"}]`,
		`type="text" text="It routes requests."`,
	}, "\n")
	if got != want {
		t.Fatalf("output %s\ncame back as\n%s\nwant\n%s", strings.Join(items, "\n"), got, want)
	}
}
