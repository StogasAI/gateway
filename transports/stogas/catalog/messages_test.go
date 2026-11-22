package catalog

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// Claude Code sends its whole set of anthropic-beta values on every request, and Anthropic's SDKs
// send the value of each field that needs one, such as fast-mode-2026-02-01 with speed. The route
// carries the values that change what a hosting does, once each, and refuses any other value with
// the token that Claude Code's recovery reads before it sends the request again without the value.
func TestMessagesBetas(t *testing.T) {
	carried, err := MessagesBetas([]string{
		"claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,advanced-tool-use-2025-11-20",
		" effort-2025-11-24 , claude-code-20250219,thinking-token-count-2026-05-13",
		"fast-mode-2026-02-01,compact-2026-01-12",
		"",
	})
	want := []string{"claude-code-20250219", "interleaved-thinking-2025-05-14", "thinking-token-count-2026-05-13"}
	if err != nil || !reflect.DeepEqual(carried, want) {
		t.Fatalf("carried = %v, err = %v, want %v", carried, err, want)
	}

	_, err = MessagesBetas([]string{"claude-code-20250219,context-1m-2025-08-07"})
	var refusal APIError
	if !errors.As(err, &refusal) || refusal.StatusCode != 400 || refusal.Code != "unsupported_request" ||
		refusal.Message != "capability_rejected: beta_header:context-1m-2025-08-07" {
		t.Fatalf("refusal = %#v", err)
	}
}

func messagesFields(t *testing.T, body string) map[string]json.RawMessage {
	t.Helper()
	fields, err := DecodeRequestBody([]byte(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	return fields
}

// A Messages body that Anthropic's API would refuse gets Anthropic's words, which name the field,
// so that Claude Code can tell which capability to leave out.
func TestMessagesRefusalsUseAnthropicsWords(t *testing.T) {
	const message = `"messages":[{"role":"user","content":"hi"}]`
	for _, test := range []struct {
		name, body, want string
	}{
		{"an unknown field", `{"model":"m","max_tokens":1,` + message + `,"betas":[]}`,
			"betas: Extra inputs are not permitted"},
		{"an unknown field in a block",
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"hi","priority":1}]}]}`,
			"messages.0.content.0.priority: Extra inputs are not permitted"},
		{"an unknown block type",
			`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"container_upload","file_id":"f"}]}]}`,
			"messages.0.content.0: Input tag 'container_upload' found using 'type' does not match any of the expected tags: "},
		{"an unknown tool type", `{"model":"m","max_tokens":1,` + message + `,"tools":[{"type":"memory_20250818","name":"memory"}]}`,
			"tools.0: Input tag 'memory_20250818' found using 'type' does not match any of the expected tags: "},
		{"a value of another kind", `{"model":"m","max_tokens":"1",` + message + `}`, "max_tokens: Input should be a valid integer"},
		{"no output token limit", `{"model":"m",` + message + `}`, "max_tokens: Field required"},
		{"thinking without its signature",
			`{"model":"m","max_tokens":1,"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"a"}]}]}`,
			"messages.0.content.0.signature: Field required"},
		{"Priority Tier", `{"model":"m","max_tokens":1,` + message + `,"service_tier":"priority"}`,
			"service_tier: Input should be 'auto' or 'standard_only'"},
		{"MCP connectors", `{"model":"m","max_tokens":1,` + message + `,"mcp_servers":[{"type":"url","url":"https://example.com","name":"x"}]}`,
			"Anthropic MCP connectors are not supported"},
	} {
		_, _, err := messagesToResponses([]byte(test.body), messagesFields(t, test.body))
		var refusal APIError
		if !errors.As(err, &refusal) || refusal.StatusCode != 400 || !strings.HasPrefix(refusal.Message, test.want) {
			t.Errorf("%s: %v, want %q", test.name, err, test.want)
		}
	}
}

// Claude Code sends Claude Opus 4.5 a thinking budget with an effort, Claude Sonnet 4.5 and Haiku
// 4.5 a budget alone, and newer models adaptive thinking with an effort (Claude Code 2.1.330). The
// checks read each as sent, with no effort that the client did not send.
func TestMessagesReasoningKeepsClaudeCodesControls(t *testing.T) {
	omitted := schemas.Ptr("none")
	for _, test := range []struct {
		name, fields string
		want         schemas.ResponsesParametersReasoning
	}{
		{"a budget", `"thinking":{"type":"enabled","budget_tokens":31999,"display":"omitted"}`,
			schemas.ResponsesParametersReasoning{MaxTokens: schemas.Ptr(31999), Summary: omitted}},
		{"a budget with an effort", `"thinking":{"type":"enabled","budget_tokens":31999,"display":"omitted"},"output_config":{"effort":"high"}`,
			schemas.ResponsesParametersReasoning{Effort: schemas.Ptr("high"), MaxTokens: schemas.Ptr(31999), Summary: omitted}},
		{"adaptive thinking with an effort", `"thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"high"}`,
			schemas.ResponsesParametersReasoning{Effort: schemas.Ptr("high"), Summary: omitted}},
	} {
		body := `{"model":"m","max_tokens":32000,"messages":[{"role":"user","content":"hi"}],` + test.fields + `}`
		responses, _, err := messagesToResponses([]byte(body), messagesFields(t, body))
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		var got schemas.ResponsesParametersReasoning
		if err := json.Unmarshal(responses["reasoning"], &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: reasoning = %s, want %+v", test.name, responses["reasoning"], test.want)
		}
	}
}

// speed chooses the tier as service_tier does on the other routes, and Anthropic's own
// service_tier values leave the tier to the model and speed.
func TestMessagesSpeedChoosesTheTier(t *testing.T) {
	for _, test := range []struct{ fields, want string }{
		{``, ``},
		{`,"speed":"fast"`, `"fast"`},
		{`,"speed":"standard"`, `"standard"`},
		{`,"speed":"standard","service_tier":"standard_only"`, `"standard"`},
		{`,"service_tier":"auto"`, ``},
	} {
		body := `{"model":"m","max_tokens":16,"messages":[{"role":"user","content":"hi"}]` + test.fields + `}`
		responses, _, err := messagesToResponses([]byte(body), messagesFields(t, body))
		if err != nil || string(responses["service_tier"]) != test.want {
			t.Errorf("%s: service_tier = %s, err = %v, want %s", test.fields, responses["service_tier"], err, test.want)
		}
	}
	for _, fields := range []string{`"speed":"turbo"`, `"service_tier":"priority"`} {
		body := `{"model":"m","max_tokens":16,"messages":[{"role":"user","content":"hi"}],` + fields + `}`
		if _, _, err := messagesToResponses([]byte(body), messagesFields(t, body)); err == nil {
			t.Errorf("%s was taken", fields)
		}
	}
}

// A deployment with both of Claude's controls keeps an effort beside a budget, and a deployment
// with one keeps the one that it has.
func TestNormalizeMessagesReasoning(t *testing.T) {
	budgets := &ReasoningMaxTokens{Minimum: 1024, Maximum: 64000}
	efforts := []string{"low", "medium", "high"}
	for _, test := range []struct {
		name       string
		deployment Deployment
		want       schemas.ResponsesParametersReasoning
	}{
		{"both controls", Deployment{Reasoning: "optional", ReasoningMaxTokens: budgets, ReasoningEfforts: efforts},
			schemas.ResponsesParametersReasoning{Effort: schemas.Ptr("high"), MaxTokens: schemas.Ptr(31999)}},
		{"budgets alone", Deployment{Reasoning: "optional", ReasoningMaxTokens: budgets},
			schemas.ResponsesParametersReasoning{MaxTokens: schemas.Ptr(31999)}},
		{"efforts alone", Deployment{Reasoning: "optional", ReasoningEfforts: efforts},
			schemas.ResponsesParametersReasoning{Effort: schemas.Ptr("high")}},
	} {
		reasoning := schemas.ResponsesParametersReasoning{Effort: schemas.Ptr("high"), MaxTokens: schemas.Ptr(31999)}
		if err := normalizeMessagesReasoning(&reasoning, test.deployment, 32000); err != nil || !reflect.DeepEqual(reasoning, test.want) {
			t.Errorf("%s: %+v, err = %v, want %+v", test.name, reasoning, err, test.want)
		}
	}
}
