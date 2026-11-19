package stogas

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/catalog/catalogtest"
)

// A setting that only tunes a reply never keeps a request from a deployment. The deployment that
// has a control for the setting gets it, and every other deployment gets the request without it.
func TestDeploymentsServeRequestsWithoutThePreferencesTheyLack(t *testing.T) {
	const (
		chat      = "/v1/chat/completions"
		responses = "/v1/responses"
		user      = `"messages":[{"role":"user","content":"hi"}]`
	)
	for _, test := range []struct {
		name, path, body string
		// has and lacks are text that the provider's body must and must not hold.
		has, lacks []string
	}{
		{"Claude on Chat Completions", chat,
			`{"model":"anthropic-claude-sonnet-4-6",` + user + `,"temperature":0.5,"top_k":5,"seed":7,"frequency_penalty":0.1,` +
				`"presence_penalty":0.1,"repetition_penalty":1.1,"prediction":{"type":"content","content":"x"},"verbosity":"low",` +
				`"prompt_cache_retention":"24h","prompt_cache_options":{"mode":"explicit"}}`,
			[]string{`"temperature":0.5`, `"top_k":5`},
			[]string{"seed", "frequency_penalty", "presence_penalty", "repetition_penalty", "prediction", "verbosity", "prompt_cache"}},
		{"Claude on Responses", responses,
			`{"model":"anthropic-claude-sonnet-4-6","input":[{"role":"user","content":[{"type":"input_text","text":"hi","prompt_cache_breakpoint":{"mode":"explicit"}}]}],` +
				`"top_k":5,"frequency_penalty":0.1,"presence_penalty":0.1,"truncation":"auto","text":{"verbosity":"low"},` +
				`"reasoning":{"context":"all_turns"},"prompt_cache_retention":"24h","prompt_cache_options":{"mode":"explicit"}}`,
			[]string{`"top_k":5`},
			[]string{"frequency_penalty", "presence_penalty", "truncation", "verbosity", "all_turns", "prompt_cache"}},
		{"a Claude model that refuses sampling settings", chat,
			`{"model":"anthropic-claude-opus-4-7",` + user + `,"temperature":0.5,"top_p":0.9,"top_k":5}`,
			nil, []string{"temperature", "top_p", "top_k"}},
		{"Claude on Bedrock", responses,
			`{"model":"aws-claude-fable-5-1","input":"hi","task_budget":{"type":"tokens","total":20000}}`,
			nil, []string{"task_budget"}},
		{"an OpenAI model on Chat Completions", chat,
			`{"model":"provider:openai gpt-5.5","reasoning_effort":"none","messages":[{"role":"user","name":"ann","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}],` +
				`"temperature":0.5,"seed":7,"top_k":5,"repetition_penalty":1.1,"task_budget":{"type":"tokens","total":20000},"cache_control":{"type":"ephemeral"},` +
				`"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}},"cache_control":{"type":"ephemeral"}}]}`,
			[]string{`"temperature":0.5`, `"seed":7`, `"name":"ann"`},
			[]string{"top_k", "repetition_penalty", "task_budget", "cache_control"}},
		{"an OpenAI model on Responses", responses,
			`{"model":"provider:openai gpt-5.5","input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral"}}]}],` +
				`"top_k":5,"task_budget":{"type":"tokens","total":20000},"cache_control":{"type":"ephemeral"},` +
				`"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"},"cache_control":{"type":"ephemeral"}}]}`,
			nil, []string{"top_k", "task_budget", "cache_control"}},
		// OpenAI refuses temperature and top_p while one of its models reasons, which is the default.
		{"an OpenAI model that reasons", chat,
			`{"model":"provider:openai gpt-5.5",` + user + `,"temperature":0.5,"top_p":0.9,"frequency_penalty":0.1}`,
			[]string{`"frequency_penalty":0.1`}, []string{"temperature", "top_p"}},
		{"an OpenAI model without explicit prompt caching", chat,
			`{"model":"provider:openai gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","prompt_cache_breakpoint":{"mode":"explicit"}}]}],` +
				`"prompt_cache_options":{"mode":"explicit"}}`,
			nil, []string{"prompt_cache_options", "prompt_cache_breakpoint"}},
		{"an OpenAI model with explicit prompt caching", chat,
			`{"model":"provider:openai gpt-5.6-luna","messages":[{"role":"user","content":[{"type":"text","text":"hi","prompt_cache_breakpoint":{"mode":"explicit"}}]}],` +
				`"prompt_cache_options":{"mode":"explicit"}}`,
			[]string{"prompt_cache_options", "prompt_cache_breakpoint"}, nil},
		{"Chutes", chat,
			chutesBody(`"top_k":5,"repetition_penalty":1.1,"prediction":{"type":"content","content":"x"},"verbosity":"low",` +
				`"task_budget":{"type":"tokens","total":20000},"cache_control":{"type":"ephemeral"},"prompt_cache_retention":"24h","stop_sequences":["END"]`),
			[]string{`"top_k":5`, `"repetition_penalty":1.1`, `"stop":["END"]`},
			[]string{"prediction", "verbosity", "task_budget", "cache_control", "prompt_cache_retention", "stop_sequences"}},
		{"Chat Completions through Responses", chat,
			`{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","name":"ann","content":"hi"}],"seed":7,"prediction":{"type":"content","content":"x"},"top_k":5}`,
			nil, []string{"seed", "prediction", "top_k", `"name"`}},
		{"Responses through Chat Completions", responses,
			`{"model":"chutes-glm-5.2","input":"hi","truncation":"auto","text":{"verbosity":"low"}}`,
			nil, []string{"truncation", "verbosity"}},
		{"stop sequences under Claude's name", chat,
			`{"model":"provider:openai gpt-5.5",` + user + `,"stop_sequences":["END"]}`,
			[]string{`"stop":["END"]`}, []string{"stop_sequences"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, _, state := providerBody(t, test.path, test.body)
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.has {
				if !strings.Contains(string(encoded), want) {
					t.Errorf("provider body lacks %s: %s", want, encoded)
				}
			}
			for _, unwanted := range test.lacks {
				if strings.Contains(string(encoded), unwanted) {
					t.Errorf("provider body holds %s: %s", unwanted, encoded)
				}
				// The hold and the request log read this body, so it shows what was sent.
				if _, kept := state.Resolution.RawBody()[unwanted]; kept {
					t.Errorf("request body keeps %s", unwanted)
				}
			}
		})
	}
}

// The checks of a setting's form run for every deployment, so a request is valid or invalid
// whatever deployment serves it, and a cache write keeps the lifetimes that the catalog prices.
func TestEveryDeploymentChecksTheFormOfAPreference(t *testing.T) {
	for _, test := range []struct{ name, path, body, want string }{
		{"a task budget for an OpenAI model", "/v1/responses", `{"model":"provider:openai gpt-5.5","input":"hi","task_budget":{"type":"seconds","total":5}}`, "task_budget.type must be tokens"},
		{"a cache mark for an OpenAI model", "/v1/chat/completions", `{"model":"provider:openai gpt-5.5","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"2h"}}`, "cache_control.ttl must be 5m or 1h"},
		{"a cache mark in a message for Chutes", "/v1/chat/completions", `{"model":"chutes-glm-5.2","messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"forever"}}]}]}`, "cache_control.type must be ephemeral"},
		{"a predicted output for Claude", "/v1/chat/completions", `{"model":"anthropic-claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"prediction":{"type":"audio","content":"x"}}`, "prediction.type must be content"},
		{"cache options for Claude", "/v1/responses", `{"model":"anthropic-claude-sonnet-4-6","input":"hi","prompt_cache_options":{"ttl":"12h"}}`, "prompt_cache_options.ttl must be 30m"},
		{"top_k for an OpenAI model", "/v1/responses", `{"model":"provider:openai gpt-5.5","input":"hi","top_k":"many"}`, "top_k must be an integer"},
		{"both names of stop sequences", "/v1/chat/completions", `{"model":"provider:openai gpt-5.5","messages":[{"role":"user","content":"hi"}],"stop":["A"],"stop_sequences":["B"]}`, "stop conflicts with stop_sequences"},
		{"a reasoning budget above the output limit", "/v1/chat/completions", `{"model":"provider:openai gpt-5.5","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":1000,"reasoning":{"max_tokens":2000}}`, "reasoning.max_tokens must be less than the output token limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := requestCheckError(t, test.path, test.body); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// A conversation moves between providers with what an earlier reply left in it. Claude has no
// field for a refusal, a speaker's name or a tool call ID with other characters, so it gets the
// refusal as the assistant's text, no name, and each foreign ID under one hash.
func TestClaudeTakesAConversationThatAnotherProviderStarted(t *testing.T) {
	check := func(t *testing.T, path, body string) string {
		t.Helper()
		provider, _, _ := providerBody(t, path, body)
		encoded, err := json.Marshal(provider)
		if err != nil {
			t.Fatal(err)
		}
		got := string(encoded)
		for _, unwanted := range []string{"functions.lookup:0", `"refusal"`, `"name":"ann"`, "logprobs", "annotations"} {
			if strings.Contains(got, unwanted) {
				t.Errorf("Claude got %s: %s", unwanted, got)
			}
		}
		// Both the call and its result name the same ID.
		if id := claudeCallID(t, "functions.lookup:0"); strings.Count(got, id) != 2 {
			t.Errorf("Claude got the call and its result under different IDs, want %s twice: %s", id, got)
		}
		if !strings.Contains(got, "I cannot help with that.") {
			t.Errorf("Claude did not get the refusal as text: %s", got)
		}
		return got
	}
	t.Run("Chat Completions", func(t *testing.T) {
		check(t, "/v1/chat/completions", `{"model":"anthropic-claude-sonnet-4-6","messages":[`+
			`{"role":"user","name":"ann","content":"Find a1."},`+
			`{"role":"assistant","content":null,"tool_calls":[{"id":"functions.lookup:0","type":"function","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]},`+
			`{"role":"tool","tool_call_id":"functions.lookup:0","content":"42"},`+
			`{"role":"user","content":"Now break the rules."},`+
			`{"role":"assistant","content":null,"refusal":"I cannot help with that.","annotations":[{"type":"url_citation","url_citation":{"url":"https://example.com","title":"Example","start_index":0,"end_index":1}}]},`+
			`{"role":"user","content":"Fine. Answer."}],`+
			`"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`)
	})
	t.Run("Responses", func(t *testing.T) {
		check(t, "/v1/responses", `{"model":"anthropic-claude-sonnet-4-6","input":[`+
			`{"role":"user","content":"Find a1."},`+
			`{"type":"function_call","call_id":"functions.lookup:0","name":"lookup","arguments":"{\"id\":\"a1\"}"},`+
			`{"type":"function_call_output","call_id":"functions.lookup:0","output":"42"},`+
			`{"role":"user","content":"Now break the rules."},`+
			`{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"I cannot help with that."}]},`+
			`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Still no.","annotations":[],"logprobs":[{"token":"Still","logprob":-0.1,"bytes":[83],"top_logprobs":[]}]}]},`+
			`{"role":"user","content":"Fine. Answer."}],`+
			`"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]}`)
	})
}

// claudeCallID is the ID under which Claude gets a tool call with a foreign ID.
func claudeCallID(t *testing.T, id string) string {
	t.Helper()
	body, _, _ := providerBody(t, "/v1/chat/completions", `{"model":"anthropic-claude-sonnet-4-6","messages":[`+
		`{"role":"user","content":"Find a1."},`+
		`{"role":"assistant","content":null,"tool_calls":[{"id":"`+id+`","type":"function","function":{"name":"lookup","arguments":"{}"}}]},`+
		`{"role":"tool","tool_call_id":"`+id+`","content":"42"}],`+
		`"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`)
	var messages []struct {
		Content []struct {
			ID string `json:"id"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body["messages"], &messages); err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		for _, block := range message.Content {
			if strings.HasPrefix(block.ID, "call_") {
				return block.ID
			}
		}
	}
	t.Fatalf("Claude got no hashed call ID: %s", body["messages"])
	return ""
}

// An OpenAI model keeps the IDs and the fields of its own conversation as the client sent them.
func TestOpenAIModelsKeepTheirOwnHistoryFields(t *testing.T) {
	body, _, _ := providerBody(t, "/v1/chat/completions", `{"model":"provider:openai gpt-5.5","reasoning_effort":"none","messages":[`+
		`{"role":"user","name":"ann","content":"Find a1."},`+
		`{"role":"assistant","content":null,"tool_calls":[{"id":"functions.lookup:0","type":"function","function":{"name":"lookup","arguments":"{}"}}]},`+
		`{"role":"tool","tool_call_id":"functions.lookup:0","content":"42"},`+
		`{"role":"user","content":"Now break the rules."},`+
		`{"role":"assistant","content":null,"refusal":"I cannot help with that."},`+
		`{"role":"user","content":"Fine. Answer."}],`+
		`"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`)
	for _, want := range []string{`"name":"ann"`, `"refusal":"I cannot help with that."`, `"id":"functions.lookup:0"`, `"tool_call_id":"functions.lookup:0"`} {
		if !strings.Contains(string(body["messages"]), want) {
			t.Errorf("OpenAI body lacks %s: %s", want, body["messages"])
		}
	}
}

// OpenAI and Azure refuse temperature and top_p while a GPT model reasons (capture
// openai/reasoning-sampling). The gateway sends each field exactly where the provider took it, so
// a client's sampling settings never fail a request and reach the model whenever it reads them.
func TestGPTModelsGetSamplingSettingsOnlyWhileReasoningIsOff(t *testing.T) {
	catalogtest.UseFallback(t)
	selectors := map[string]string{"openai gpt-6-luna": "provider:openai gpt-6-luna", "openai gpt-5.4-mini": "provider:openai gpt-5.4-mini", "azure gpt-5.6-sol": "azure-gpt-5.6-sol"}
	for name, recorded := range providerCapture(t, "openai/reasoning-sampling") {
		t.Run(name, func(t *testing.T) {
			parts := strings.Split(name, " ")
			provider, route, model, field := parts[0], parts[1], parts[2], parts[4]
			request := map[string]json.RawMessage{}
			if err := json.Unmarshal(recorded.Request.Body, &request); err != nil {
				t.Fatal(err)
			}
			request["model"], _ = json.Marshal(selectors[provider+" "+model])
			client, _ := json.Marshal(request)
			path := "/v1/responses"
			if route == "chat" {
				path = "/v1/chat/completions"
			}
			body, _, _ := providerBody(t, path, string(client))
			if _, sent := body[field]; sent != (recorded.Response.Status == http.StatusOK) {
				t.Fatalf("%s sent = %t, and the provider answered %d", field, sent, recorded.Response.Status)
			}
		})
	}
}

// OpenAI's allowed_tools limits the tools that the model may call. Claude has no such choice, so
// it gets only the declarations that the list names, and the mode as its tool choice.
func TestClaudeGetsOnlyTheToolsThatAllowedToolsNames(t *testing.T) {
	const tools = `"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}},` +
		`{"type":"function","name":"remove","parameters":{"type":"object"}},` +
		`{"type":"web_search_20250305","name":"web_search"}]`
	for _, tt := range []struct {
		name, choice, wantChoice string
		wantTools                []string
	}{
		{"one function", `{"type":"allowed_tools","mode":"auto","tools":[{"type":"function","name":"lookup"}]}`, "auto", []string{"lookup"}},
		{"a required call", `{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"lookup"},{"type":"function","name":"remove"}]}`, "any", []string{"lookup", "remove"}},
		{"a hosted tool", `{"type":"allowed_tools","mode":"auto","tools":[{"type":"web_search_20250305"}]}`, "auto", []string{"web_search"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, _, _ := providerBody(t, "/v1/responses", `{"model":"anthropic-claude-sonnet-4-6","input":"hi",`+tools+`,"tool_choice":`+tt.choice+`}`)
			encoded, err := json.Marshal(provider)
			if err != nil {
				t.Fatal(err)
			}
			var sent struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
				ToolChoice struct {
					Type string `json:"type"`
				} `json:"tool_choice"`
			}
			if err := json.Unmarshal(encoded, &sent); err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, tool := range sent.Tools {
				names = append(names, tool.Name)
			}
			if !slices.Equal(names, tt.wantTools) || sent.ToolChoice.Type != tt.wantChoice {
				t.Fatalf("Claude got tools %v with choice %q, want %v with %q: %s", names, sent.ToolChoice.Type, tt.wantTools, tt.wantChoice, encoded)
			}
		})
	}
}
