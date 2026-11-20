package stogas

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/catalog/catalogtest"
)

// awsChatDeployments names the catalog deployment of each inference profile that the recordings of
// Bedrock's Chat Completions API call.
var awsChatDeployments = map[string]string{
	"global.moonshotai.kimi-k3":   "aws-kimi-k3",
	"global.moonshotai.kimi-k3.1": "aws-kimi-k3.1-pro",
}

// awsChatRequest turns a recorded request to Bedrock into a client's request for the catalog
// deployment of its inference profile.
func awsChatRequest(t *testing.T, recorded providerExchange) string {
	t.Helper()
	request := map[string]json.RawMessage{}
	var profile string
	if err := json.Unmarshal(recorded.Request.Body, &request); err != nil || json.Unmarshal(request["model"], &profile) != nil {
		t.Fatalf("decode request: %v", err)
	}
	deployment, ok := awsChatDeployments[profile]
	if !ok {
		t.Fatalf("no catalog deployment for %q", profile)
	}
	request["model"], _ = json.Marshal(deployment)
	body, _ := json.Marshal(request)
	return string(body)
}

// resolveAWSChatState resolves a client's Chat Completions request for an AWS deployment and checks
// it as the gateway does before it holds funds.
func resolveAWSChatState(t *testing.T, body string) (*State, error) {
	t.Helper()
	return resolveAWSState(t, "/v1/chat/completions", body)
}

// resolveAWSState is resolveAWSChatState for a request of either interface.
func resolveAWSState(t *testing.T, path, body string) (*State, error) {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: http.MethodPost, Path: path, Body: []byte(body)})
	if err != nil {
		return nil, err
	}
	if resolution.Provider != catalog.ProviderAWS {
		t.Fatalf("provider = %q, want AWS", resolution.Provider)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		return nil, err
	}
	return state, state.Adapter.SanitizeRequest(state)
}

// awsCustomerChatBody prepares a client's Chat Completions request for an AWS deployment with the
// customer's own credential and returns the body that Bedrock receives.
func awsCustomerChatBody(t *testing.T, body string) []byte {
	t.Helper()
	return awsCustomerBody(t, "/v1/chat/completions", body)
}

// awsCustomerBody is awsCustomerChatBody for a request of either interface, which reaches Bedrock
// as Chat Completions.
func awsCustomerBody(t *testing.T, path, body string) []byte {
	t.Helper()
	state, err := resolveAWSState(t, path, body)
	if err != nil {
		t.Fatal(err)
	}
	_, state.PreparedCredential = customerOpenAICredential(t)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.WireRequestType())
	request, err := state.Resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatal(err)
	}
	return preparedProviderBody(t, ctx, request.ChatRequest)
}

// TestAWSChatSendsWhatBedrockTook prepares clients' requests in OpenAI's own fields, with the
// customer's own credential, for Kimi on AWS. OpenAI's models would receive a developer message,
// max_completion_tokens, user, safety_identifier and store from them, and Kimi on Bedrock refuses
// or ignores the seed, top_p and penalties, but each body must equal a request that Bedrock took
// in the recording (capture aws/chat-completions-request-fields).
func TestAWSChatSendsWhatBedrockTook(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "aws/chat-completions-request-fields")
	for _, test := range []struct{ took, client string }{
		{"max_tokens and a system message", `"messages":[{"role":"developer","content":"Answer in one word."},{"role":"user","content":"Say OK."}],"max_completion_tokens":400,"reasoning_effort":"none","user":"user-1","safety_identifier":"user-hash","store":false,"metadata":{"run":"1"}`},
		{"temperature 0.5", `"messages":[{"role":"user","content":"Say OK."}],"max_tokens":400,"reasoning_effort":"none","temperature":0.5,"seed":7,"top_p":0.9,"frequency_penalty":0.5,"presence_penalty":0.5,"logprobs":false`},
		{"top_k 1", `"messages":[{"role":"user","content":"Say OK."}],"max_tokens":400,"reasoning_effort":"none","top_k":1,"parallel_tool_calls":true`},
	} {
		t.Run(test.took, func(t *testing.T) {
			took := exchange(t, recorded, test.took)
			if took.Response.Status != http.StatusOK {
				t.Fatalf("Bedrock answered %d in the recording", took.Response.Status)
			}
			if sent := awsCustomerChatBody(t, `{"model":"aws-kimi-k3",`+test.client+`}`); !sameJSON(t, sent, took.Request.Body) {
				t.Fatalf("sent %s, Bedrock took %s", sent, took.Request.Body)
			}
		})
	}
}

// TestAWSChatRefusesWhatBedrockLeavesUnapplied replays each recorded request that Bedrock answered
// 200 without applying a field that decides what the reply holds or what the model may do: log
// probabilities, a token bias, a web search, or one tool call per turn (captures
// aws/chat-completions-request-fields and aws/chat-completions-tools). The gateway refuses each
// before it holds funds. A field that only tunes sampling, or that no interface defines, never
// reaches Bedrock.
func TestAWSChatRefusesWhatBedrockLeavesUnapplied(t *testing.T) {
	catalogtest.UseFallback(t)
	fields := providerCapture(t, "aws/chat-completions-request-fields")
	tools := providerCapture(t, "aws/chat-completions-tools")
	for _, recorded := range []providerExchange{
		exchange(t, fields, "logit_bias with a key that names no token"),
		exchange(t, fields, "logprobs"),
		exchange(t, fields, "web_search_options"),
		exchange(t, tools, "parallel_tool_calls false"),
	} {
		t.Run(recorded.Name, func(t *testing.T) {
			if recorded.Response.Status != http.StatusOK {
				t.Fatalf("Bedrock answered %d in the recording", recorded.Response.Status)
			}
			if _, err := resolveAWSChatState(t, awsChatRequest(t, recorded)); err == nil {
				t.Fatal("the gateway took the request")
			}
		})
	}
	for name, field := range map[string]string{
		"repetition_penalty as a string":     "repetition_penalty",
		"a field that Bedrock does not know": "stogas_unknown_field",
	} {
		t.Run(name, func(t *testing.T) {
			request := awsChatRequest(t, exchange(t, fields, name))
			if _, err := resolveAWSChatState(t, request); err != nil {
				return
			}
			var sent map[string]json.RawMessage
			if err := json.Unmarshal(awsCustomerChatBody(t, request), &sent); err != nil {
				t.Fatal(err)
			}
			if _, ok := sent[field]; ok {
				t.Fatalf("Bedrock receives %s", field)
			}
		})
	}
}

// TestAWSChatStatesWhatBedrockTook compares the sampling fields that the catalog states for Kimi
// on AWS with what Bedrock did with each model in the recording (capture
// aws/chat-completions-request-fields). Bedrock applies temperature and top_k where three replies
// at temperature 0 or top_k 1 agree, and seed where three replies at one seed agree. A field that
// Bedrock refused at the value sent, or left unapplied, is stated as not taken, so the gateway
// leaves it out and a policy that needs it filters the deployment out.
func TestAWSChatStatesWhatBedrockTook(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "aws/chat-completions-request-fields")
	for _, model := range []struct {
		prefix      string
		deployments []string
	}{
		{"", []string{"aws-kimi-k3", "aws-kimi-k3-us", "aws-kimi-k3-in"}},
		{"Kimi K3.1 Pro: ", []string{"aws-kimi-k3.1-pro", "aws-kimi-k3.1-pro-us", "aws-kimi-k3.1-pro-in"}},
	} {
		took := func(label string) bool {
			return exchange(t, recorded, model.prefix+label).Response.Status == http.StatusOK
		}
		agree := func(label string) bool {
			replies := map[string]bool{}
			for _, run := range []string{"1", "2", "3"} {
				var body struct {
					Choices []struct {
						Message struct {
							Content string `json:"content"`
						} `json:"message"`
					} `json:"choices"`
				}
				reply := exchange(t, recorded, model.prefix+label+", run "+run)
				if err := json.Unmarshal(reply.Response.Body, &body); err != nil || len(body.Choices) == 0 {
					t.Fatalf("decode %s%s reply: %v", model.prefix, label, err)
				}
				replies[body.Choices[0].Message.Content] = true
			}
			return len(replies) == 1
		}
		applied := map[string]bool{
			"temperature":       took("temperature 0.5") && agree("temperature 0"),
			"top_k":             took("top_k 1") && agree("top_k 1"),
			"top_p":             took("top_p 0.9"),
			"frequency_penalty": took("frequency_penalty 0.5"),
			"presence_penalty":  took("presence_penalty 0.5"),
			"seed":              agree("seed 7"),
		}
		for _, deploymentID := range model.deployments {
			t.Run(deploymentID, func(t *testing.T) {
				state, err := resolveAWSChatState(t, `{"model":"`+deploymentID+`","messages":[{"role":"user","content":"Say OK."}]}`)
				if err != nil {
					t.Fatal(err)
				}
				sampling := state.Resolution.Deployment.Sampling
				for field, stated := range map[string]bool{
					"temperature":       sampling.Temperature,
					"top_k":             sampling.TopK,
					"top_p":             sampling.TopP,
					"frequency_penalty": sampling.FrequencyPenalty,
					"presence_penalty":  sampling.PresencePenalty,
					"seed":              sampling.Seed,
				} {
					if stated != applied[field] {
						t.Errorf("the catalog states %s as %t, and the recording shows %t", field, stated, applied[field])
					}
				}
				if sampling.LogitBias || sampling.RepetitionPenalty {
					t.Errorf("the catalog states logit_bias %t and repetition_penalty %t, which Bedrock ignores", sampling.LogitBias, sampling.RepetitionPenalty)
				}
			})
		}
	}
}

// TestAWSChatSendsOnlyEffortsThatBedrockTook sends each recorded request with reasoning_effort as a
// client's request for its deployment (capture aws/chat-completions-efforts). The gateway sends
// every effort as one of Kimi's own that Bedrock took, none as none, and no effort without one,
// which Bedrock answers at max, the default that the catalog states.
func TestAWSChatSendsOnlyEffortsThatBedrockTook(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "aws/chat-completions-efforts")
	for name, took := range recorded {
		t.Run(name, func(t *testing.T) {
			profile, effort, _ := strings.Cut(name, " reasoning_effort ")
			var sent struct {
				ReasoningEffort *string `json:"reasoning_effort"`
			}
			if err := json.Unmarshal(awsCustomerChatBody(t, awsChatRequest(t, took)), &sent); err != nil {
				t.Fatal(err)
			}
			if sent.ReasoningEffort == nil {
				if effort != "unset" {
					t.Fatalf("sent no effort for %s", effort)
				}
				return
			}
			if effort == "none" && *sent.ReasoningEffort != "none" {
				t.Fatalf("sent %s for none", *sent.ReasoningEffort)
			}
			if answered := exchange(t, recorded, profile+" reasoning_effort "+*sent.ReasoningEffort).Response.Status; answered != http.StatusOK {
				t.Fatalf("sent reasoning_effort %q, which Bedrock answered with %d", *sent.ReasoningEffort, answered)
			}
		})
	}
	state, err := resolveAWSChatState(t, `{"model":"aws-kimi-k3","messages":[{"role":"user","content":"Say OK."}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if def := state.Resolution.Deployment.ReasoningDefault; def == nil || *def != "max" {
		t.Fatalf("reasoning default = %v, want max", def)
	}
}

// TestAWSChatHoldsWhatKimiGenerates replays Kimi's recorded replies to an output limit of 12 under
// either name (capture aws/chat-completions-output-limits). Kimi keeps reasoning and answer within
// the limit and counts both in completion_tokens, so the hold is the client's limit and billing
// counts every generated token. Bedrock refuses a limit of 0 or above the model's maximum, which
// the catalog states and the gateway refuses first.
func TestAWSChatHoldsWhatKimiGenerates(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "aws/chat-completions-output-limits")
	for _, name := range []string{"max_tokens of 12", "max_completion_tokens of 12"} {
		t.Run(name, func(t *testing.T) {
			reply := exchange(t, recorded, name)
			response := &schemas.BifrostChatResponse{}
			if err := sonic.Unmarshal(reply.Response.Body, response); err != nil {
				t.Fatal(err)
			}
			usage := response.Usage
			generated := usage.TotalTokens - usage.PromptTokens
			state, err := resolveAWSChatState(t, awsChatRequest(t, reply))
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatal(err)
			}
			held := findMeterEstimate(state.Hold.Meters, billing.MeterOutputTokens)
			if held == nil || held.Quantity != "12" || generated > 12 {
				t.Fatalf("output hold = %#v, want 12 tokens, at least the %d generated", held, generated)
			}
			if err := ingestReportedUsage(state, usage); err != nil {
				t.Fatal(err)
			}
			if got := state.Signals.CompletionTokens(); got != generated {
				t.Fatalf("completion tokens = %d billed, want the %d generated", got, generated)
			}
		})
	}
	above := exchange(t, recorded, "max_tokens of 1048577")
	if !strings.Contains(string(above.Response.Body), "("+strconv.Itoa(1048576)+")") {
		t.Fatalf("Bedrock stated another maximum: %s", above.Response.Body)
	}
	for _, name := range []string{"max_tokens of 1048577", "max_tokens of 0"} {
		if _, err := resolveAWSChatState(t, awsChatRequest(t, exchange(t, recorded, name))); err == nil {
			t.Fatalf("the gateway took %s", name)
		}
	}
	state, err := resolveAWSChatState(t, `{"model":"aws-kimi-k3","messages":[{"role":"user","content":"Say OK."}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if state.Resolution.Deployment.MaxOutputTokens != 1048576 {
		t.Fatalf("output limit = %d, want Bedrock's 1048576", state.Resolution.Deployment.MaxOutputTokens)
	}
}

// TestAWSChatBillsTheCacheAsBedrockReports replays Kimi's recorded cache writes and reads (capture
// aws/chat-completions-prompt-caching). A breakpoint writes the prompt before it at the cache write
// rate, which the hold covers, and the next request reads it at the cache read rate. With
// prompt_cache_options mode explicit and no breakpoint, nothing is written, so the hold prices no
// write. A breakpoint's ttl reaches Bedrock, which refuses it, only without the ttl.
func TestAWSChatBillsTheCacheAsBedrockReports(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "aws/chat-completions-prompt-caching")
	for _, test := range []struct {
		name, meter string
		hold        bool
	}{
		{"breakpoint first", billing.MeterCacheWriteInputTokens, true},
		{"breakpoint again", billing.MeterCachedInputTokens, true},
		{"no mark again", billing.MeterCachedInputTokens, true},
		{"prompt_cache_options explicit without a breakpoint", billing.MeterInputTokens, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			reply := exchange(t, recorded, test.name)
			response := &schemas.BifrostChatResponse{}
			if err := sonic.Unmarshal(reply.Response.Body, response); err != nil {
				t.Fatal(err)
			}
			state, err := resolveAWSChatState(t, awsChatRequest(t, reply))
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatal(err)
			}
			if held := findMeterEstimate(state.Hold.Meters, billing.MeterCacheWriteInputTokens); (held != nil) != test.hold {
				t.Fatalf("cache write hold = %#v, want one: %t", held, test.hold)
			}
			if err := ingestReportedUsage(state, response.Usage); err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatal(err)
			}
			details := response.Usage.PromptTokensDetails
			if details == nil {
				t.Fatal("Bedrock reported no prompt token details")
			}
			want := map[string]int{
				billing.MeterCacheWriteInputTokens: details.CachedWriteTokens,
				billing.MeterCachedInputTokens:     details.CachedReadTokens,
				billing.MeterInputTokens:           response.Usage.PromptTokens - details.CachedWriteTokens - details.CachedReadTokens,
			}
			if want[test.meter] == 0 {
				t.Fatalf("Bedrock reported no %s: %+v", test.meter, details)
			}
			for meter, quantity := range want {
				if billed := meterQuantity(findMeterEstimate(state.FinalMeters, meter)); quantity != 0 && billed != strconv.Itoa(quantity) {
					t.Fatalf("%s billed %q, Bedrock reported %d: %#v", meter, billed, quantity, state.FinalMeters)
				}
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD) < 0 {
				t.Fatalf("hold %s does not cover the cost %s", state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD)
			}
		})
	}
	marked := exchange(t, recorded, "breakpoint first")
	refused := exchange(t, recorded, "breakpoint with a ttl")
	if refused.Response.Status != http.StatusBadRequest {
		t.Fatalf("Bedrock answered a breakpoint's ttl with %d", refused.Response.Status)
	}
	// breakpoint returns the prompt_cache_breakpoint of a body's first part. The first message holds
	// parts, and a later one may hold text.
	breakpoint := func(body []byte) json.RawMessage {
		t.Helper()
		var request struct {
			Messages []struct {
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		var parts []map[string]json.RawMessage
		if err := json.Unmarshal(body, &request); err != nil || len(request.Messages) == 0 {
			t.Fatalf("decode %s: %v", body, err)
		}
		if err := json.Unmarshal(request.Messages[0].Content, &parts); err != nil || len(parts) == 0 {
			t.Fatalf("decode the first message of %s: %v", body, err)
		}
		return parts[0]["prompt_cache_breakpoint"]
	}
	sent := awsCustomerChatBody(t, awsChatRequest(t, refused))
	if got, want := breakpoint(sent), breakpoint(marked.Request.Body); !sameJSON(t, got, want) {
		t.Fatalf("breakpoint sent = %s, Bedrock took %s", got, want)
	}
	if _, err := resolveAWSChatState(t, awsChatRequest(t, exchange(t, recorded, "prompt_cache_options ttl 24h"))); err == nil {
		t.Fatal("the gateway took a ttl of 24h, which Bedrock refused")
	}
}

// TestAWSChatTakesTheFilesThatBedrockReads replays Kimi's recorded file and image requests
// (capture aws/chat-completions-files). The gateway sends each file and image that the model read
// as Bedrock took it, an image in a tool message included, and refuses before it holds funds what
// Bedrock refused: an image URL, a file without a name that ends in an extension that Bedrock
// lists, audio, and a file in a tool message.
func TestAWSChatTakesTheFilesThatBedrockReads(t *testing.T) {
	catalogtest.UseFallback(t)
	for name, recorded := range providerCapture(t, "aws/chat-completions-files") {
		t.Run(name, func(t *testing.T) {
			request := awsChatRequest(t, recorded)
			_, err := resolveAWSChatState(t, request)
			if took := recorded.Response.Status == http.StatusOK; took != (err == nil) {
				t.Fatalf("Bedrock answered %d, and the gateway's check returned %v", recorded.Response.Status, err)
			}
			if err != nil {
				return
			}
			var sent, took struct {
				Messages json.RawMessage `json:"messages"`
			}
			if json.Unmarshal(awsCustomerChatBody(t, request), &sent) != nil || json.Unmarshal(recorded.Request.Body, &took) != nil {
				t.Fatal("decode messages")
			}
			if !sameJSON(t, sent.Messages, took.Messages) {
				t.Fatalf("messages sent = %s, Bedrock took %s", sent.Messages, took.Messages)
			}
		})
	}
	// A Responses tool output reaches Bedrock as the tool message whose image the model read.
	recorded := exchange(t, providerCapture(t, "aws/chat-completions-files"), "image in a tool message")
	var took struct {
		Messages []struct {
			Content   json.RawMessage `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
		Tools []struct {
			Function json.RawMessage `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(recorded.Request.Body, &took); err != nil || len(took.Messages) != 3 || len(took.Tools) != 1 {
		t.Fatalf("decode the recorded request: %v", err)
	}
	var image []struct {
		ImageURL struct {
			URL string `json:"url"`
		} `json:"image_url"`
	}
	call := took.Messages[1].ToolCalls[0]
	tool := map[string]json.RawMessage{}
	if json.Unmarshal(took.Messages[2].Content, &image) != nil || json.Unmarshal(took.Tools[0].Function, &tool) != nil {
		t.Fatal("decode the recorded tool message")
	}
	tool["type"] = json.RawMessage(`"function"`)
	tools, _ := json.Marshal([]map[string]json.RawMessage{tool})
	request, _ := json.Marshal(map[string]any{
		"model": "aws-kimi-k3",
		"input": []any{
			map[string]any{"role": "user", "content": took.Messages[0].Content},
			map[string]any{"type": "function_call", "call_id": call.ID, "name": call.Function.Name, "arguments": call.Function.Arguments},
			map[string]any{"type": "function_call_output", "call_id": call.ID, "output": []any{map[string]any{"type": "input_image", "image_url": image[0].ImageURL.URL}}},
		},
		"tools":             json.RawMessage(tools),
		"max_output_tokens": 400,
		"reasoning":         map[string]any{"effort": "none"},
	})
	var sent struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(awsCustomerBody(t, "/v1/responses", string(request)), &sent); err != nil || len(sent.Messages) != 3 {
		t.Fatalf("decode the sent request: %v", err)
	}
	var tookMessages struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(recorded.Request.Body, &tookMessages); err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, sent.Messages[2], tookMessages.Messages[2]) {
		t.Fatalf("the Responses tool output reached Bedrock as %s, and Bedrock took %s", sent.Messages[2], tookMessages.Messages[2])
	}
}

// TestAWSChatTakesToolChoicesThatKimiFollows replays Kimi's recorded tool requests (capture
// aws/chat-completions-tools): Kimi K3 and K3.1 called the tool at every choice that requires one,
// a named function included, even when the prompt gave no reason to, which the catalog states, and
// answered in the schema of response_format.
func TestAWSChatTakesToolChoicesThatKimiFollows(t *testing.T) {
	catalogtest.UseFallback(t)
	names := []string{"tool_choice auto", "tool_choice required", "tool_choice naming the function", "tool_choice none", "response_format json_schema"}
	for _, model := range []string{"global.moonshotai.kimi-k3", "global.moonshotai.kimi-k3.1"} {
		names = append(names, model+" tool_choice required after Hello", model+" tool_choice naming the function after Hello")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			recorded := exchange(t, providerCapture(t, "aws/chat-completions-tools"), name)
			if recorded.Response.Status != http.StatusOK {
				t.Fatalf("Bedrock answered %d in the recording", recorded.Response.Status)
			}
			request := awsChatRequest(t, recorded)
			if sent := awsCustomerChatBody(t, request); !sameJSON(t, sent, recorded.Request.Body) {
				t.Fatalf("sent %s, Bedrock took %s", sent, recorded.Request.Body)
			}
			if !strings.Contains(name, "required") && !strings.Contains(name, "naming") {
				return
			}
			var reply struct {
				Choices []struct {
					Message struct {
						ToolCalls []json.RawMessage `json:"tool_calls"`
					} `json:"message"`
				} `json:"choices"`
			}
			if err := json.Unmarshal(recorded.Response.Body, &reply); err != nil || len(reply.Choices) == 0 || len(reply.Choices[0].Message.ToolCalls) == 0 {
				t.Fatalf("Kimi answered a forced tool choice without a call: %s", recorded.Response.Body)
			}
			state, err := resolveAWSChatState(t, request)
			if err != nil || !state.Resolution.Deployment.Capabilities.ToolChoice {
				t.Fatalf("the catalog states no tool choice for a deployment that follows it: %v", err)
			}
		})
	}
}

// TestAWSChatStreamCountsReasoningAsBedrockReports replays Kimi's recorded stream (capture
// aws/chat-completions-stream). Every event passes the gateway's checks, and the usage of the last
// event, whose completion_tokens include the reasoning tokens, is what billing counts.
func TestAWSChatStreamCountsReasoningAsBedrockReports(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := exchange(t, providerCapture(t, "aws/chat-completions-stream"), "stream with usage")
	request := awsChatRequest(t, recorded)
	if sent := awsCustomerChatBody(t, request); !sameJSON(t, sent, recorded.Request.Body) {
		t.Fatalf("sent %s, Bedrock took %s", sent, recorded.Request.Body)
	}
	state, err := resolveAWSChatState(t, request)
	if err != nil {
		t.Fatal(err)
	}
	var usage *schemas.BifrostLLMUsage
	for _, data := range recorded.Response.Events {
		chunk := &schemas.BifrostChatResponse{}
		if err := sonic.Unmarshal(data, chunk); err != nil {
			t.Fatal(err)
		}
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
			t.Fatalf("event refused: %v: %s", err, data)
		}
	}
	if usage == nil || usage.CompletionTokensDetails == nil || usage.CompletionTokensDetails.ReasoningTokens == 0 {
		t.Fatalf("the stream reported no reasoning tokens: %+v", usage)
	}
	if got := state.Signals.CompletionTokens(); got != usage.CompletionTokens {
		t.Fatalf("completion tokens = %d billed, Bedrock reported %d", got, usage.CompletionTokens)
	}
}

// TestAWSChatSendsReasoningBackAsBedrockTookIt replays a conversation that Kimi on Bedrock took
// with the reasoning_content of an earlier answer and of an earlier tool call (capture
// aws/chat-completions-reasoning-history).
func TestAWSChatSendsReasoningBackAsBedrockTookIt(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "aws/chat-completions-reasoning-history")
	replayReasoningHistory(t, exchange(t, recorded, "global.moonshotai.kimi-k3 answer after both turns sent back with their reasoning"), "aws-kimi-k3")
}
