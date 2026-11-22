package stogas

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog/catalogtest"
)

// googleOpenModels names the catalog deployment of each open model that the recordings of Agent
// Platform's Chat Completions API call.
var googleOpenModels = map[string]string{
	"openai/gpt-oss-120b-maas":                  "google-cloud-gpt-oss-120b",
	"google/gemma-4-26b-a4b-it-maas":            "google-cloud-gemma-4-26b-a4b",
	"deepseek-ai/deepseek-v4.1-flash-1017-maas": "google-cloud-deepseek-v4.1-flash-1017",
	"zai-org/glm-5.2-maas":                      "google-cloud-glm-5.2",
}

// googleChatRequest turns a recorded request to Agent Platform into a client's request for the
// catalog deployment of its model. A client turns reasoning off with the effort none, which the
// gateway sends as the chat template's switch.
func googleChatRequest(t *testing.T, recorded providerExchange) string {
	t.Helper()
	request := map[string]json.RawMessage{}
	var model string
	if err := json.Unmarshal(recorded.Request.Body, &request); err != nil || json.Unmarshal(request["model"], &model) != nil {
		t.Fatalf("decode request: %v", err)
	}
	deployment, ok := googleOpenModels[model]
	if !ok {
		t.Fatalf("no catalog deployment for %q", model)
	}
	request["model"], _ = json.Marshal(deployment)
	if template, set := request["chat_template_kwargs"]; set {
		if !sameJSON(t, template, []byte(`{"enable_thinking":false,"thinking":false}`)) {
			t.Fatalf("%s turns reasoning on through the template, which no client field does", recorded.Name)
		}
		delete(request, "chat_template_kwargs")
		request["reasoning_effort"] = json.RawMessage(`"none"`)
	}
	body, _ := json.Marshal(request)
	return string(body)
}

// googleChatReply decodes a recorded reply of Agent Platform's Chat Completions API as core does,
// or returns nil for a refusal, which Google sends for some models as a 200 reply that holds an
// error.
func googleChatReply(t *testing.T, recorded providerExchange) *schemas.BifrostChatResponse {
	t.Helper()
	if recorded.Response.Status != http.StatusOK || openaiprovider.ErrorInSuccessfulChatBody(recorded.Response.Body) != nil {
		return nil
	}
	reply := &schemas.BifrostChatResponse{}
	if err := sonic.Unmarshal(recorded.Response.Body, reply); err != nil {
		t.Fatalf("%s: %v", recorded.Name, err)
	}
	return reply
}

// googleReasoned reports whether a recorded reply holds reasoning.
func googleReasoned(t *testing.T, recorded providerExchange) bool {
	t.Helper()
	reply := googleChatReply(t, recorded)
	if reply == nil || len(reply.Choices) == 0 || reply.Choices[0].Message == nil {
		return false
	}
	assistant := reply.Choices[0].Message.ChatAssistantMessage
	return assistant != nil && assistant.Reasoning != nil && *assistant.Reasoning != ""
}

// TestGoogleChatReasonsAsTheRequestAsks prepares a request at each effort for each open model on
// Agent Platform (capture google-cloud/chat-completions-reasoning). Each body that the gateway
// sends equals one that Google took, under which the model reasoned when the request asks for
// reasoning and did not when it asks for none, unless the model always reasons. A request without
// an effort gets the reasoning that the catalog states as the deployment's default. The gateway
// sends reasoning back as Google took it.
func TestGoogleChatReasonsAsTheRequestAsks(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/chat-completions-reasoning")
	for model, deployment := range googleOpenModels {
		for _, effort := range []string{"unset", "none", "minimal", "low", "medium", "high", "xhigh", "max"} {
			t.Run(model+" "+effort, func(t *testing.T) {
				client := `{"model":"` + deployment + `","messages":[{"role":"user","content":"Is 391 a prime number? Answer yes or no."}],"max_tokens":8000`
				if effort != "unset" {
					client += `,"reasoning_effort":"` + effort + `"`
				}
				client += `}`
				state, err := resolveGoogleState(t, geminiChatPath, client)
				if err != nil {
					t.Fatal(err)
				}
				sent := googleBody(t, geminiChatPath, client)
				var took *providerExchange
				for name, candidate := range recorded {
					if strings.HasPrefix(name, model+" ") && sameJSON(t, sent, candidate.Request.Body) {
						took = &candidate
						break
					}
				}
				if took == nil {
					t.Fatalf("sent %s, which Google took in no recorded request", sent)
				}
				served := state.Resolution.Deployment
				want := effort != "none" || served.Reasoning == "required"
				if effort == "unset" {
					want = served.ReasoningDefault == nil || *served.ReasoningDefault != "none"
				}
				if took.Response.Status != http.StatusOK || googleReasoned(t, *took) != want {
					t.Fatalf("sent %s, which Google answered with %d, and the model reasoned: %t", sent, took.Response.Status, googleReasoned(t, *took))
				}
			})
		}
		t.Run(model+" history", func(t *testing.T) {
			replayReasoningHistory(t, exchange(t, recorded, model+" answer after both turns sent back with their reasoning"), deployment)
		})
	}
}

// TestGoogleChatStreamsReasoningApartFromTheAnswer replays each open model's recorded stream on
// Agent Platform (capture google-cloud/chat-completions-reasoning). The client gets the reasoning
// and the answer apart, as Google sent them, and the usage of its last event.
func TestGoogleChatStreamsReasoningApartFromTheAnswer(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/chat-completions-reasoning")
	for model, deployment := range googleOpenModels {
		t.Run(model, func(t *testing.T) {
			stream := exchange(t, recorded, model+" stream")
			state, err := resolveGoogleState(t, geminiChatPath, `{"model":"`+deployment+`","messages":[{"role":"user","content":"Is 391 a prime number? Answer yes or no."}],"max_tokens":8000,"reasoning_effort":"high","stream":true}`)
			if err != nil {
				t.Fatal(err)
			}
			var wantReasoning, wantAnswer, reasoning, answer strings.Builder
			var usage *schemas.BifrostLLMUsage
			for _, data := range stream.Response.Events {
				var sent struct {
					Choices []struct {
						Delta struct {
							Content          string `json:"content"`
							ReasoningContent string `json:"reasoning_content"`
						} `json:"delta"`
					} `json:"choices"`
				}
				if err := json.Unmarshal(data, &sent); err != nil {
					t.Fatal(err)
				}
				for _, choice := range sent.Choices {
					wantReasoning.WriteString(choice.Delta.ReasoningContent)
					wantAnswer.WriteString(choice.Delta.Content)
				}
				chunk := &schemas.BifrostChatResponse{}
				if err := sonic.Unmarshal(data, chunk); err != nil {
					t.Fatal(err)
				}
				if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
					t.Fatalf("event refused: %v: %s", err, data)
				}
				for _, choice := range chunk.Choices {
					if choice.ChatStreamResponseChoice == nil || choice.Delta == nil {
						continue
					}
					if choice.Delta.Reasoning != nil {
						reasoning.WriteString(*choice.Delta.Reasoning)
					}
					if choice.Delta.Content != nil {
						answer.WriteString(*choice.Delta.Content)
					}
				}
				if chunk.Usage != nil {
					usage = chunk.Usage
				}
			}
			if wantReasoning.Len() == 0 || wantAnswer.Len() == 0 {
				t.Fatalf("the recorded stream holds reasoning %q and answer %q", wantReasoning.String(), wantAnswer.String())
			}
			if reasoning.String() != wantReasoning.String() || answer.String() != wantAnswer.String() {
				t.Fatalf("reasoning %q and answer %q, want %q and %q", reasoning.String(), answer.String(), wantReasoning.String(), wantAnswer.String())
			}
			if usage == nil || usage.PromptTokens == 0 || usage.CompletionTokens == 0 {
				t.Fatalf("usage = %+v", usage)
			}
		})
	}
}

// TestGoogleChatStatesTheLimitsThatGoogleTakes replays the recorded output limits of the open
// models on Agent Platform (capture google-cloud/chat-completions-limits). Google took each
// deployment's output limit that is below the model's context window, refused one that equals it,
// which leaves the prompt no room, and refused a larger one with a limit that is the deployment's
// or, for DeepSeek, above it. The gateway sends the deployment's limit to a request that sets none
// wherever it leaves the prompt room, so that Google stops where the hold ends. The gateway refuses
// before it holds funds a limit above the deployment's or of 0.
func TestGoogleChatStatesTheLimitsThatGoogleTakes(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/chat-completions-limits")
	// Google's own refusal, and the model server's (vLLM) behind it.
	stated := regexp.MustCompile(`(?:exceeds the maximum output tokens limit: |supports at most )(\d+)`)
	for model, deployment := range googleOpenModels {
		t.Run(model, func(t *testing.T) {
			state, err := resolveGoogleState(t, geminiChatPath, `{"model":"`+deployment+`","messages":[{"role":"user","content":"Say OK."}]}`)
			if err != nil {
				t.Fatal(err)
			}
			served := state.Resolution.Deployment
			at := exchange(t, recorded, model+" max_tokens at the deployment's limit")
			var request struct {
				MaxTokens int `json:"max_tokens"`
			}
			if err := json.Unmarshal(at.Request.Body, &request); err != nil || request.MaxTokens != served.MaxOutputTokens {
				t.Fatalf("the recording sent max_tokens %d, and the deployment states %d", request.MaxTokens, served.MaxOutputTokens)
			}
			if fits := served.MaxOutputTokens < served.ContextWindowTokens; fits != (googleChatReply(t, at) != nil) {
				t.Fatalf("Google answered the deployment's limit with %d: %s", at.Response.Status, at.Response.Body)
			}
			match := stated.FindSubmatch(exchange(t, recorded, model+" max_tokens above the maximum").Response.Body)
			if match == nil {
				t.Fatal("Google's refusal states no limit")
			}
			limit, _ := strconv.Atoi(string(match[1]))
			if limit < served.MaxOutputTokens {
				t.Fatalf("Google states an output limit of %d, and the deployment %d", limit, served.MaxOutputTokens)
			}
			var sent struct {
				MaxTokens           *int `json:"max_tokens"`
				MaxCompletionTokens *int `json:"max_completion_tokens"`
			}
			if err := json.Unmarshal(googleBody(t, geminiChatPath, `{"model":"`+deployment+`","messages":[{"role":"user","content":"Say OK."}]}`), &sent); err != nil {
				t.Fatal(err)
			}
			if sent.MaxTokens != nil {
				sent.MaxCompletionTokens = sent.MaxTokens
			}
			if served.MaxOutputTokens < served.ContextWindowTokens {
				if sent.MaxCompletionTokens == nil || *sent.MaxCompletionTokens != served.MaxOutputTokens {
					t.Fatalf("a request without a limit went out with %v, and the deployment states %d", sent.MaxCompletionTokens, served.MaxOutputTokens)
				}
			} else if sent.MaxCompletionTokens != nil {
				t.Fatalf("a request without a limit went out with %d", *sent.MaxCompletionTokens)
			}
			for _, name := range []string{"max_tokens above the maximum", "max_tokens above the maximum, streamed", "max_tokens of 0"} {
				if _, err := resolveGoogleState(t, geminiChatPath, googleChatRequest(t, exchange(t, recorded, model+" "+name))); err == nil {
					t.Errorf("the gateway took %s", name)
				}
			}
		})
	}
}

// TestGoogleChatTakesOnlyTheFilesThatTheModelReads replays the recorded file and image requests to
// the open models on Agent Platform (capture google-cloud/chat-completions-files). The gateway
// refuses before it holds funds each that Google refused, a document or an image URL, and each
// image that the model never saw, and sends each image that the model read as Google took it, an
// image in a tool message included.
func TestGoogleChatTakesOnlyTheFilesThatTheModelReads(t *testing.T) {
	catalogtest.UseFallback(t)
	for name, recorded := range providerCapture(t, "google-cloud/chat-completions-files") {
		t.Run(name, func(t *testing.T) {
			reply := googleChatReply(t, recorded)
			read := reply != nil && reply.Choices[0].Message.Content != nil && reply.Choices[0].Message.Content.ContentStr != nil &&
				strings.Contains(strings.ToLower(*reply.Choices[0].Message.Content.ContentStr), "red")
			request := googleChatRequest(t, recorded)
			if _, err := resolveGoogleState(t, geminiChatPath, request); read != (err == nil) {
				t.Fatalf("Google answered %d and the model read the image: %t, and the gateway's check returned %v", recorded.Response.Status, read, err)
			}
			if !read {
				return
			}
			if sent := googleBody(t, geminiChatPath, request); !sameJSON(t, sent, recorded.Request.Body) {
				t.Fatalf("sent %s, Google took %s", sent, recorded.Request.Body)
			}
		})
	}
}

// TestGoogleChatSendsToolCallIDsAsGoogleTookThem replays the recorded conversations whose tool call
// IDs Agent Platform took for each open model (capture google-cloud/chat-completions-tool-call-ids):
// IDs of every provider's form. The gateway sends each conversation as Google took it.
func TestGoogleChatSendsToolCallIDsAsGoogleTookThem(t *testing.T) {
	catalogtest.UseFallback(t)
	for name, recorded := range providerCapture(t, "google-cloud/chat-completions-tool-call-ids") {
		t.Run(name, func(t *testing.T) {
			if googleChatReply(t, recorded) == nil {
				t.Fatalf("Google answered %d: %s", recorded.Response.Status, recorded.Response.Body)
			}
			if sent := googleBody(t, geminiChatPath, googleChatRequest(t, recorded)); !sameJSON(t, sent, recorded.Request.Body) {
				t.Fatalf("sent %s, Google took %s", sent, recorded.Request.Body)
			}
		})
	}
}

// TestGoogleChatBillsTheCacheAsGoogleReports replays the open models' recorded repeats of one
// prompt on Agent Platform (capture google-cloud/chat-completions-caching), which the gateway sends
// as Google took them. Each reply's cached tokens bill at the deployment's cached input price, and
// the rest of the prompt at its input price, within the hold. Google prices no cached token of
// gpt-oss-120b, whose cached tokens bill as input
// (TestCalculateUpstreamCostKeepsUnpricedCacheDetailsAsOrdinaryInput).
func TestGoogleChatBillsTheCacheAsGoogleReports(t *testing.T) {
	catalogtest.UseFallback(t)
	hits := 0
	for name, recorded := range providerCapture(t, "google-cloud/chat-completions-caching") {
		t.Run(name, func(t *testing.T) {
			reply := googleChatReply(t, recorded)
			if reply == nil || reply.Usage == nil {
				t.Fatalf("Google answered %d: %s", recorded.Response.Status, recorded.Response.Body)
			}
			request := googleChatRequest(t, recorded)
			if sent := googleBody(t, geminiChatPath, request); !sameJSON(t, sent, recorded.Request.Body) {
				t.Fatalf("sent %s, Google took %s", sent, recorded.Request.Body)
			}
			state, err := resolveGoogleState(t, geminiChatPath, request)
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatal(err)
			}
			if err := ingestReportedUsage(state, reply.Usage); err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatal(err)
			}
			cached := 0
			if details := reply.Usage.PromptTokensDetails; details != nil {
				cached = details.CachedReadTokens
			}
			if cached*2 > reply.Usage.PromptTokens {
				hits++
			}
			for meter, quantity := range map[string]int{
				billing.MeterCachedInputTokens: cached,
				billing.MeterInputTokens:       reply.Usage.PromptTokens - cached,
			} {
				if billed := meterQuantity(findMeterEstimate(state.FinalMeters, meter)); quantity != 0 && billed != strconv.Itoa(quantity) {
					t.Fatalf("%s billed %q, Google reported %d: %#v", meter, billed, quantity, state.FinalMeters)
				}
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD) < 0 {
				t.Fatalf("hold %s does not cover the cost %s", state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD)
			}
		})
	}
	// Gemma 4's three prompts and the two longer prompts of each other model end with a repeat that
	// is mostly cached.
	if hits != 7 {
		t.Fatalf("%d replies are mostly cached, want 7", hits)
	}
}
