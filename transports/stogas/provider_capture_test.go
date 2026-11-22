package stogas

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/catalog/catalogtest"
	"github.com/valyala/fasthttp"
)

// providerExchange is one request that a provider received and the reply that it gave, recorded
// from the provider itself. A stream's reply holds the data of its events in order.
type providerExchange struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Request  struct {
		Path string          `json:"path"`
		Body json.RawMessage `json:"body"`
	} `json:"request"`
	Response struct {
		Status int               `json:"status"`
		Body   json.RawMessage   `json:"body"`
		Events []json.RawMessage `json:"events"`
	} `json:"response"`
}

// providerCapture reads testdata/provider/<id>.json, which holds what its exchanges show, the day
// they were recorded and the exchanges by name. A test replays them instead of a reply written by
// hand, so that it checks the gateway against what the provider sent and took.
func providerCapture(t *testing.T, id string) map[string]providerExchange {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "provider", filepath.FromSlash(id)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Shows     string             `json:"shows"`
		Recorded  string             `json:"recorded"`
		Exchanges []providerExchange `json:"exchanges"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	if capture.Shows == "" || capture.Recorded == "" || len(capture.Exchanges) == 0 {
		t.Fatalf("%s needs what it shows, its date and an exchange", id)
	}
	exchanges := make(map[string]providerExchange, len(capture.Exchanges))
	for _, exchange := range capture.Exchanges {
		if _, repeated := exchanges[exchange.Name]; repeated || exchange.Name == "" {
			t.Fatalf("%s: exchange names must be unique, got %q twice or empty", id, exchange.Name)
		}
		exchanges[exchange.Name] = exchange
	}
	return exchanges
}

// exchange returns the named exchange of a capture.
func exchange(t *testing.T, exchanges map[string]providerExchange, name string) providerExchange {
	t.Helper()
	found, ok := exchanges[name]
	if !ok {
		t.Fatalf("the capture has no exchange %q", name)
	}
	return found
}

// responsesReply decodes a recorded Responses reply as core decodes it.
func (e providerExchange) responsesReply(t *testing.T) *schemas.BifrostResponsesResponse {
	t.Helper()
	response := &schemas.BifrostResponsesResponse{}
	if err := sonic.Unmarshal(e.Response.Body, response); err != nil {
		t.Fatalf("%s: %v", e.Name, err)
	}
	return response
}

// responsesStream decodes the events of a recorded Responses stream as core decodes each one.
func (e providerExchange) responsesStream(t *testing.T) []*schemas.BifrostResponsesStreamResponse {
	t.Helper()
	events := make([]*schemas.BifrostResponsesStreamResponse, 0, len(e.Response.Events))
	for _, data := range e.Response.Events {
		event := &schemas.BifrostResponsesStreamResponse{}
		if err := sonic.Unmarshal(data, event); err != nil {
			*event = schemas.BifrostResponsesStreamResponse{}
			if err := schemas.UnmarshalResponsesStreamObjectDelta(data, event); err != nil {
				t.Fatalf("%s: decode %s: %v", e.Name, data, err)
			}
		}
		events = append(events, event)
	}
	return events
}

// TestEveryProviderCaptureLoads keeps each recorded file readable in the one format.
func TestEveryProviderCaptureLoads(t *testing.T) {
	root := filepath.Join("testdata", "provider")
	found := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if filepath.Ext(path) != ".json" {
			t.Errorf("%s is not a capture", path)
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		providerCapture(t, filepath.ToSlash(relative[:len(relative)-len(".json")]))
		found++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no provider captures")
	}
}

// errorReply is a recorded error reply as core receives it from the provider.
func (e providerExchange) errorReply(t *testing.T) *fasthttp.Response {
	t.Helper()
	response := &fasthttp.Response{}
	response.SetStatusCode(e.Response.Status)
	response.Header.SetContentType("application/json")
	response.SetBody(e.Response.Body)
	return response
}

// TestRecordedProviderRefusalsKeepTheirMeaning checks the status that the gateway gives recorded
// error replies: a spent monthly cap is the account's, which moves the request to another
// credential, a prompt and output limit beyond the context window moves it to another
// deployment, and encrypted reasoning that the provider cannot read is the request's own error.
func TestRecordedProviderRefusalsKeepTheirMeaning(t *testing.T) {
	spendCap := exchange(t, providerCapture(t, "anthropic/monthly-spend-cap"), "message")
	if got := billing.NormalizeUpstreamStatus(anthropic.ParseAnthropicError(spendCap.errorReply(t))); got != "over_budget" {
		t.Fatalf("Anthropic's spent monthly cap = %s, want over_budget", got)
	}
	limits := providerCapture(t, "aws/chat-completions-in-region-limits")
	for _, model := range awsInRegionModels {
		for name, want := range map[string]string{
			"max_tokens at the maximum":    "context_length_exceeded",
			"max_tokens above the maximum": "invalid_request",
			"max_tokens of 0":              "invalid_request",
		} {
			refusal := exchange(t, limits, model+" "+name)
			if refusal.Response.Status == http.StatusOK {
				continue
			}
			if got := billing.NormalizeUpstreamStatus(openai.ParseOpenAIError(refusal.errorReply(t))); got != want {
				t.Fatalf("%s %s = %s, want %s", model, name, got, want)
			}
		}
	}
	for _, capture := range []string{"openai/encrypted-reasoning-replay", "azure/encrypted-reasoning-replay"} {
		for _, name := range []string{"replay changed content", "replay another id", "replay without summary"} {
			refusal := exchange(t, providerCapture(t, capture), name)
			if got := billing.NormalizeUpstreamStatus(openai.ParseOpenAIError(refusal.errorReply(t))); got != "invalid_request" {
				t.Fatalf("%s, %s = %s, want invalid_request", capture, name, got)
			}
		}
	}
	otherAccount := providerCapture(t, "openai/encrypted-reasoning-other-account")
	for _, name := range []string{"openai reasoning sent to azure", "azure reasoning sent to openai"} {
		refusal := exchange(t, otherAccount, name)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(refusal.Response.Body, &body); err != nil || refusal.Response.Status != 400 || body.Error.Code != "invalid_encrypted_content" {
			t.Fatalf("%s: status %d, code %q", name, refusal.Response.Status, body.Error.Code)
		}
	}
}

// TestRecordedReasoningStreamKeepsEachEventsEncryptedReasoning replays a recorded OpenAI stream,
// which carries an item's encrypted reasoning in response.output_item.done and again in
// response.completed. The gateway returns each event's own value bound to the account, so a client
// can send back either one, whether or not OpenAI encrypts the two apart.
func TestRecordedReasoningStreamKeepsEachEventsEncryptedReasoning(t *testing.T) {
	stream := exchange(t, providerCapture(t, "openai/encrypted-reasoning-stream"), "stream")
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(stream.Request.Body, &fields); err != nil {
		t.Fatal(err)
	}
	fields["model"] = json.RawMessage(`"provider:openai gpt-6-luna"`)
	body, _ := json.Marshal(fields)
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	state := testPair(resolution)
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatal(err)
	}
	// encrypted returns the event's encrypted reasoning, which ingesting the event replaces.
	encrypted := func(event *schemas.BifrostResponsesStreamResponse) *string {
		if event.Type == schemas.ResponsesStreamResponseTypeOutputItemDone && event.Item != nil && event.Item.ResponsesReasoning != nil {
			return event.Item.ResponsesReasoning.EncryptedContent
		}
		if event.Type == schemas.ResponsesStreamResponseTypeCompleted {
			for _, item := range event.Response.Output {
				if item.ResponsesReasoning != nil && item.ResponsesReasoning.EncryptedContent != nil {
					return item.ResponsesReasoning.EncryptedContent
				}
			}
		}
		return nil
	}
	values := 0
	for _, event := range stream.responsesStream(t) {
		sent := encrypted(event)
		if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}); err != nil {
			t.Fatalf("recorded %s event refused: %v", event.Type, err)
		}
		if sent == nil {
			continue
		}
		values++
		if returned := encrypted(event); returned == nil || *returned != boundReasoning(*sent) {
			t.Fatalf("%s returned %v, want OpenAI's value bound to the account", event.Type, returned)
		}
	}
	if values != 2 {
		t.Fatalf("stream carried encrypted reasoning in %d events, want response.output_item.done and response.completed", values)
	}
}

// TestToolChoiceNoneReachesOnlyDeploymentsThatHoldTheModelToIt replays the recorded questions that
// need get_weather under tool_choice none, fresh and after an earlier call (captures
// aws/chat-completions-tool-choice-none, azure/other-model-formats-tool-choice-none,
// chutes/tool-choice-none and google-cloud/generate-content-tool-choice-none). The gateway sends
// tool_choice none with tools to each deployment of a model that answered thirty questions in
// text, fifteen of them after an earlier call, and refuses it before it holds funds for each one of
// a model that called the tool, wrote the call or answered fewer questions. Agent Platform and
// Chutes hold no model to none: each recorded Gemini model called the tool, and most Chutes models,
// a different few in each run, so the gateway refuses it on both routes.
func TestToolChoiceNoneReachesOnlyDeploymentsThatHoldTheModelToIt(t *testing.T) {
	catalogtest.UseFallback(t)
	// The catalog deployments of each recorded model on Bedrock and Azure: the profiles of every
	// geography, and the deployment types of the Azure deployment that the recording named.
	deployments := map[string][]string{
		"global.moonshotai.kimi-k3":             {"aws-kimi-k3", "aws-kimi-k3-us", "aws-kimi-k3-in"},
		"global.moonshotai.kimi-k3.1":           {"aws-kimi-k3.1-pro", "aws-kimi-k3.1-pro-us", "aws-kimi-k3.1-pro-in"},
		"openai.gpt-oss-120b-1:0":               {"aws-gpt-oss-120b-us"},
		"deepseek.v3.2":                         {"aws-deepseek-v3.2-us"},
		"qwen.qwen3-32b-v1:0":                   {"aws-qwen3-32b-us"},
		"nvidia.nemotron-super-3-120b":          {"aws-nemotron-3-super-us"},
		"mistral.mistral-large-3-675b-instruct": {"aws-mistral-large-2512-us"},
		"deepseek-v4-flash":                     {"azure-deepseek-v4-flash-0423", "azure-deepseek-v4-flash-0423-eu", "azure-deepseek-v4-flash-0423-us"},
		"deepseek-v4-pro":                       {"azure-deepseek-v4-pro", "azure-deepseek-v4-pro-us"},
		"gpt-oss-120b":                          {"azure-gpt-oss-120b", "azure-gpt-oss-120b-us"},
		"grok-4.6":                              {"azure-grok-4.6"},
		"grok-4.7":                              {"azure-grok-4.7", "azure-grok-4.7-us"},
		"kimi-k3.1-pro":                         {"azure-kimi-k3.1-pro"},
		"mistral-large-3":                       {"azure-mistral-large-2512", "azure-mistral-large-2512-eu", "azure-mistral-large-2512-us"},
		"mistral-large-4":                       {"azure-mistral-large-4", "azure-mistral-large-4-eu", "azure-mistral-large-4-us"},
		"mistral-medium-3-5":                    {"azure-mistral-medium-3-5", "azure-mistral-medium-3-5-eu", "azure-mistral-medium-3-5-us"},
	}
	held := map[string]bool{}
	leaked := map[string]int{}
	models := map[string]int{}
	for _, id := range []string{
		"aws/chat-completions-tool-choice-none", "azure/other-model-formats-tool-choice-none",
		"chutes/tool-choice-none", "google-cloud/generate-content-tool-choice-none",
	} {
		type answers struct {
			text, afterCall int
			leaked          bool
		}
		asked := map[string]*answers{}
		for _, took := range providerCapture(t, id) {
			if strings.Contains(took.Name, "without tools") || took.Response.Status != http.StatusOK {
				continue
			}
			// Google names the model in the path, and the others in the body.
			var request struct {
				Model string `json:"model"`
			}
			if err := json.Unmarshal(took.Request.Body, &request); err != nil {
				t.Fatal(err)
			}
			if _, model, inPath := strings.Cut(took.Request.Path, "/models/"); inPath {
				request.Model, _, _ = strings.Cut(model, ":")
			}
			model := asked[request.Model]
			if model == nil {
				model = &answers{}
				asked[request.Model] = model
			}
			switch {
			case toolCallUnderNone(t, took):
				model.leaked = true
			case strings.Contains(took.Name, " after a call "):
				model.text++
				model.afterCall++
			default:
				model.text++
			}
		}
		for model, answers := range asked {
			// A model that wrote a call one time in ten would answer thirty questions in text about
			// one time in twenty-four.
			held[model] = !answers.leaked && answers.text >= 30 && answers.afterCall >= 15
			if answers.leaked {
				leaked[id]++
			}
		}
		models[id] = len(asked)
	}
	if google := "google-cloud/generate-content-tool-choice-none"; leaked[google] != models[google] {
		t.Fatalf("%d of %d Gemini models called the tool under none", leaked[google], models[google])
	}
	if chutes := "chutes/tool-choice-none"; 2*leaked[chutes] <= models[chutes] {
		t.Fatalf("%d of %d Chutes models called the tool under none", leaked[chutes], models[chutes])
	}
	// GLM-5.2 answered in text in the recording and called the tool in another run.
	refused := []string{"chutes-deepseek-v3.2", "chutes-glm-5.2", "chutes-glm-5.2-unknown-hosted",
		"google-cloud-gemini-3.8-flash", "google-cloud-gemini-3.8-flash-eu", "google-cloud-gemini-4-hydrogen"}
	for model, ids := range deployments {
		holds, recorded := held[model]
		if !recorded {
			t.Fatalf("no recorded question to %s", model)
		}
		if !holds {
			refused = append(refused, ids...)
			continue
		}
		for _, id := range ids {
			t.Run(id, func(t *testing.T) {
				resolution, err := catalog.ResolveRequest(toolChoiceNoneRequest(id))
				if err != nil || resolution.Deployment.ID != id {
					t.Fatalf("%s answered every question in text, and the gateway answered %v", model, err)
				}
				if choice := string(resolution.RawBody()["tool_choice"]); choice != `"none"` {
					t.Fatalf("the gateway sends tool_choice %s", choice)
				}
			})
		}
	}
	for _, id := range refused {
		t.Run(id, func(t *testing.T) {
			if _, err := catalog.ResolveRequest(toolChoiceNoneRequest(id)); err == nil ||
				err.Error() != "tool choice none is not supported for the selected deployment" {
				t.Fatalf("the gateway answered %v", err)
			}
		})
	}
}

// toolChoiceNoneRequest is a Chat Completions request for a deployment with a tool under
// tool_choice none.
func toolChoiceNoneRequest(deployment string) catalog.RequestInput {
	body := `{"model":"` + deployment + `","messages":[{"role":"user","content":"What is the weather in Paris?"}],` +
		`"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}],"tool_choice":"none"}`
	return catalog.RequestInput{Method: http.MethodPost, Path: "/v1/chat/completions", Body: []byte(body)}
}

// writtenCall matches a call to get_weather that a model writes into its answer, as it does where
// its provider parses no call: the name in call markup, or followed by its city argument. A
// sentence that only names the tool answers in text.
var writtenCall = regexp.MustCompile(`[<>=.:\[\]{|_]get_weather|get_weather[<>{\[\]|]|get_weather[\s\S]{0,100}?(?:\bcity\b["']?\s*[:=>]|=["']?city\b)`)

// toolCallUnderNone reports whether a recorded reply under tool_choice none calls a tool or writes
// the call into its answer. Gemini answers in parts, and Mistral Medium 3.5 on Azure writes the call
// as a part that refers to the tool by name, followed by the arguments.
func toolCallUnderNone(t *testing.T, recorded providerExchange) bool {
	t.Helper()
	var reply struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text         string          `json:"text"`
					Thought      bool            `json:"thought"`
					FunctionCall json.RawMessage `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		Choices []struct {
			Message struct {
				Content   json.RawMessage   `json:"content"`
				ToolCalls []json.RawMessage `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(recorded.Response.Body, &reply); err != nil {
		t.Fatalf("%s: %v", recorded.Name, err)
	}
	for _, candidate := range reply.Candidates {
		for _, part := range candidate.Content.Parts {
			if part.FunctionCall != nil || !part.Thought && writtenCall.MatchString(part.Text) {
				return true
			}
		}
	}
	for _, choice := range reply.Choices {
		if len(choice.Message.ToolCalls) > 0 {
			return true
		}
		var text string
		if content := choice.Message.Content; len(content) > 0 && json.Unmarshal(content, &text) != nil {
			var parts []struct {
				Text         string   `json:"text"`
				ReferenceIDs []string `json:"reference_ids"`
			}
			if err := json.Unmarshal(content, &parts); err != nil {
				t.Fatalf("%s: %v", recorded.Name, err)
			}
			for _, part := range parts {
				text += part.Text + " " + strings.Join(part.ReferenceIDs, " ")
			}
		}
		if _, answer, _ := bedrockReasoning(text); writtenCall.MatchString(answer) {
			return true
		}
	}
	return false
}
