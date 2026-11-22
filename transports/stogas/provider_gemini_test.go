package stogas

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	geminiprovider "github.com/maximhq/bifrost/core/providers/gemini"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/catalog/catalogtest"
)

const (
	geminiChatPath      = "/v1/chat/completions"
	geminiResponsesPath = "/v1/responses"
	// geminiWeather is the client's form of the function that the recorded tool requests declare.
	geminiWeather = `"tools":[{"type":"function","function":{"name":"get_weather","description":"Returns a city's weather.","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}}}]`
	// geminiAsk is the client's form of the recorded tool requests without a tool choice.
	geminiAsk = `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"What is the weather in Paris and in Rome? Look up each city."}],"max_completion_tokens":2000,"reasoning_effort":"low",` + geminiWeather
)

// resolveGoogleState resolves a client's request for a Google Cloud deployment, through an account
// that the test pair's credential reaches, and checks it as the gateway does before it holds funds.
func resolveGoogleState(t *testing.T, path, body string) (*State, error) {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: http.MethodPost, Path: path, Body: []byte(body)})
	if err != nil {
		return nil, err
	}
	if resolution.Provider != catalog.ProviderGoogleCloud {
		t.Fatalf("provider = %q, want Google Cloud", resolution.Provider)
	}
	state := testPair(resolution)
	if err := state.Adapter.ValidateRequest(state); err != nil {
		return nil, err
	}
	return state, state.Adapter.SanitizeRequest(state)
}

// googleBody prepares a client's request for a Google Cloud deployment, Gemini or an open model,
// and returns the body that Agent Platform receives.
func googleBody(t *testing.T, path, body string) []byte {
	t.Helper()
	state, err := resolveGoogleState(t, path, body)
	if err != nil {
		t.Fatal(err)
	}
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

// geminiChatReply converts a recorded generateContent reply as core does.
func geminiChatReply(t *testing.T, recorded providerExchange) *schemas.BifrostChatResponse {
	t.Helper()
	response := &geminiprovider.GenerateContentResponse{}
	if err := sonic.Unmarshal(recorded.Response.Body, response); err != nil {
		t.Fatalf("%s: %v", recorded.Name, err)
	}
	return response.ToBifrostChatResponse()
}

// geminiClientReply returns a recorded generateContent reply to a client's request as the client gets
// it, through an account that the test pair's credential reaches.
func geminiClientReply(t *testing.T, client string, recorded providerExchange) *schemas.BifrostChatResponse {
	t.Helper()
	state, err := resolveGoogleState(t, geminiChatPath, client)
	if err != nil {
		t.Fatal(err)
	}
	reply := geminiChatReply(t, recorded)
	if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ChatResponse: reply}, nil); err != nil {
		t.Fatalf("%s: %v", recorded.Name, err)
	}
	return reply
}

// geminiRecordedPart returns the first file of a recorded request, inline or by URL, as a client's
// content part: an image, a file or audio. Core sends an image URL with the type of its extension,
// or JPEG, and a file URL with its file_type, or the type of its extension.
func geminiRecordedPart(t *testing.T, recorded providerExchange) string {
	t.Helper()
	var request struct {
		Contents []struct {
			Parts []struct {
				InlineData struct {
					Data     string `json:"data"`
					MimeType string `json:"mimeType"`
				} `json:"inlineData"`
				FileData struct {
					FileURI  string `json:"fileUri"`
					MimeType string `json:"mimeType"`
				} `json:"fileData"`
			} `json:"parts"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(recorded.Request.Body, &request); err != nil || len(request.Contents) == 0 || len(request.Contents[0].Parts) == 0 {
		t.Fatalf("decode %s: %v", recorded.Name, err)
	}
	if linked := request.Contents[0].Parts[0].FileData; linked.FileURI != "" {
		uri, _ := json.Marshal(linked.FileURI)
		if strings.HasPrefix(linked.MimeType, "image/") {
			return `{"type":"image_url","image_url":{"url":` + string(uri) + `}}`
		}
		fileType := ""
		if path.Ext(linked.FileURI) == "" {
			fileType = `,"file_type":"` + linked.MimeType + `"`
		}
		return `{"type":"file","file":{"file_url":` + string(uri) + fileType + `}}`
	}
	inline := request.Contents[0].Parts[0].InlineData
	switch inline.MimeType {
	case "image/png":
		return `{"type":"image_url","image_url":{"url":"data:image/png;base64,` + inline.Data + `"}}`
	case "audio/wav":
		return `{"type":"input_audio","input_audio":{"data":"` + inline.Data + `","format":"wav"}}`
	}
	name := map[string]string{"application/pdf": "note.pdf", "text/plain": "note.txt"}[inline.MimeType]
	if name == "" {
		name = "report.docx"
	}
	return `{"type":"file","file":{"filename":"` + name + `","file_data":"data:` + inline.MimeType + `;base64,` + inline.Data + `"}}`
}

// geminiRecordedText returns the text of the last part of a recorded request's first message.
func geminiRecordedText(t *testing.T, recorded providerExchange) string {
	t.Helper()
	var request struct {
		Contents []struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(recorded.Request.Body, &request); err != nil || len(request.Contents) == 0 || len(request.Contents[0].Parts) == 0 {
		t.Fatalf("decode %s: %v", recorded.Name, err)
	}
	text, _ := json.Marshal(request.Contents[0].Parts[len(request.Contents[0].Parts)-1].Text)
	return string(text)
}

// TestGeminiSendsWhatGoogleTook prepares clients' requests in OpenAI's fields, on both interfaces,
// for Gemini on Google Cloud, and each body must equal a request that Agent Platform took in the
// recordings. Gemini 3.8 Flash ignores temperature, top_p and top_k, and Agent Platform has no
// field for an end user, store or metadata, so none of them reaches it. A final assistant message
// stays, which Gemini 3.5 Flash continued. Google fetched each image and file URL, whatever it
// held, such as an MP3 that the request calls an image.
func TestGeminiSendsWhatGoogleTook(t *testing.T) {
	catalogtest.UseFallback(t)
	fields := providerCapture(t, "google-cloud/generate-content-request-fields")
	tools := providerCapture(t, "google-cloud/generate-content-tools")
	files := providerCapture(t, "google-cloud/generate-content-files")
	stream := providerCapture(t, "google-cloud/generate-content-stream")
	caching := providerCapture(t, "google-cloud/generate-content-implicit-caching")
	trailing := providerCapture(t, "google-cloud/generate-content-trailing-model-turn")
	invent := geminiRecordedText(t, exchange(t, fields, "gemini-3.1-flash-lite: seed 7, run 1"))
	file := func(name, question string) string {
		return `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":[` + geminiRecordedPart(t, exchange(t, files, name)) +
			`,{"type":"text","text":` + question + `}]}],"max_completion_tokens":2000,"reasoning_effort":"low"}`
	}
	linked := func(name string) string { return file(name, geminiRecordedText(t, exchange(t, files, name))) }
	arithmetic := `"messages":[{"role":"user","content":"What is 17*23? Answer with the number only."}],"max_completion_tokens":4000`
	for _, test := range []struct {
		took   providerExchange
		path   string
		client string
	}{
		{exchange(t, fields, "gemini-3.8-flash: a system instruction and stop sequences"), geminiChatPath,
			`{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"developer","content":"Answer in one word."},{"role":"user","content":"Say OK."}],"max_completion_tokens":2000,"reasoning_effort":"low","stop":["END"],"temperature":0.2,"top_p":0.5,"top_k":5,"user":"user-1","safety_identifier":"user-hash","store":false,"metadata":{"run":"1"}}`},
		{exchange(t, fields, "gemini-3.5-flash: frequencyPenalty and presencePenalty 0.5"), geminiChatPath,
			`{"model":"google-cloud-gemini-3.5-flash","messages":[{"role":"user","content":"Say OK."}],"max_tokens":2000,"reasoning_effort":"minimal","frequency_penalty":0.5,"presence_penalty":0.5}`},
		{exchange(t, fields, "gemini-3.1-flash-lite: seed 7, run 1"), geminiChatPath,
			`{"model":"google-cloud-gemini-3.1-flash-lite","messages":[{"role":"user","content":` + invent + `}],"max_completion_tokens":2000,"reasoning_effort":"minimal","seed":7}`},
		{exchange(t, fields, "gemini-3.5-flash-lite: thinkingLevel MEDIUM"), geminiResponsesPath,
			`{"model":"google-cloud-gemini-3.5-flash-lite","input":"Say OK.","max_output_tokens":2000,"reasoning":{"effort":"medium","summary":"auto"},"store":false}`},
		{exchange(t, tools, "tools at mode AUTO"), geminiChatPath, geminiAsk + `}`},
		{exchange(t, tools, "mode ANY"), geminiChatPath, geminiAsk + `,"tool_choice":"required"}`},
		{exchange(t, tools, "mode ANY with allowedFunctionNames"), geminiChatPath, geminiAsk + `,"tool_choice":{"type":"function","function":{"name":"get_weather"}}}`},
		{exchange(t, tools, "responseJsonSchema"), geminiChatPath,
			`{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"Name the capital of France."}],"max_completion_tokens":2000,"reasoning_effort":"low","response_format":{"type":"json_schema","json_schema":{"name":"capital","strict":true,"schema":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}}}}`},
		{exchange(t, files, "png"), geminiChatPath, file("png", `"What color is this image? Answer with one word."`)},
		{exchange(t, files, "pdf"), geminiChatPath, file("pdf", `"What is the code? Answer with it only."`)},
		{exchange(t, files, "txt"), geminiChatPath, file("txt", `"What is the code? Answer with it only."`)},
		{exchange(t, files, "wav"), geminiChatPath, file("wav", `"Describe this sound in a few words."`)},
		{exchange(t, files, "image url"), geminiChatPath, linked("image url")},
		{exchange(t, files, "image url on another host"), geminiChatPath, linked("image url on another host")},
		{exchange(t, files, "web page called an image"), geminiChatPath, linked("web page called an image")},
		{exchange(t, files, "mp3 called an image"), geminiChatPath, linked("mp3 called an image")},
		{exchange(t, files, "mp3 url"), geminiChatPath, linked("mp3 url")},
		{exchange(t, files, "pdf url"), geminiChatPath, linked("pdf url")},
		{exchange(t, files, "pdf url without an extension"), geminiChatPath, linked("pdf url without an extension")},
		{exchange(t, stream, "stream with thought summaries"), geminiChatPath,
			`{"model":"google-cloud-gemini-3.8-flash",` + arithmetic + `,"reasoning_effort":"medium","stream":true,"stream_options":{"include_usage":true}}`},
		{exchange(t, stream, "reply without thoughts"), geminiChatPath,
			`{"model":"google-cloud-gemini-3.8-flash",` + arithmetic + `,"reasoning":{"effort":"medium","display":"omitted"}}`},
		{exchange(t, trailing, "gemini-3.5-flash: a trailing model turn"), geminiChatPath,
			`{"model":"google-cloud-gemini-3.5-flash","messages":[{"role":"user","content":"Name one primary color. Answer with one short sentence."},{"role":"assistant","content":"The primary color I name is"}],"max_completion_tokens":500,"reasoning_effort":"minimal"}`},
		{exchange(t, caching, "first request"), geminiChatPath,
			`{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":` + geminiRecordedText(t, exchange(t, caching, "first request")) + `}],"max_completion_tokens":2000,"reasoning_effort":"low"}`},
	} {
		t.Run(test.took.Name, func(t *testing.T) {
			if test.took.Response.Status != http.StatusOK {
				t.Fatalf("Agent Platform answered %d in the recording", test.took.Response.Status)
			}
			if sent := googleBody(t, test.path, test.client); !sameJSON(t, sent, test.took.Request.Body) {
				t.Fatalf("sent %s, Agent Platform took %s", sent, test.took.Request.Body)
			}
		})
	}
}

// TestGeminiRefusesWhatGoogleRefuses checks each request that Agent Platform refused or cannot
// carry out: log probabilities, one tool call per turn, which Gemini has no control for while it
// made two calls in one turn in the recording, a Word document, tool_choice none with tools, which
// each recorded Gemini model broke after an earlier call (TestToolChoiceNoneReachesOnlyDeploymentsThatHoldTheModelToIt),
// and penalties, temperature and thinking levels that a model refuses or ignores. The gateway
// refuses the first four before it holds funds, and leaves out the fields that only tune sampling.
func TestGeminiRefusesWhatGoogleRefuses(t *testing.T) {
	catalogtest.UseFallback(t)
	fields := providerCapture(t, "google-cloud/generate-content-request-fields")
	tools := providerCapture(t, "google-cloud/generate-content-tools")
	files := providerCapture(t, "google-cloud/generate-content-files")
	for _, recorded := range []providerExchange{
		exchange(t, fields, "gemini-3.8-flash: responseLogprobs"),
		exchange(t, files, "docx"),
	} {
		if recorded.Response.Status != http.StatusBadRequest {
			t.Fatalf("%s: Agent Platform answered %d in the recording", recorded.Name, recorded.Response.Status)
		}
	}
	if calls := geminiChatReply(t, exchange(t, tools, "tools at mode AUTO")).Choices[0].Message.ToolCalls; len(calls) != 2 {
		t.Fatalf("the recording holds %d calls in one turn, want 2", len(calls))
	}
	for name, client := range map[string]string{
		"logprobs":         `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"Say OK."}],"logprobs":true,"top_logprobs":2}`,
		"top_logprobs":     `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"Say OK."}],"top_logprobs":2}`,
		"tool_choice none": geminiAsk + `,"tool_choice":"none"}`,
		"a Word document": `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":[` +
			geminiRecordedPart(t, exchange(t, files, "docx")) + `,{"type":"text","text":"Summarize."}]}]}`,
		"a function tool on Responses that Claude defines": `{"model":"google-cloud-gemini-3.8-flash","input":"Hi","tools":[{"type":"bash_20250124","name":"bash"}]}`,
		"a hosted tool on Responses":                       `{"model":"google-cloud-gemini-3.8-flash","input":"Hi","tools":[{"type":"web_search"}]}`,
		// Core would ground the reply with Google Search, which keeps queries and has no price here.
		"web_search_options":              `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"Say OK."}],"web_search_options":{}}`,
		"web_search_options on Responses": `{"model":"google-cloud-gemini-3.8-flash","input":"Hi","web_search_options":{}}`,
		"the Flex tier":                   `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"Say OK."}],"service_tier":"flex"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := geminiChatPath
			if strings.Contains(client, `"input"`) {
				path = geminiResponsesPath
			}
			if _, err := resolveGoogleState(t, path, client); err == nil {
				t.Fatal("the gateway took the request")
			}
		})
	}
	// The deployments run at Standard only, so a body names no tier.
	if body := googleBody(t, geminiChatPath, `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"Say OK."}],"service_tier":"default"}`); strings.Contains(string(body), "serviceTier") {
		t.Fatalf("sent %s", body)
	}
	// The gateway leaves out what a model refuses or ignores, and sends an effort as the nearest
	// thinking level that the model takes.
	for _, test := range []struct{ refused, client string }{
		{"gemini-3.8-flash: frequencyPenalty and presencePenalty 0.5", `"frequency_penalty":0.5,"presence_penalty":0.5,"reasoning_effort":"low"`},
		{"gemini-3.8-flash: thinkingLevel MINIMAL", `"reasoning_effort":"minimal"`},
		{"gemini-3.8-flash: thinkingLevel XHIGH", `"reasoning_effort":"xhigh"`},
	} {
		t.Run(test.refused, func(t *testing.T) {
			refused := exchange(t, fields, test.refused)
			if refused.Response.Status != http.StatusBadRequest {
				t.Fatalf("Agent Platform answered %d in the recording", refused.Response.Status)
			}
			var sent struct {
				GenerationConfig map[string]json.RawMessage `json:"generationConfig"`
			}
			body := googleBody(t, geminiChatPath, `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"Say OK."}],`+test.client+`}`)
			if err := json.Unmarshal(body, &sent); err != nil {
				t.Fatal(err)
			}
			var thinking struct {
				ThinkingLevel string `json:"thinkingLevel"`
			}
			_ = json.Unmarshal(sent.GenerationConfig["thinkingConfig"], &thinking)
			if _, penalty := sent.GenerationConfig["frequencyPenalty"]; penalty || !slices.Contains([]string{"LOW", "MEDIUM", "HIGH"}, thinking.ThinkingLevel) {
				t.Fatalf("sent %s", body)
			}
		})
	}
}

// TestGeminiTakesSystemMessagesOnlyBeforeTheConversation: generateContent takes system instructions
// before the conversation only, so a system or developer message after it starts gets 400 on
// either interface, as on Claude models without the role there, instead of becoming user text.
func TestGeminiTakesSystemMessagesOnlyBeforeTheConversation(t *testing.T) {
	for _, test := range []struct{ path, client, want string }{
		{geminiChatPath, `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"Hi."},` +
			`{"role":"assistant","content":"Hello."},{"role":"developer","content":"Answer in French."},{"role":"user","content":"Again."}]}`,
			"messages[3].role cannot be preserved after the conversation starts on Gemini on Google Cloud"},
		{geminiResponsesPath, `{"model":"google-cloud-gemini-3.8-flash","instructions":"Be brief.","input":[{"role":"user","content":"Hi."},{"role":"developer","content":"Answer in French."}]}`,
			"input[1].role cannot be preserved after the conversation starts on Gemini on Google Cloud"},
	} {
		if _, err := resolveGoogleState(t, test.path, test.client); err == nil || err.Error() != test.want {
			t.Errorf("%s: error %v, want %q", test.path, err, test.want)
		}
	}
	body := googleBody(t, geminiChatPath, `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"system","content":"Be brief."},{"role":"developer","content":"Answer in French."},{"role":"user","content":"Hi."}]}`)
	var sent struct {
		SystemInstruction struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"systemInstruction"`
		Contents []json.RawMessage `json:"contents"`
	}
	if err := json.Unmarshal(body, &sent); err != nil || len(sent.SystemInstruction.Parts) != 2 || len(sent.Contents) != 1 {
		t.Fatalf("sent %s", body)
	}
}

// TestGeminiGetsAnEarlierRefusalAsText: Gemini has no refusal field, so an earlier refusal reaches
// it as the text that the model wrote, on either interface, as on Claude.
func TestGeminiGetsAnEarlierRefusalAsText(t *testing.T) {
	for path, client := range map[string]string{
		geminiChatPath: `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"Hi."},{"role":"assistant","refusal":"I can't help with that."},{"role":"user","content":"Why?"}]}`,
		geminiResponsesPath: `{"model":"google-cloud-gemini-3.8-flash","input":[{"role":"user","content":"Hi."},` +
			`{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"I can't help with that."}]},{"role":"user","content":"Why?"}]}`,
	} {
		var sent struct {
			Contents []struct {
				Role  string `json:"role"`
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"contents"`
		}
		body := googleBody(t, path, client)
		if err := json.Unmarshal(body, &sent); err != nil || len(sent.Contents) != 3 || sent.Contents[1].Role != "model" ||
			len(sent.Contents[1].Parts) != 1 || sent.Contents[1].Parts[0].Text != "I can't help with that." {
			t.Fatalf("%s: sent %s", path, body)
		}
	}
}

// TestGeminiShowsThoughtSummariesAsAsked: Gemini returns summaries of its thoughts only when a
// request asks (includeThoughts), which the gateway does for every display but omitted and updates,
// and on Responses for every summary but Claude's none and updates, which mean the same.
func TestGeminiShowsThoughtSummariesAsAsked(t *testing.T) {
	chat, responses := `"messages":[{"role":"user","content":"Hi."}]`, `"input":"Hi."`
	for _, test := range []struct {
		path, client string
		shown        bool
	}{
		{geminiChatPath, chat, true},
		{geminiChatPath, chat + `,"reasoning_display":"summarized"`, true},
		{geminiChatPath, chat + `,"reasoning_display":"omitted"`, false},
		{geminiChatPath, chat + `,"reasoning_display":"updates"`, false},
		{geminiResponsesPath, responses, true},
		{geminiResponsesPath, responses + `,"reasoning":{"summary":"detailed"}`, true},
		{geminiResponsesPath, responses + `,"reasoning":{"summary":"none"}`, false},
		{geminiResponsesPath, responses + `,"reasoning":{"summary":"updates","effort":"high"}`, false},
	} {
		var sent struct {
			GenerationConfig struct {
				ThinkingConfig struct {
					IncludeThoughts bool `json:"includeThoughts"`
				} `json:"thinkingConfig"`
			} `json:"generationConfig"`
		}
		body := googleBody(t, test.path, `{"model":"google-cloud-gemini-3.8-flash",`+test.client+`}`)
		if err := json.Unmarshal(body, &sent); err != nil || sent.GenerationConfig.ThinkingConfig.IncludeThoughts != test.shown {
			t.Errorf("%s: sent %s", test.client, body)
		}
	}
}

// TestGeminiStatesWhatGoogleTook compares what the catalog states for each recorded Gemini model,
// on every endpoint, with what Agent Platform did in the recording: the efforts are the thinking
// levels that it took, penalties are taken where it took them, and temperature, top_p and top_k
// are applied where at least two of three candidates agreed. Every model took a seed.
func TestGeminiStatesWhatGoogleTook(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "google-cloud/generate-content-request-fields")
	for _, model := range []string{"gemini-3.8-flash", "gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite"} {
		took := func(label string) bool {
			return exchange(t, recorded, model+": "+label).Response.Status == http.StatusOK
		}
		// distinct counts the different answers of three candidates, which core's conversion
		// leaves out after the first.
		distinct := func(label string) int {
			var reply struct {
				Candidates []struct {
					Content struct {
						Parts []struct {
							Text    string `json:"text"`
							Thought bool   `json:"thought"`
						} `json:"parts"`
					} `json:"content"`
				} `json:"candidates"`
			}
			if err := json.Unmarshal(exchange(t, recorded, model+": "+label+", three candidates").Response.Body, &reply); err != nil || len(reply.Candidates) != 3 {
				t.Fatalf("%s %s: %d candidates, %v", model, label, len(reply.Candidates), err)
			}
			answers := map[string]bool{}
			for _, candidate := range reply.Candidates {
				var answer strings.Builder
				for _, part := range candidate.Content.Parts {
					if !part.Thought {
						answer.WriteString(part.Text)
					}
				}
				answers[strings.TrimSpace(answer.String())] = true
			}
			return len(answers)
		}
		agree := func(label string) bool { return distinct(label) < 3 }
		if distinct("no sampling field") < 2 {
			t.Fatalf("%s: candidates agree without sampling fields, so agreement shows nothing", model)
		}
		var levels []string
		for _, level := range []string{"MINIMAL", "LOW", "MEDIUM", "HIGH", "XHIGH"} {
			if took("thinkingLevel " + level) {
				levels = append(levels, strings.ToLower(level))
			}
		}
		applied := catalog.Sampling{
			Temperature:      agree("temperature 0"),
			TopP:             agree("topP 0.01"),
			TopK:             agree("topK 1"),
			FrequencyPenalty: took("frequencyPenalty and presencePenalty 0.5"),
			PresencePenalty:  took("frequencyPenalty and presencePenalty 0.5"),
			Seed:             took("seed 7, run 1"),
		}
		for _, suffix := range []string{"", "-us", "-eu"} {
			deploymentID := "google-cloud-" + model + suffix
			t.Run(deploymentID, func(t *testing.T) {
				state, err := resolveGoogleState(t, geminiChatPath, `{"model":"`+deploymentID+`","messages":[{"role":"user","content":"Say OK."}]}`)
				if err != nil {
					t.Fatal(err)
				}
				deployment := state.Resolution.Deployment
				if !slices.Equal(deployment.ReasoningEfforts, levels) {
					t.Errorf("the catalog states efforts %v, and Agent Platform took %v", deployment.ReasoningEfforts, levels)
				}
				if deployment.Sampling != applied {
					t.Errorf("the catalog states sampling %+v, and the recording shows %+v", deployment.Sampling, applied)
				}
			})
		}
	}
}

// TestGeminiSendsToolCallsBackAsGoogleTookThem takes the recorded reply with two calls in one turn
// as a client gets it, sends the assistant message back with each call's result, and the body must
// equal the recorded request that Agent Platform answered: the calls with their IDs, the first with
// its thought signature and the second with Google's placeholder, and both results in one turn.
// Agent Platform refused the calls without signatures.
func TestGeminiSendsToolCallsBackAsGoogleTookThem(t *testing.T) {
	catalogtest.UseFallback(t)
	tools := providerCapture(t, "google-cloud/generate-content-tools")
	if refused := exchange(t, tools, "the calls back without signatures"); refused.Response.Status != http.StatusBadRequest {
		t.Fatalf("Agent Platform answered calls without signatures with %d", refused.Response.Status)
	}
	recorded := exchange(t, tools, "tools at mode AUTO")
	reply := geminiClientReply(t, geminiAsk+`}`, recorded)
	message := reply.Choices[0].Message
	if reply.Choices[0].FinishReason == nil || *reply.Choices[0].FinishReason != "tool_calls" || len(message.ToolCalls) != 2 {
		t.Fatalf("reply %+v", reply.Choices[0])
	}
	// The client gets the IDs that Gemini gave, the summary of its thoughts and the first call's
	// signature bound to the account.
	var made struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text             string `json:"text"`
					ThoughtSignature string `json:"thoughtSignature"`
					FunctionCall     *struct {
						ID string `json:"id"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(recorded.Response.Body, &made); err != nil {
		t.Fatal(err)
	}
	parts := made.Candidates[0].Content.Parts
	assistant := message.ChatAssistantMessage
	details, _ := json.Marshal(assistant.ReasoningDetails)
	want, _ := json.Marshal([]schemas.ChatReasoningDetails{
		{Index: 0, Type: schemas.BifrostReasoningDetailsTypeSummary, Summary: &parts[0].Text},
		{Index: 1, Type: schemas.BifrostReasoningDetailsTypeEncrypted, ID: schemas.Ptr("tool_call_" + parts[1].FunctionCall.ID), Data: schemas.Ptr("gemini:" + testAccount + ":" + parts[1].ThoughtSignature)},
	})
	if *message.ToolCalls[0].ID != parts[1].FunctionCall.ID || *message.ToolCalls[1].ID != parts[2].FunctionCall.ID ||
		assistant.Reasoning == nil || *assistant.Reasoning != parts[0].Text || string(details) != string(want) {
		encoded, _ := json.Marshal(message)
		t.Fatalf("the client got %s", encoded)
	}
	took := exchange(t, tools, "the calls back with their signatures")
	if sent := googleBody(t, geminiChatPath, geminiCallsBack(t, "gemini-3.8-flash", message)); !sameJSON(t, sent, took.Request.Body) {
		t.Fatalf("sent %s, Agent Platform took %s", sent, took.Request.Body)
	}
}

// TestGeminiTakesCallsOfOtherProviders sends a call that another provider made, with its result,
// and each body must equal a request that Agent Platform answered: Gemini took every ID that fits
// the gateway's 64 bytes, so each goes as the client wrote it, with Google's placeholder for the
// signature that no other provider writes.
func TestGeminiTakesCallsOfOtherProviders(t *testing.T) {
	catalogtest.UseFallback(t)
	ids := providerCapture(t, "google-cloud/generate-content-foreign-call-ids")
	for label, id := range map[string]string{
		"Kimi's ID":         "functions.get_weather:0",
		"Claude's ID":       "toolu_01A09q90qw90lq917835lq9",
		"an ID of 64 bytes": "call 1/2+3=4|x.y:z#\u00e4" + strings.Repeat("a", 43),
	} {
		took := exchange(t, ids, label)
		if took.Response.Status != http.StatusOK {
			t.Fatalf("%s: Agent Platform answered %d", label, took.Response.Status)
		}
		client := `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"What is the weather in Paris? Look it up."},` +
			`{"role":"assistant","tool_calls":[{"type":"function","id":` + strconv.Quote(id) + `,"function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]},` +
			`{"role":"tool","tool_call_id":` + strconv.Quote(id) + `,"content":"Sunny, 21 C"}],"max_completion_tokens":2000,"reasoning_effort":"low",` + geminiWeather + `}`
		if sent := googleBody(t, geminiChatPath, client); !sameJSON(t, sent, took.Request.Body) {
			t.Fatalf("%s: sent %s, Agent Platform took %s", label, sent, took.Request.Body)
		}
	}
}

// geminiCallsBack is a client's request to a Gemini model with the calls of an assistant message
// as the client got it, each with its result.
func geminiCallsBack(t *testing.T, model string, message *schemas.ChatMessage) string {
	t.Helper()
	return `{"model":"google-cloud-` + model + `","messages":` + geminiCallsBackMessages(t, message) + `,"max_completion_tokens":2000,"reasoning_effort":"low",` + geminiWeather + `}`
}

// geminiCallsBackMessages are the messages of geminiCallsBack.
func geminiCallsBackMessages(t *testing.T, message *schemas.ChatMessage) string {
	t.Helper()
	assistant, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	messages := []string{`{"role":"user","content":"What is the weather in Paris and in Rome? Look up each city."}`, string(assistant)}
	for _, call := range message.ToolCalls {
		result := "Sunny, 21 C"
		if strings.Contains(call.Function.Arguments, "Rome") {
			result = "Rain, 14 C"
		}
		messages = append(messages, `{"role":"tool","tool_call_id":`+strconv.Quote(*call.ID)+`,"content":`+strconv.Quote(result)+`}`)
	}
	return "[" + strings.Join(messages, ",") + "]"
}

// TestGeminiSendsSignaturesBackAsGoogleTookThem sends recorded replies back as a client got them,
// and each body must equal a request that Agent Platform answered: an answer with its signature on
// its text part, and the calls of Gemini 3.8 Flash with its signature to other Gemini models, which
// took them. Agent Platform refused a changed signature of either kind, so the gateway sends each
// back unchanged.
func TestGeminiSendsSignaturesBackAsGoogleTookThem(t *testing.T) {
	catalogtest.UseFallback(t)
	signatures := providerCapture(t, "google-cloud/generate-content-thought-signatures")
	for _, refused := range []string{"gemini-3.8-flash: the calls back with a changed signature", "gemini-3.8-flash: the answer back with a changed signature"} {
		if status := exchange(t, signatures, refused).Response.Status; status != http.StatusBadRequest {
			t.Fatalf("%s: Agent Platform answered %d", refused, status)
		}
	}
	question := `{"role":"user","content":"Name a color of the French flag. Answer with one word."}`
	answer := geminiClientReply(t, `{"model":"google-cloud-gemini-3.8-flash","messages":[`+question+`],"max_completion_tokens":2000,"reasoning_effort":"low"}`,
		exchange(t, signatures, "gemini-3.8-flash: an answer")).Choices[0].Message
	encoded, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}
	client := `{"model":"google-cloud-gemini-3.8-flash","messages":[` + question + `,` + string(encoded) + `,{"role":"user","content":"Name another one."}],"max_completion_tokens":2000,"reasoning_effort":"low"}`
	took := exchange(t, signatures, "gemini-3.8-flash: the answer back with its signature")
	if sent := googleBody(t, geminiChatPath, client); !sameJSON(t, sent, took.Request.Body) {
		t.Fatalf("sent %s, Agent Platform took %s", sent, took.Request.Body)
	}
	calls := geminiClientReply(t, geminiAsk+`}`, exchange(t, signatures, "gemini-3.8-flash: calls at mode AUTO")).Choices[0].Message
	for _, model := range []string{"gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite"} {
		took := exchange(t, signatures, model+": the calls of gemini-3.8-flash back")
		if sent := googleBody(t, geminiChatPath, geminiCallsBack(t, model, calls)); !sameJSON(t, sent, took.Request.Body) {
			t.Fatalf("%s: sent %s, Agent Platform took %s", model, sent, took.Request.Body)
		}
	}
}

// TestGeminiStreamGivesSignaturesBack streams a recorded reply to a client: the thought summary
// arrives as reasoning text and one summary detail, and the answer's signature, which Gemini sends
// with an empty text part last, as encrypted reasoning bound to the account under an index of its
// own. The client's message, joined from the stream, takes the signature back to the answer's text
// part.
func TestGeminiStreamGivesSignaturesBack(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := exchange(t, providerCapture(t, "google-cloud/generate-content-stream"), "stream with thought summaries")
	ask := `"messages":[{"role":"user","content":"What is 17*23? Answer with the number only."}],"max_completion_tokens":4000,"reasoning_effort":"medium"`
	state, err := resolveGoogleState(t, geminiChatPath, `{"model":"google-cloud-gemini-3.8-flash",`+ask+`,"stream":true,"stream_options":{"include_usage":true}}`)
	if err != nil {
		t.Fatal(err)
	}
	var thoughts, signature string
	stream := geminiprovider.NewGeminiStreamState()
	var content, reasoning strings.Builder
	details := map[int]schemas.ChatReasoningDetails{}
	for _, event := range recorded.Response.Events {
		var parts struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text             string `json:"text"`
						Thought          bool   `json:"thought"`
						ThoughtSignature string `json:"thoughtSignature"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(event, &parts); err != nil {
			t.Fatal(err)
		}
		for _, part := range parts.Candidates[0].Content.Parts {
			if part.Thought {
				thoughts += part.Text
			}
			if part.ThoughtSignature != "" {
				signature = part.ThoughtSignature
			}
		}
		response := &geminiprovider.GenerateContentResponse{}
		if err := sonic.Unmarshal(event, response); err != nil {
			t.Fatal(err)
		}
		chunks, bifrostErr, _ := response.ToBifrostChatCompletionStream(stream)
		if bifrostErr != nil {
			t.Fatal(bifrostErr.Error.Message)
		}
		for _, chunk := range chunks {
			if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
				encoded, _ := json.Marshal(chunk)
				t.Fatalf("%v: %s", err, encoded)
			}
			for _, choice := range chunk.Choices {
				delta := choice.ChatStreamResponseChoice.Delta
				if delta.Content != nil {
					content.WriteString(*delta.Content)
				}
				if delta.Reasoning != nil {
					reasoning.WriteString(*delta.Reasoning)
				}
				// A client joins the parts of each detail by index.
				for _, detail := range delta.ReasoningDetails {
					joined, ok := details[detail.Index]
					if ok && detail.Summary != nil {
						detail.Summary = schemas.Ptr(*joined.Summary + *detail.Summary)
					}
					details[detail.Index] = detail
				}
			}
		}
	}
	if thoughts == "" || signature == "" || reasoning.String() != thoughts || len(details) != 2 ||
		details[0].Summary == nil || *details[0].Summary != thoughts ||
		details[1].Data == nil || *details[1].Data != "gemini:"+testAccount+":"+signature || details[1].ID != nil {
		t.Fatalf("the client got reasoning %q and details %+v", reasoning.String(), details)
	}
	message, err := json.Marshal(schemas.ChatMessage{
		Role:    schemas.ChatMessageRoleAssistant,
		Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr(content.String())},
		ChatAssistantMessage: &schemas.ChatAssistantMessage{
			Reasoning:        schemas.Ptr(reasoning.String()),
			ReasoningDetails: []schemas.ChatReasoningDetails{details[0], details[1]},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var sent struct {
		Contents []struct {
			Parts []map[string]json.RawMessage `json:"parts"`
		} `json:"contents"`
	}
	body := googleBody(t, geminiChatPath, `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"What is 17*23? Answer with the number only."},`+string(message)+`,{"role":"user","content":"And 17*24?"}],"max_completion_tokens":4000,"reasoning_effort":"medium"}`)
	if err := json.Unmarshal(body, &sent); err != nil || len(sent.Contents) != 3 || len(sent.Contents[1].Parts) != 1 ||
		string(sent.Contents[1].Parts[0]["text"]) != strconv.Quote(content.String()) || string(sent.Contents[1].Parts[0]["thoughtSignature"]) != strconv.Quote(signature) {
		t.Fatalf("sent %s", body)
	}
}

// TestGeminiResponsesSendsCallsBackAsGoogleTookThem is TestGeminiSendsToolCallsBackAsGoogleTookThem
// on Responses: the reply's output items, appended to the input with each call's output, reach
// Agent Platform as the recorded request that it answered.
func TestGeminiResponsesSendsCallsBackAsGoogleTookThem(t *testing.T) {
	catalogtest.UseFallback(t)
	tools := providerCapture(t, "google-cloud/generate-content-tools")
	weather := `"tools":[{"type":"function","name":"get_weather","description":"Returns a city's weather.","strict":false,"parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}}]`
	ask := `{"role":"user","content":"What is the weather in Paris and in Rome? Look up each city."}`
	request := func(input string) string {
		return `{"model":"google-cloud-gemini-3.8-flash","input":[` + input + `],"max_output_tokens":2000,"reasoning":{"effort":"low","summary":"auto"},"store":false,` + weather + `}`
	}
	state, err := resolveGoogleState(t, geminiResponsesPath, request(ask))
	if err != nil {
		t.Fatal(err)
	}
	reply := ingestBridgedReply(t, state, &schemas.BifrostResponse{ChatResponse: geminiChatReply(t, exchange(t, tools, "tools at mode AUTO"))})
	input := []string{ask}
	for _, item := range reply.Output {
		encoded, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		input = append(input, string(encoded))
	}
	for _, item := range reply.Output {
		if item.Type != nil && *item.Type == schemas.ResponsesMessageTypeFunctionCall {
			result := "Sunny, 21 C"
			if strings.Contains(*item.Arguments, "Rome") {
				result = "Rain, 14 C"
			}
			input = append(input, `{"type":"function_call_output","call_id":`+strconv.Quote(*item.CallID)+`,"output":`+strconv.Quote(result)+`}`)
		}
	}
	took := exchange(t, tools, "the calls back with their signatures")
	if sent := googleBody(t, geminiResponsesPath, request(strings.Join(input, ","))); !sameJSON(t, sent, took.Request.Body) {
		t.Fatalf("sent %s, Agent Platform took %s", sent, took.Request.Body)
	}
}

// TestGeminiBillsWhatGoogleReports settles recorded replies as the gateway does: the prompt without
// what it read from the cache as input, the cache read at its own price, the answer as output and
// the thoughts, which Agent Platform counts apart, as reasoning. The hold covers each cost.
func TestGeminiBillsWhatGoogleReports(t *testing.T) {
	catalogtest.UseFallback(t)
	tools := providerCapture(t, "google-cloud/generate-content-tools")
	caching := providerCapture(t, "google-cloud/generate-content-implicit-caching")
	stream := providerCapture(t, "google-cloud/generate-content-stream")
	cached := exchange(t, caching, "same prompt again")
	streamed := exchange(t, stream, "stream with thought summaries")
	// maxOutputTokens bounds thoughts and answer together, so a hold for the limit covers both.
	cut := exchange(t, providerCapture(t, "google-cloud/generate-content-output-limit"), "gemini-3.8-flash: a limit of 64")
	for _, test := range []struct {
		name   string
		client string
		usage  func(t *testing.T) *schemas.BifrostLLMUsage
		report string
	}{
		{"tool calls with thoughts", geminiAsk + `}`, func(t *testing.T) *schemas.BifrostLLMUsage {
			return geminiChatReply(t, exchange(t, tools, "tools at mode AUTO")).Usage
		}, string(exchange(t, tools, "tools at mode AUTO").Response.Body)},
		{"a prompt read from the cache", `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":` + geminiRecordedText(t, cached) + `}],"max_completion_tokens":2000,"reasoning_effort":"low"}`,
			func(t *testing.T) *schemas.BifrostLLMUsage { return geminiChatReply(t, cached).Usage }, string(cached.Response.Body)},
		{"a reply cut at its limit", `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"How many prime numbers are there below 500? Check each candidate before you answer."}],"max_completion_tokens":64,"reasoning_effort":"high"}`,
			func(t *testing.T) *schemas.BifrostLLMUsage {
				reply := geminiChatReply(t, cut)
				if reply.Choices[0].FinishReason == nil || *reply.Choices[0].FinishReason != "length" {
					t.Fatalf("finish reason %v", reply.Choices[0].FinishReason)
				}
				return reply.Usage
			}, string(cut.Response.Body)},
		{"a stream", `{"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"What is 17*23? Answer with the number only."}],"max_completion_tokens":4000,"reasoning_effort":"medium","stream":true,"stream_options":{"include_usage":true}}`,
			func(t *testing.T) *schemas.BifrostLLMUsage {
				state := geminiprovider.NewGeminiStreamState()
				var usage *schemas.BifrostLLMUsage
				for _, event := range streamed.Response.Events {
					response := &geminiprovider.GenerateContentResponse{}
					if err := sonic.Unmarshal(event, response); err != nil {
						t.Fatal(err)
					}
					chunks, bifrostErr, _ := response.ToBifrostChatCompletionStream(state)
					if bifrostErr != nil {
						t.Fatal(bifrostErr.Error.Message)
					}
					for _, chunk := range chunks {
						if chunk.Usage != nil {
							usage = chunk.Usage
						}
					}
				}
				return usage
			}, string(streamed.Response.Events[len(streamed.Response.Events)-1])},
	} {
		t.Run(test.name, func(t *testing.T) {
			var report struct {
				UsageMetadata struct {
					PromptTokenCount        int `json:"promptTokenCount"`
					CandidatesTokenCount    int `json:"candidatesTokenCount"`
					ThoughtsTokenCount      int `json:"thoughtsTokenCount"`
					CachedContentTokenCount int `json:"cachedContentTokenCount"`
				} `json:"usageMetadata"`
			}
			if err := json.Unmarshal([]byte(test.report), &report); err != nil {
				t.Fatal(err)
			}
			reported := report.UsageMetadata
			state, err := resolveGoogleState(t, geminiChatPath, test.client)
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatal(err)
			}
			usage := test.usage(t)
			if usage == nil {
				t.Fatal("core reported no usage")
			}
			if err := ingestReportedUsage(state, usage); err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatal(err)
			}
			for meter, quantity := range map[string]int{
				billing.MeterInputTokens:       reported.PromptTokenCount - reported.CachedContentTokenCount,
				billing.MeterCachedInputTokens: reported.CachedContentTokenCount,
				billing.MeterOutputTokens:      reported.CandidatesTokenCount,
				billing.MeterReasoningTokens:   reported.ThoughtsTokenCount,
			} {
				billed := meterQuantity(findMeterEstimate(state.FinalMeters, meter))
				if quantity == 0 && (billed == "" || billed == "0") {
					continue
				}
				if billed != strconv.Itoa(quantity) {
					t.Errorf("%s billed %q, Agent Platform reported %d: %#v", meter, billed, quantity, state.FinalMeters)
				}
			}
			if reported.ThoughtsTokenCount == 0 || reported.CandidatesTokenCount == 0 {
				t.Fatalf("the recording reports no thoughts or no answer: %+v", reported)
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD) < 0 {
				t.Fatalf("hold %s does not cover the cost %s", state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD)
			}
		})
	}
}

// TestGeminiEndsAReplyCutAtItsSegmentAtLength gives a client a reply that Gemini ended at its output
// segment, which holds fewer tokens than the request's limit, as a reply cut at its output limit, as
// OpenRouter does: Google ends it with CONTINUATION, which only its v1beta1 API resumes. The
// recorded reply cut at a limit of 64 stands in for one cut at a segment.
func TestGeminiEndsAReplyCutAtItsSegmentAtLength(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := exchange(t, providerCapture(t, "google-cloud/generate-content-output-limit"), "gemini-3.8-flash: a limit of 64")
	// A capture's writer puts a space after each colon.
	cut := strings.Replace(string(recorded.Response.Body), `"finishReason": "MAX_TOKENS"`, `"finishReason": "CONTINUATION"`, 1)
	if cut == string(recorded.Response.Body) {
		t.Fatalf("the recorded reply ends without MAX_TOKENS: %s", recorded.Response.Body)
	}
	recorded.Response.Body = json.RawMessage(cut)
	ask := `"model":"google-cloud-gemini-3.8-flash","messages":[{"role":"user","content":"How many prime numbers are there below 500? Check each candidate before you answer."}],"max_completion_tokens":2000,"reasoning_effort":"high"`
	if reason := geminiClientReply(t, `{`+ask+`}`, recorded).Choices[0].FinishReason; reason == nil || *reason != "length" {
		t.Fatalf("a reply got the reason %v", reason)
	}

	state, err := resolveGoogleState(t, geminiChatPath, `{`+ask+`,"stream":true,"stream_options":{"include_usage":true}}`)
	if err != nil {
		t.Fatal(err)
	}
	response := &geminiprovider.GenerateContentResponse{}
	if err := sonic.Unmarshal(recorded.Response.Body, response); err != nil {
		t.Fatal(err)
	}
	chunks, bifrostErr, _ := response.ToBifrostChatCompletionStream(geminiprovider.NewGeminiStreamState())
	if bifrostErr != nil {
		t.Fatal(bifrostErr.Error.Message)
	}
	var reason *string
	for _, chunk := range chunks {
		if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
			t.Fatal(err)
		}
		for _, choice := range chunk.Choices {
			if choice.FinishReason != nil {
				reason = choice.FinishReason
			}
		}
	}
	if reason == nil || *reason != "length" {
		t.Fatalf("a stream got the reason %v", reason)
	}

	state, err = resolveGoogleState(t, geminiResponsesPath, `{"model":"google-cloud-gemini-3.8-flash","input":"How many prime numbers are there below 500? Check each candidate before you answer.","max_output_tokens":2000,"reasoning":{"effort":"high"},"store":false}`)
	if err != nil {
		t.Fatal(err)
	}
	reply := ingestBridgedReply(t, state, &schemas.BifrostResponse{ChatResponse: geminiChatReply(t, recorded)})
	if reply.Status == nil || *reply.Status != schemas.ResponsesResponseStatusIncomplete ||
		reply.IncompleteDetails == nil || reply.IncompleteDetails.Reason != "max_output_tokens" {
		t.Fatalf("a Responses reply got the status %v and details %+v", reply.Status, reply.IncompleteDetails)
	}
}
