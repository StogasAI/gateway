package stogas

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// toolResultRequest is a tool loop whose result holds text, a PDF and an image, as each
// interface spells it. The file and the image are those of the recorded exchange.
func toolResultRequest(t *testing.T, route, model string) (body string, pdf, image string) {
	t.Helper()
	recorded := exchange(t, providerCapture(t, "openai/tool-result-attachments"), "openai Responses")
	var request struct {
		Input []struct {
			Output json.RawMessage `json:"output"`
		} `json:"input"`
	}
	if err := json.Unmarshal(recorded.Request.Body, &request); err != nil {
		t.Fatal(err)
	}
	var parts []struct {
		Type     string `json:"type"`
		FileData string `json:"file_data"`
		ImageURL string `json:"image_url"`
	}
	if err := json.Unmarshal(request.Input[2].Output, &parts); err != nil {
		t.Fatal(err)
	}
	pdf, image = parts[1].FileData, parts[2].ImageURL
	if route == "responses" {
		return `{"model":"` + model + `","input":[{"role":"user","content":"Read the evidence."},` +
			`{"type":"function_call","call_id":"call_1","name":"get_evidence","arguments":"{}"},` +
			`{"type":"function_call_output","call_id":"call_1","output":` + string(request.Input[2].Output) + `}]}`, pdf, image
	}
	return `{"model":"` + model + `","messages":[{"role":"user","content":"Read the evidence."},` +
		`{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_evidence","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"call_1","content":[{"type":"text","text":"The file and the image follow."},` +
		`{"type":"file","file":{"filename":"evidence.pdf","file_data":"` + pdf + `"}},` +
		`{"type":"image_url","image_url":{"url":"` + image + `"}}]}]}`, pdf, image
}

// A tool result's image and file reach each provider in the parts that it took in the recorded
// exchange: Responses parts at OpenAI, and an image and a document inside Claude's tool result.
func TestToolResultAttachmentsReachTheProvider(t *testing.T) {
	recorded := providerCapture(t, "openai/tool-result-attachments")
	t.Run("Responses at OpenAI", func(t *testing.T) {
		body, _, _ := toolResultRequest(t, "responses", "provider:openai gpt-5.5")
		resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		if estimate, ok := resolved.EstimatedInputTokens(); !ok || estimate != resolved.Deployment.MaxInputTokens {
			t.Fatalf("the hold is %d tokens, want the deployment's whole input, %d", estimate, resolved.Deployment.MaxInputTokens)
		}
		if files := resolved.InputFiles(); files.Count != 2 {
			t.Fatalf("the request counts %d files, want 2", files.Count)
		}
		var sent, took struct {
			Input []struct {
				Type   string `json:"type"`
				Output any    `json:"output"`
			} `json:"input"`
		}
		fields, _, _ := providerBody(t, "/v1/responses", body)
		if err := json.Unmarshal(fields["input"], &sent.Input); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(exchange(t, recorded, "openai Responses").Request.Body, &took); err != nil {
			t.Fatal(err)
		}
		last := sent.Input[len(sent.Input)-1]
		want, _ := json.Marshal(took.Input[2].Output)
		// Core names the image's detail, auto, which is the provider's default.
		got, _ := json.Marshal(last.Output)
		if got := strings.Replace(string(got), `"detail":"auto",`, "", 1); last.Type != "function_call_output" || got != string(want) {
			t.Fatalf("the provider gets another tool output than the one it took:\n%.300s", got)
		}
	})
	for _, route := range []string{"chat/completions", "responses"} {
		t.Run("Claude through "+route, func(t *testing.T) {
			body, pdf, image := toolResultRequest(t, strings.TrimPrefix(route, "chat/"), "provider:anthropic anthropic-claude-sonnet-4-6")
			if route == "chat/completions" {
				body, pdf, image = toolResultRequest(t, "chat", "provider:anthropic anthropic-claude-sonnet-4-6")
			}
			body = strings.Replace(body, `{"model"`, `{"max_tokens":50,"model"`, 1)
			if route == "responses" {
				body = strings.Replace(body, `"max_tokens"`, `"max_output_tokens"`, 1)
			}
			type toolResult []struct {
				Type    string `json:"type"`
				Content []struct {
					Type   string `json:"type"`
					Source struct {
						Type      string `json:"type"`
						MediaType string `json:"media_type"`
						Data      string `json:"data"`
					} `json:"source"`
				} `json:"content"`
			}
			var sent, took struct {
				Messages []struct {
					Content json.RawMessage `json:"content"`
				} `json:"messages"`
			}
			last := func(messages []struct {
				Content json.RawMessage `json:"content"`
			}) toolResult {
				var content toolResult
				if err := json.Unmarshal(messages[len(messages)-1].Content, &content); err != nil {
					t.Fatal(err)
				}
				return content
			}
			fields, _, _ := providerBody(t, "/v1/"+route, body)
			if err := json.Unmarshal(fields["messages"], &sent.Messages); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(exchange(t, recorded, "Claude on Amazon Bedrock").Request.Body, &took); err != nil {
				t.Fatal(err)
			}
			result, wanted := last(sent.Messages)[0], last(took.Messages)[0]
			if result.Type != "tool_result" || len(result.Content) != len(wanted.Content) {
				t.Fatalf("Claude gets %+v, want a tool result with %d parts", result, len(wanted.Content))
			}
			for i, part := range result.Content {
				want := wanted.Content[i]
				if part.Type != want.Type || part.Source.Type != want.Source.Type || part.Source.MediaType != want.Source.MediaType || part.Source.Data != want.Source.Data {
					t.Fatalf("part %d is a %s of %s, want the %s of %s that Claude took", i, part.Type, part.Source.MediaType, want.Type, want.Source.MediaType)
				}
			}
			if !strings.HasSuffix(pdf, wanted.Content[1].Source.Data) || !strings.HasSuffix(image, wanted.Content[2].Source.Data) {
				t.Fatal("the recorded exchanges hold different files")
			}
		})
	}
}

// Chat Completions at OpenAI answers 200 for an image in a tool message that the model never
// sees, so a deployment that serves the request through it refuses the attachment.
func TestToolResultAttachmentsNeedADeploymentThatReadsThem(t *testing.T) {
	recorded := exchange(t, providerCapture(t, "openai/tool-result-attachments"), "openai Chat Completions, image")
	var reply struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(recorded.Response.Body, &reply); err != nil || recorded.Response.Status != 200 || strings.Contains(strings.ToLower(reply.Choices[0].Message.Content), "red") {
		t.Fatalf("the recorded reply must be a 200 that does not name the image's color: %v %s", err, recorded.Response.Body)
	}
	body, pdf, _ := toolResultRequest(t, "chat", "provider:openai gpt-5.5")
	imageOnly := strings.Replace(body, `{"type":"file","file":{"filename":"evidence.pdf","file_data":"`+pdf+`"}},`, "", 1)
	_, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(imageOnly)})
	if err == nil || !strings.Contains(err.Error(), "messages[2].content[1] images in tool results are not supported by") {
		t.Fatalf("a Chat Completions deployment took an image in a tool result: %v", err)
	}
	// OpenAI refuses a file there, which the deployment states too.
	_, err = catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)})
	if err == nil || !strings.Contains(err.Error(), "messages[2].content[1] files in tool results are not supported by") {
		t.Fatalf("a Chat Completions deployment took a file in a tool result: %v", err)
	}
	// The request's own checks treat audio in a tool result as any other attachment, and routing
	// refuses it there, since no interface carries audio in a tool result.
	audio := strings.Replace(body, `{"type":"image_url","image_url":{"url":"`, `{"type":"input_audio","input_audio":{"format":"wav","data":"`, 1)
	var messages struct {
		Messages []map[string]json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(audio), &messages); err != nil {
		t.Fatal(err)
	}
	plain, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(`{"model":"provider:openai gpt-5.5","messages":[{"role":"user","content":"Read the evidence."}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	const noAudio = "messages[2].content[2] audio input is not supported by"
	if _, err := validateChatMessageContent(&State{Resolution: plain}, messages.Messages[2]["content"], "messages[2].content", false, true); err == nil || !strings.Contains(err.Error(), noAudio) {
		t.Fatalf("the request's checks gave their own reason for audio in a tool result: %v", err)
	}
	_, err = catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(strings.Replace(audio, "provider:openai gpt-5.5", "provider:anthropic anthropic-claude-sonnet-4-6", 1))})
	if err == nil || !strings.Contains(err.Error(), "messages[2].content[2] audio in tool results is not supported by") {
		t.Fatalf("a deployment took audio in a tool result: %v", err)
	}
}

// A tool result's attachment gets the policy checks of one in a user message: text extraction
// turns a text file into text that redaction reads, and an image under redaction is refused.
func TestToolResultAttachmentsGetThePolicyChecksOfUserMessages(t *testing.T) {
	compose := func(document string) *policy.Config {
		t.Helper()
		source, err := policy.CompileSource([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	request := func(part string) []byte {
		return []byte(`{"model":"provider:openai gpt-5.5","input":[{"role":"user","content":"Read it."},` +
			`{"type":"function_call","call_id":"call_1","name":"get_evidence","arguments":"{}"},` +
			`{"type":"function_call_output","call_id":"call_1","output":[` + part + `]}]}`)
	}
	note := `{"type":"input_file","filename":"note.txt","file_data":"data:text/plain;base64,aGVsbG8="}`
	redaction := compose(`{"plugins":{"textExtraction":{"text":"always"},"redaction":{"customPattern":"hello"}}}`)

	resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Policy: redaction, Body: request(note)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(resolved.RawBody())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "base64") || strings.Contains(string(raw), "hello") || !strings.Contains(string(raw), "note.txt") {
		t.Fatalf("the file in the tool output was not extracted and redacted: %s", raw)
	}

	_, _, image := toolResultRequest(t, "responses", "provider:openai gpt-5.5")
	if _, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Policy: redaction, Body: request(`{"type":"input_image","image_url":"` + image + `"}`)}); err == nil || !strings.Contains(err.Error(), "input[2].output[0]") {
		t.Fatalf("an image in a tool output passed redaction: %v", err)
	}
	// Redaction reads the text parts of a tool output and leaves the image's bytes alone.
	resolved, err = catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST", Path: "/v1/responses", Policy: compose(`{"plugins":{"redaction":{"customPattern":"hello"}},"input":{"mediaTypes":{"allow":["text/plain"]}}}`),
		Body: request(`{"type":"input_text","text":"hello there"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(resolved.RawBody()); strings.Contains(string(raw), "hello") {
		t.Fatalf("text in a tool output passed redaction: %s", raw)
	}
	if _, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST", Path: "/v1/responses", Policy: compose(`{"input":{"mediaTypes":{"allow":["text/plain"]}}}`),
		Body: request(`{"type":"input_image","image_url":"` + image + `"}`),
	}); err == nil || !strings.Contains(err.Error(), "input[2].output[0]") {
		t.Fatalf("input.mediaTypes did not refuse an image in a tool output: %v", err)
	}
}
