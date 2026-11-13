package stogas

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
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
			t.Fatalf("%s: decode %s: %v", e.Name, data, err)
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
// credential, and encrypted reasoning that the provider cannot read is the request's own error.
func TestRecordedProviderRefusalsKeepTheirMeaning(t *testing.T) {
	spendCap := exchange(t, providerCapture(t, "anthropic/monthly-spend-cap"), "message")
	if got := billing.NormalizeUpstreamStatus(anthropic.ParseAnthropicError(spendCap.errorReply(t))); got != "over_budget" {
		t.Fatalf("Anthropic's spent monthly cap = %s, want over_budget", got)
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

// TestRecordedReasoningStreamKeepsEachEventsEncryptedReasoning replays a recorded OpenAI stream.
// OpenAI encrypts an item's reasoning again for response.completed, so the two values differ, and
// the gateway returns each bound to the account.
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
	var done, completed string
	for _, event := range stream.responsesStream(t) {
		if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}); err != nil {
			t.Fatalf("recorded %s event refused: %v", event.Type, err)
		}
		if event.Type == schemas.ResponsesStreamResponseTypeOutputItemDone && event.Item != nil && event.Item.ResponsesReasoning != nil && event.Item.ResponsesReasoning.EncryptedContent != nil {
			done = *event.Item.ResponsesReasoning.EncryptedContent
		}
		if event.Type == schemas.ResponsesStreamResponseTypeCompleted {
			for _, item := range event.Response.Output {
				if item.ResponsesReasoning != nil && item.ResponsesReasoning.EncryptedContent != nil {
					completed = *item.ResponsesReasoning.EncryptedContent
				}
			}
		}
	}
	prefix := boundReasoning("")
	if !strings.HasPrefix(done, prefix) || !strings.HasPrefix(completed, prefix) || done == completed || len(done) != len(completed) {
		t.Fatalf("item done %.30s… (%d bytes), completed %.30s… (%d bytes)", done, len(done), completed, len(completed))
	}
}
