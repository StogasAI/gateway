package catalog

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
)

func TestResolveRequestRedactsBeforeTokenHoldAndProviderConversion(t *testing.T) {
	loadTestCatalog(t)
	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body: []byte(`{
			"model":"gpt-5.5",
			"messages":[{"role":"user","content":"Contact alice@corp.io"}],
			"tools":[{"type":"function","function":{"name":"lookup","description":"Owner tools@corp.io","parameters":{"type":"object"}}}]
		}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary := resolution.StructuredPIIRedactionSummary(); summary.ItemsRedacted != 2 {
		t.Fatalf("redaction summary = %#v, want 2 items", summary)
	}

	rawBody, err := sonic.Marshal(resolution.RawBody())
	if err != nil {
		t.Fatal(err)
	}
	assertRedactedProviderData(t, rawBody)
	expectedHold := inputTokenHoldEstimate(
		rawBody,
		resolution.RawBody(),
		resolution.Provider,
		resolution.Model,
		resolution.Route,
		resolution.Deployment.ContextWindowTokens,
	)
	if resolution.InputTokenLimit() != expectedHold {
		t.Fatalf("input hold = %d, want redacted hold %d", resolution.InputTokenLimit(), expectedHold)
	}

	request, err := resolution.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
	if err != nil {
		t.Fatal(err)
	}
	providerRequest, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	assertRedactedProviderData(t, providerRequest)
}

func TestResolveResponsesPreservesEncryptedReasoning(t *testing.T) {
	loadTestCatalog(t)
	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"gpt-5.5",
			"input":[
				{"type":"message","role":"user","content":[{"type":"input_text","text":"Contact outside@corp.io"}]},
				{"type":"reasoning","summary":[{"type":"summary_text","text":"Keep signed@corp.io"}],"encrypted_content":"ciphertext"}
			]
		}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary := resolution.StructuredPIIRedactionSummary(); summary.ItemsRedacted != 1 {
		t.Fatalf("redaction summary = %#v, want 1 item", summary)
	}
	input := resolution.RawBody()["input"]
	if !bytes.Contains(input, []byte("<EMAIL_ADDRESS>")) || !bytes.Contains(input, []byte("signed@corp.io")) {
		t.Fatalf("encrypted reasoning was changed or ordinary input was not redacted: %s", input)
	}
}

func TestResolveChatPreservesSignedReasoning(t *testing.T) {
	loadTestCatalog(t)
	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"messages":[
				{"role":"user","content":"Question"},
				{"role":"assistant","content":"Answer","reasoning":"Keep signed@corp.io","reasoning_details":[{"index":0,"type":"reasoning.text","text":"Keep signed@corp.io","signature":"opaque-signature"}]},
				{"role":"user","content":"Contact outside@corp.io"}
			]
		}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary := resolution.StructuredPIIRedactionSummary(); summary.ItemsRedacted != 1 {
		t.Fatalf("redaction summary = %#v, want 1 item", summary)
	}
	messages := resolution.RawBody()["messages"]
	if !bytes.Contains(messages, []byte("<EMAIL_ADDRESS>")) || bytes.Count(messages, []byte("signed@corp.io")) != 2 {
		t.Fatalf("signed reasoning was changed or ordinary input was not redacted: %s", messages)
	}

	request, err := resolution.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
	if err != nil {
		t.Fatal(err)
	}
	providerRequest, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(providerRequest, []byte("outside@corp.io")) || !bytes.Contains(providerRequest, []byte("signed@corp.io")) {
		t.Fatalf("signed reasoning or redacted input changed during provider conversion: %s", providerRequest)
	}
}

func TestResolveChatRedactsStopSequencesInRawRequest(t *testing.T) {
	loadTestCatalog(t)
	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"messages":[{"role":"user","content":"Continue"}],
			"stop_sequences":["alice@corp.io"]
		}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.StructuredPIIRedactionSummary().ItemsRedacted != 1 ||
		bytes.Contains(resolution.RawBody()["stop_sequences"], []byte("alice@corp.io")) ||
		!bytes.Contains(resolution.RawBody()["stop_sequences"], []byte("<EMAIL_ADDRESS>")) {
		t.Fatalf("stop sequences were not redacted: summary=%#v value=%s", resolution.StructuredPIIRedactionSummary(), resolution.RawBody()["stop_sequences"])
	}
}

func assertRedactedProviderData(t *testing.T, data []byte) {
	t.Helper()
	if bytes.Contains(data, []byte("alice@corp.io")) || bytes.Contains(data, []byte("tools@corp.io")) {
		t.Fatalf("raw PII reached provider data: %s", data)
	}
	if bytes.Count(data, []byte("EMAIL_ADDRESS")) < 2 {
		t.Fatalf("typed placeholders missing from provider data: %s", data)
	}
}
