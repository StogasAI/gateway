package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestRedactionWorkExhaustionRejectsBothRequestSurfaces(t *testing.T) {
	loadTestCatalog(t)
	redactionPolicy, err := redaction.CompilePolicy(redaction.Options{
		CustomPatterns: []redaction.CustomPattern{{Expression: `a.*z|a`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		raw := map[string]any{"model": "gpt-5.5"}
		input := strings.Repeat("a", 32768)
		if path == "/v1/responses" {
			raw["input"] = input
		} else {
			raw["messages"] = []map[string]string{{"role": "user", "content": input}}
		}
		body, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		resolutions, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: body, RedactionPolicy: redactionPolicy})
		var apiError APIError
		if !errors.As(err, &apiError) || apiError.StatusCode != 413 || resolutions != nil {
			t.Fatalf("%s: resolution=%v error=%v", path, resolutions, err)
		}
	}
}

func TestRoutingRejectionsPrecedeRedactionWorkForBothSurfaces(t *testing.T) {
	loadTestCatalog(t)
	redactionPolicy, err := redaction.CompilePolicy(redaction.Options{
		CustomPatterns: []redaction.CustomPattern{{Expression: "EMP-[0-9]+"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	denied := policyConfig(1)
	denied.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Models: []string{}}
	filtered := policyConfig(1)
	filtered.Routing.Query = mustRouting(t, `provider.id == 'not-a-provider'`, nil)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		outputField := "max_completion_tokens"
		if path == "/v1/responses" {
			outputField = "max_output_tokens"
		}
		for _, test := range []struct {
			name, model string
			extra       map[string]any
			config      *policy.Config
			want        APIError
		}{
			{name: "unknown model", model: "not-a-model", want: ErrModelUnavailable},
			{name: "unknown provider", model: "gpt-5.5", extra: map[string]any{"provider": "not-a-provider"}, want: ErrProviderUnavailable},
			{name: "unsupported tier", model: "gpt-5.5", extra: map[string]any{"service_tier": "not-a-tier"}, want: ErrUnsupportedServiceTier},
			{name: "scope exclusion", model: "gpt-5.5", config: denied, want: ErrModelUnavailable},
			{name: "query exclusion", model: "gpt-5.5", config: filtered, want: ErrModelUnavailable},
			{name: "invalid output type", model: "gpt-5.5", extra: map[string]any{outputField: "100"}, want: ErrInvalidJSON},
			{name: "negative output", model: "gpt-5.5", extra: map[string]any{outputField: -1}, want: ErrParameterTooLarge},
			{name: "excessive output", model: "gpt-5.5", extra: map[string]any{outputField: 100000000}, want: ErrParameterTooLarge},
			{name: "valid route still redacts", model: "gpt-5.5", want: APIError{StatusCode: 413}},
		} {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				raw := map[string]any{"model": test.model}
				text := strings.Repeat("EMP-1 ", 65_537)
				if path == "/v1/responses" {
					raw["input"] = text
				} else {
					raw["messages"] = []map[string]string{{"role": "user", "content": text}}
				}
				for key, value := range test.extra {
					raw[key] = value
				}
				body, err := json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				_, err = ResolveRequest(RequestInput{Method: "POST", Path: path, Body: body, Policy: test.config, RedactionPolicy: redactionPolicy})
				var apiErr APIError
				if !errors.As(err, &apiErr) || apiErr.StatusCode != test.want.StatusCode || apiErr.Code != test.want.Code {
					t.Fatalf("got %v, want status=%d code=%s", err, test.want.StatusCode, test.want.Code)
				}
			})
		}
	}
}

func TestColdRedactionBuildFollowsCheapChecksAndFailsClosed(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, model := range []string{"not-a-model", "openai-gpt-5.6-sol"} {
			called := 0
			body := []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hello"}],"input":"hello"}`)
			_, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: body, Policy: policyConfig(2), LoadRedactionPolicy: func() (*redaction.Policy, error) {
				called++
				return nil, errors.New("cold compiler unavailable")
			}})
			if model == "not-a-model" {
				if called != 0 || !errors.Is(err, ErrModelUnavailable) {
					t.Fatalf("compiled denied route: %d %v", called, err)
				}
			} else if called != 1 || PublicError(err).StatusCode != 503 {
				t.Fatalf("compiler failure must not dispatch or use default redaction: %d %v", called, err)
			}
		}
	}
}

func TestOmittedRedactionPreservesTextThroughProviderConversion(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			body := map[string]any{"model": "gpt-5.5"}
			const input = "Contact alice@corp.io at 212-555-1234"
			if path == "/v1/responses" {
				body["input"] = input
			} else {
				body["messages"] = []map[string]string{{"role": "user", "content": input}}
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: raw})
			if err != nil {
				t.Fatal(err)
			}
			if resolution.StructuredPIIRedactionSummary() != nil {
				t.Fatal("omitted redaction emitted metrics")
			}
			request, err := resolution.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
			if err != nil {
				t.Fatal(err)
			}
			provider, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(provider, []byte(input)) {
				t.Fatalf("provider input was changed: %s", provider)
			}
		})
	}
}

func TestResolveRequestRedactsBeforeTokenHoldAndProviderConversion(t *testing.T) {
	loadTestCatalog(t)
	resolution, err := ResolveRequest(RequestInput{
		RedactionPolicy: testEmailRedactionPolicy(t),
		Method:          "POST",
		Path:            "/v1/chat/completions",
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
		t,
		resolution.RawBody(),
		resolution.Deployment.snapshot.graph.Models[resolution.Deployment.ModelID].AuthorID,
		resolution.Route,
		resolution.Deployment.MaxInputTokens,
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
		RedactionPolicy: testEmailRedactionPolicy(t),
		Method:          "POST",
		Path:            "/v1/responses",
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
	if estimate, known := resolution.EstimatedInputTokens(); !known || estimate != resolution.InputTokenLimit() || estimate >= resolution.Deployment.ContextWindowTokens/2 {
		t.Fatal("opaque reasoning did not use the shared bounded input estimate")
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
		RedactionPolicy: testEmailRedactionPolicy(t),
		Method:          "POST",
		Path:            "/v1/chat/completions",
		Body: []byte(`{
			"model":"anthropic-claude-sonnet-4-6",
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
		RedactionPolicy: testEmailRedactionPolicy(t),
		Method:          "POST",
		Path:            "/v1/chat/completions",
		Body: []byte(`{
			"model":"anthropic-claude-sonnet-4-6",
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

func testEmailRedactionPolicy(t *testing.T) *redaction.Policy {
	t.Helper()
	policy, err := redaction.CompilePolicy(redaction.Options{Patterns: []redaction.Pattern{redaction.PatternEmailAddress}})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
