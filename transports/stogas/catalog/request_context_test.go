package catalog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestProviderOwnsContextAcceptanceAfterRedaction(t *testing.T) {
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, transform := range []bool{false, true} {
			name := "overestimated input"
			if transform {
				name = "redaction expands past context"
			}
			t.Run(path+"/"+name, func(t *testing.T) {
				snap := loadTestCatalog(t)
				text := strings.Repeat("~ ", 1024) + "Keep this ending."
				body := map[string]any{"model": "openai-gpt-5.6-sol"}
				route, field := RouteChat, "messages"
				body[field] = []map[string]string{{"role": "user", "content": text}}
				body["max_completion_tokens"] = 16
				if path == "/v1/responses" {
					route, field = RouteResponses, "input"
					delete(body, "messages")
					delete(body, "max_completion_tokens")
					body[field], body["max_output_tokens"] = text, 16
				}
				encoded, _ := json.Marshal(body)
				raw, _ := DecodeRequestBody(encoded, nil)
				before := inputTokenHoldEstimate(t, raw, "openai", route, 0)
				contextWindow := before / 3
				var matcher *redaction.Policy
				if transform {
					var err error
					matcher, err = redaction.CompilePolicy(redaction.Options{CustomPatterns: []redaction.CustomPattern{{Expression: "~"}}})
					if err != nil {
						t.Fatal(err)
					}
					contextWindow = before + 1
				}
				deployment := snap.graph.Deployments["openai-gpt-5.6-sol"]
				deployment.ContextWindowTokens, deployment.MaxInputTokens, deployment.MaxOutputTokens = contextWindow, contextWindow, 128
				snap.graph.Deployments["openai-gpt-5.6-sol"] = deployment
				reservedBody, checked := 0, 0
				resolved, err := ResolveRequest(RequestInput{
					Body: encoded, Method: "POST", Path: path, RedactionPolicy: matcher,
					CheckCandidate: func(schemas.ModelProvider, int, Deployment) error { checked++; return nil },
					ReserveBody:    func(bytes int) error { reservedBody = bytes; return nil },
				})
				if err != nil || resolved == nil || checked != 1 {
					t.Fatalf("context estimate must not reject or reroute: %v, checks=%d", err, checked)
				}
				after := inputTokenHoldEstimate(t, resolved.RawBody(), "openai", route, 0)
				if after <= 2*contextWindow {
					t.Fatalf("fixture did not exceed twice the context: estimate=%d context=%d", after, contextWindow)
				}
				if estimate, known := resolved.EstimatedInputTokens(); !known || estimate != contextWindow || resolved.InputTokenLimit() != contextWindow {
					t.Fatalf("reservation must remain capped independently: estimate=%d known=%t hold=%d", estimate, known, resolved.InputTokenLimit())
				}
				var want json.RawMessage
				expected := text
				if transform {
					expected = strings.ReplaceAll(text, "~", "<CUSTOM_PII>")
					if resolved.StructuredPIIRedactionSummary().ItemsRedacted != 1024 || reservedBody <= len(encoded) {
						t.Fatal("expanded redaction was not included in memory admission")
					}
				}
				if route == RouteResponses {
					want, _ = json.Marshal(expected)
				} else {
					want, _ = json.Marshal([]map[string]string{{"role": "user", "content": expected}})
				}
				var actualValue, expectedValue any
				_ = json.Unmarshal(resolved.RawBody()[field], &actualValue)
				_ = json.Unmarshal(want, &expectedValue)
				actualJSON, _ := json.Marshal(actualValue)
				expectedJSON, _ := json.Marshal(expectedValue)
				if string(actualJSON) != string(expectedJSON) {
					t.Fatal("context handling truncated input or changed redaction")
				}
			})
		}
	}
}

func TestExpandedBodyMemoryDenialDoesNotRestartSelection(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			config := policyConfig(2)
			config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6"}}
			config.Routing.Query = mustRouting(t, "", []policy.Sort{{By: "provider.id", Direction: "desc"}})
			body := map[string]any{}
			text := strings.Repeat("~ ", 1024)
			if path == "/v1/responses" {
				body["input"], body["max_output_tokens"] = text, 16
			} else {
				body["messages"] = []map[string]string{{"role": "user", "content": text}}
				body["max_completion_tokens"] = 16
			}
			encoded, _ := json.Marshal(body)
			matcher, err := redaction.CompilePolicy(redaction.Options{CustomPatterns: []redaction.CustomPattern{{Expression: "~"}}})
			if err != nil {
				t.Fatal(err)
			}
			capacity := errors.New("request memory capacity")
			checks, reservations := 0, 0
			resolved, err := ResolveRequest(RequestInput{
				Body: encoded, Method: "POST", Path: path, Policy: config, RedactionPolicy: matcher,
				CheckCandidate: func(schemas.ModelProvider, int, Deployment) error { checks++; return nil },
				ReserveBody: func(bytes int) error {
					reservations++
					if bytes <= len(encoded) {
						t.Fatal("admission used the original body size")
					}
					return capacity
				},
			})
			if !errors.Is(err, capacity) || resolved != nil || checks != 1 || reservations != 1 {
				t.Fatalf("memory rejection must be final: %v, checks=%d reservations=%d", err, checks, reservations)
			}
		})
	}
}

func TestReleaseInputPreservesIndependentResponseParameters(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,aGVsbG8="}]}],"instructions":"Keep answers short","parallel_tool_calls":false,"tools":[{"type":"function","name":"check","parameters":{"type":"object","properties":{}}}]}`)
	resolved, err := ResolveRequest(RequestInput{Method: "POST", Path: "/v1/responses", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	estimate, _ := resolved.EstimatedInputTokens()
	resolved.ReleaseInput()
	clear(body)
	if resolved.chat != nil || resolved.responses != nil || len(resolved.RawBody()["input"]) != 0 {
		t.Fatal("input retained after preparation")
	}
	if string(resolved.RawBody()["instructions"]) != `"Keep answers short"` || string(resolved.RawBody()["parallel_tool_calls"]) != "false" || string(resolved.RawTools()[0]["name"]) != `"check"` {
		t.Fatal("response parameters borrowed discarded input")
	}
	if after, _ := resolved.EstimatedInputTokens(); after != estimate || resolved.InputFiles().InlineBytes != 5 {
		t.Fatal("release lost accounting")
	}
	if _, err := resolved.ToBifrost(nil); err == nil {
		t.Fatal("released request could be dispatched again")
	}
}
