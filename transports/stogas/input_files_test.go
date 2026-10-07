package stogas

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestAttachmentsHoldFullInputAndPreserveProviderPayload(t *testing.T) {
	for _, route := range []string{"chat/completions", "responses"} {
		for _, source := range []string{"https://example.invalid/image.png", "data:image/png;base64,aGVsbG8="} {
			t.Run(route+"/"+source, func(t *testing.T) {
				block := `{"type":"image_url","image_url":{"url":"` + source + `"}}`
				field := "messages"
				if route == "responses" {
					block = `{"type":"input_image","image_url":"` + source + `"}`
					field = "input"
				}
				resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + route, Body: []byte(`{"model":"gpt-5.5","` + field + `":[{"role":"user","content":[` + block + `]}]}`)})
				if err != nil {
					t.Fatal(err)
				}
				if estimate, ok := resolved.EstimatedInputTokens(); !ok || estimate != resolved.Deployment.MaxInputTokens {
					t.Fatalf("opaque input hold = %d, want %d", estimate, resolved.Deployment.MaxInputTokens)
				}
				if text, _ := resolved.InputTextBytes(); text != 0 {
					t.Fatalf("binary payload counted as %d text bytes", text)
				}
				files := resolved.InputFiles()
				if files.Count != 1 || source[0] == 'h' && files.URLs != 1 || source[0] == 'd' && files.InlineBytes != 5 {
					t.Fatalf("wrong attachment quantities: %+v", files)
				}
				state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
				if err := state.Adapter.ValidateRequest(state); err != nil {
					t.Fatal(err)
				}
				ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
				request, err := resolved.ToBifrost(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := PrepareProviderRequest(ctx, state, request); err != nil {
					t.Fatal(err)
				}
				resolved.ReleaseInput()
				var body []byte
				if request.ChatRequest != nil {
					body = preparedProviderBody(t, ctx, request.ChatRequest)
				} else {
					body = preparedProviderBody(t, ctx, request.ResponsesRequest)
				}
				if !bytes.Contains(body, []byte(source)) {
					t.Fatal("provider payload lost or altered attachment")
				}
			})
		}
	}
}

func TestTextExtractionPrecedesASCIIAndRedaction(t *testing.T) {
	for _, route := range []string{"chat/completions", "responses"} {
		for _, tc := range []struct {
			name, plugins, data      string
			ascii, reject, encrypted bool
		}{
			{"opt in", `"stogasTextExtraction":true`, "aGVsbG8=", false, false, false},
			{"redaction after extraction", `"stogasTextExtraction":true,"stogasRedaction":{"customPattern":"hello"}`, "aGVsbG8=", false, false, false},
			{"encrypted extraction and redaction", `"stogasTextExtraction":true,"stogasRedaction":{"customPattern":"hello"}`, "aGVsbG8=", false, false, true},
			{"ASCII after extraction", `"stogasTextExtraction":true`, "w6k=", true, true, false},
			{"opaque cannot bypass ASCII", `"stogasTextExtraction":false`, "aGVsbG8=", true, true, false},
			{"opaque cannot bypass redaction", `"stogasRedaction":{"customPattern":"hello"}`, "aGVsbG8=", false, true, false},
		} {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				ascii := "false"
				if tc.ascii {
					ascii = "true"
				}
				var source *policy.Source
				var err error
				if tc.encrypted {
					key, parseErr := customerkey.Parse("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					defer key.Clear()
					// Independently generated with Node crypto for this organization and purpose.
					const envelope = `{"version":1,"keyId":"3a1121028ba40964d5f10b47662650a021d736bd671f4083b5066d9bd51c9ef0","salt":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","nonce":"BAQEBAQEBAQEBAQE","blob":"eIEP5gXKXonHW8cXk5BBcZHLWfwQy1fHRp2dsuH0ND3IommpMwlslorozMhdMiqaBvG9XeX-yGH40t7L9VaywZtcyT2EaqkBwJLQ_jqqh3jDlt-Kgzzrxqs"}`
					document := []byte(`{"encryption":{"keys":{"default":"` + key.ID() + `"}},"plugins":{"encrypted":` + envelope + `}}`)
					if _, missingErr := policy.OpenSource(document, "org-test", nil); missingErr == nil {
						t.Fatal("encrypted extraction accepted without key")
					}
					source, err = policy.OpenSource(document, "org-test", customerkey.Keys{"default": key})
				} else {
					source, err = policy.CompileSource([]byte(`{"plugins":{` + tc.plugins + `},"input":{"asciiOnly":` + ascii + `}}`))
				}
				if err != nil {
					t.Fatal(err)
				}
				config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
				if err != nil {
					t.Fatal(err)
				}
				file := `"file_data":"data:text/plain;base64,` + tc.data + `","filename":"note.txt"`
				block, field := `{"type":"file","file":{`+file+`}}`, "messages"
				if route == "responses" {
					block, field = `{"type":"input_file",`+file+`}`, "input"
				}
				resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + route, Policy: config, Body: []byte(`{"model":"gpt-5.5","` + field + `":[{"role":"user","content":[` + block + `]}]}`)})
				if tc.reject {
					if err == nil {
						t.Fatal("inspection policy bypassed")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if estimate, _ := resolved.EstimatedInputTokens(); estimate >= resolved.Deployment.MaxInputTokens {
					t.Fatal("extracted text retained full-input hold")
				}
				if resolved.InputFiles().InlineBytes != 5 || resolved.InputFiles().Opaque {
					t.Fatal("extracted file statistics incorrect")
				}
				state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
				if err := state.Adapter.ValidateRequest(state); err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(resolved.RawBody())
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(raw, []byte("base64")) || !bytes.Contains(raw, []byte("note.txt")) {
					t.Fatal("file was not replaced with text and its filename")
				}
				if strings.Contains(tc.plugins, "customPattern") && bytes.Contains(raw, []byte("hello")) {
					t.Fatal("extracted text bypassed redaction")
				}
			})
		}
	}
}

func TestProviderFileIDReservesFullInputAndRejectsWithoutBYOK(t *testing.T) {
	resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(`{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_file","file_id":"file-owned-by-someone-else"}]}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if estimate, _ := resolved.EstimatedInputTokens(); estimate != resolved.Deployment.MaxInputTokens {
		t.Fatalf("file ID hold = %d, want %d", estimate, resolved.Deployment.MaxInputTokens)
	}
	state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
	if err := state.Adapter.ValidateRequest(state); err == nil || !strings.Contains(err.Error(), "BYOK") {
		t.Fatalf("file ID accepted without customer credential: %v", err)
	}
}

func TestProviderFileIDWithPreparedBYOKHoldsFullInput(t *testing.T) {
	key, err := customerkey.Parse("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatal(err)
	}
	defer key.Clear()
	const id = "0198f4cc-6c25-7000-8000-000000000001"
	// Node crypto fixture: HKDF-SHA256 + AES-256-GCM, bound to org-test/byok/openai.
	const envelope = `{"version":1,"keyId":"3a1121028ba40964d5f10b47662650a021d736bd671f4083b5066d9bd51c9ef0","salt":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","nonce":"CQkJCQkJCQkJCQkJ","blob":"tWrhodGoOpIuR8FHpvQEq_u8kTS4r0HPEkvwKUzCaZz2SGH2mXN4"}`
	snapshot := &billing.KeyConfigSnapshot{
		Claims:         &billing.APIKeyClaims{OrganizationID: "org-test"},
		PolicySnapshot: billing.PolicySnapshot{Config: &policy.Config{EncryptionKeys: map[string]string{"default": key.ID()}}},
		Credentials:    map[string][]billing.CredentialSelection{"openai": {{Mode: "encrypted", ID: id, Credential: &billing.CachedCredential{ID: id, OrganizationID: "org-test", Provider: "openai", Kind: "encrypted", Enabled: true, EncryptionKeyID: key.ID(), EncryptedSecret: envelope}}}},
	}
	service := &billing.Service{}
	prepared, err := service.PrepareCredential(snapshot, "openai", 0, customerkey.Keys{"default": key})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Clear()
	for _, kind := range []string{"input_file", "input_image"} {
		t.Run(kind, func(t *testing.T) {
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(`{"model":"gpt-5.5","max_output_tokens":100,"input":[{"role":"user","content":[{"type":"` + kind + `","file_id":"file-customer-owned"}]}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			// One dollar per token makes the expected hold independent of catalog prices.
			resolved.Deployment.Pricing = billing.Pricing{billing.MeterInputTokens: {billing.RatePerMillionTokens: "1000000"}, billing.MeterOutputTokens: {billing.RatePerMillionTokens: "1000000"}}
			state := NewState(resolved, "sk-test", snapshot.Claims, AdapterFor(resolved.Provider))
			state.PreparedCredential = prepared
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatal(err)
			}
			full := resolved.Deployment.MaxInputTokens
			if findMeter(state.Hold.Meters, billing.MeterInputTokens, strconv.Itoa(full)) == nil || state.Hold.EstimatedUpstreamCostUSD != strconv.Itoa(full+100) {
				t.Fatalf("full input plus output hold missing: %+v", state.Hold)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
			request, err := resolved.ToBifrost(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatal(err)
			}
			resolved.ReleaseInput()
			if !bytes.Contains(preparedProviderBody(t, ctx, request.ResponsesRequest), []byte(`"file_id":"file-customer-owned"`)) {
				t.Fatal("provider lost file ID")
			}
		})
	}
}

func TestAnthropicAttachmentLoopHoldAndProviderToolCaps(t *testing.T) {
	for _, model := range []string{"anthropic/anthropic-claude-opus-4-8-fast-us", "azure/azure-claude-opus-4-8"} {
		for _, tool := range []string{"web_search_20250305", "web_fetch_20260309"} {
			for _, tc := range []struct {
				name, cap, cache string
				perTool, want    int
			}{
				{"conflicting caps", `,"max_tool_calls":2`, "", 9, -1},
				{"matching caps", `,"max_tool_calls":2`, "", 2, 2},
				{"omission preserves tool", "", "", 12, 12},
				{"cache with narrow cap", `,"max_tool_calls":2`, `,"cache_control":{"type":"ephemeral"}`, 2, 2},
			} {
				t.Run(model+"/"+tool+"/"+tc.name, func(t *testing.T) {
					raw := `{"model":"` + model + `","max_output_tokens":100,"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.invalid/image.png"}]}],"tools":[{"type":"` + tool + `","max_uses":` + strconv.Itoa(tc.perTool) + `} ]` + tc.cap + tc.cache + `}`
					resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(raw)})
					if err != nil {
						t.Fatal(err)
					}
					resolved.Deployment.Pricing = billing.Pricing{
						billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1"},
						billing.MeterOutputTokens:            {billing.RatePerMillionTokens: "2"},
						billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1.25"},
						billing.MeterCachedInputTokens:       {billing.RatePerMillionTokens: "0.1"},
						meterAnthropicWebSearchCalls:         {billing.RatePerThousandCalls: "10"},
					}
					state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
					validationErr := state.Adapter.ValidateRequest(state)
					if tc.want < 0 {
						if validationErr == nil || !strings.Contains(validationErr.Error(), "conflicts") {
							t.Fatalf("conflicting tool caps accepted: %v", validationErr)
						}
						return
					}
					if validationErr != nil {
						t.Fatal(validationErr)
					}
					if err := state.Adapter.SanitizeRequest(state); err != nil {
						t.Fatal(err)
					}
					if err := state.Adapter.EstimateHold(state); err != nil {
						t.Fatal(err)
					}
					full := resolved.Deployment.MaxInputTokens
					if tc.cache != "" {
						if findMeter(state.Hold.Meters, billing.MeterCacheWrite5mInputTokens, strconv.Itoa(full)) == nil || findMeter(state.Hold.Meters, billing.MeterCachedInputTokens, strconv.Itoa(full*9)) == nil {
							t.Fatalf("enabled cache loop hold: %+v", state.Hold)
						}
					} else if findMeter(state.Hold.Meters, billing.MeterInputTokens, strconv.Itoa(full*10)) == nil {
						t.Fatalf("uncached loop hold: %+v", state.Hold)
					}
					if strings.HasPrefix(tool, "web_search") && findMeter(state.Hold.Meters, meterAnthropicWebSearchCalls, strconv.Itoa(tc.want)) == nil {
						t.Fatalf("wrong call allowance: %+v", state.Hold)
					}
					ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
					ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
					request, err := resolved.ToBifrost(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := PrepareProviderRequest(ctx, state, request); err != nil {
						t.Fatal(err)
					}
					resolved.ReleaseInput()
					body := preparedProviderBody(t, ctx, request.ResponsesRequest)
					var upstream struct {
						Tools []struct {
							Type    string `json:"type"`
							MaxUses int    `json:"max_uses"`
						} `json:"tools"`
					}
					if err := json.Unmarshal(body, &upstream); err != nil {
						t.Fatal(err)
					}
					matched := false
					for _, native := range upstream.Tools {
						if strings.HasPrefix(native.Type, strings.Split(tool, "_20")[0]) {
							matched = true
							if native.MaxUses != tc.want {
								t.Fatalf("upstream max_uses=%d, want %d", native.MaxUses, tc.want)
							}
						}
					}
					if !matched {
						t.Fatal("upstream lost hosted tool")
					}
				})
			}
		}
	}
}

func TestNativeDocumentsPreserveProviderContent(t *testing.T) {
	for _, model := range []string{"gpt-5.5", "anthropic/anthropic-claude-opus-4-8-fast-us"} {
		for _, route := range []string{"chat/completions", "responses"} {
			for _, file := range []struct{ name, fields, expected string }{
				{"PDF", `"file_data":"data:application/pdf;base64,JVBERi0xLjcK","filename":"note.pdf"`, "JVBERi0xLjcK"},
				{"URL", `"file_url":"https://example.invalid/document.pdf"`, "https://example.invalid/document.pdf"},
			} {
				t.Run(model+"/"+route+"/"+file.name, func(t *testing.T) {
					block, field := `{"type":"file","file":{`+file.fields+`}}`, "messages"
					if route == "responses" {
						block, field = `{"type":"input_file",`+file.fields+`}`, "input"
					}
					resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + route, Body: []byte(`{"model":"` + model + `","` + field + `":[{"role":"user","content":[` + block + `]}]}`)})
					if err != nil {
						t.Fatal(err)
					}
					state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
					err = state.Adapter.ValidateRequest(state)
					if model == "gpt-5.5" && route == "chat/completions" && file.name == "URL" {
						if err == nil {
							t.Fatal("OpenAI Chat admitted a URL requiring gateway fetch")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
					ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
					request, err := resolved.ToBifrost(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := PrepareProviderRequest(ctx, state, request); err != nil {
						t.Fatal(err)
					}
					resolved.ReleaseInput()
					var body []byte
					if request.ChatRequest != nil {
						body = preparedProviderBody(t, ctx, request.ChatRequest)
					} else {
						body = preparedProviderBody(t, ctx, request.ResponsesRequest)
					}
					if !bytes.Contains(body, []byte(file.expected)) {
						t.Fatal("provider document lost content")
					}
					if file.name == "PDF" && !bytes.Contains(body, []byte("application/pdf")) {
						t.Fatal("provider document lost MIME type")
					}
				})
			}
		}
	}
}

func TestNativeFileFormatsFollowSelectedRouteAfterTextExtraction(t *testing.T) {
	for _, tc := range []struct {
		name, model, route, mime, filename string
		extract, raw, reject               bool
	}{
		{"OpenAI Chat PDF", "openai-gpt-5.6-luna", "chat/completions", "application/pdf", "note.pdf", false, false, false},
		{"OpenAI Chat CSV", "openai-gpt-5.6-luna", "chat/completions", "text/csv", "note.csv", false, false, true},
		{"OpenAI Chat extracted CSV", "openai-gpt-5.6-luna", "chat/completions", "text/csv", "note.csv", true, false, false},
		{"OpenAI Responses CSV", "openai-gpt-5.6-luna", "responses", "text/csv", "note.csv", false, false, false},
		{"OpenAI Responses DOCX", "openai-gpt-5.6-luna", "responses", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "note.docx", false, false, false},
		{"OpenAI Responses unknown binary", "openai-gpt-5.6-luna", "responses", "application/x-unknown", "note.pdf", false, false, true},
		{"OpenAI raw PDF filename", "openai-gpt-5.6-luna", "chat/completions", "", "note.PDF", false, true, false},
		{"OpenAI unknown filename", "openai-gpt-5.6-luna", "responses", "", "note.unknown", false, true, true},
		{"OpenAI octet-stream PDF filename", "openai-gpt-5.6-luna", "responses", "application/octet-stream", "note.pdf", false, false, false},
		{"Anthropic plain text", "anthropic-claude-opus-4-8", "responses", "text/plain", "note.txt", false, false, false},
		{"Anthropic untyped raw text", "anthropic-claude-opus-4-8", "responses", "", "note.txt", false, true, true},
		{"Anthropic CSV MIME", "anthropic-claude-opus-4-8", "responses", "text/csv", "note.csv", false, false, true},
		{"Anthropic extracted CSV", "anthropic-claude-opus-4-8", "responses", "text/csv", "note.csv", true, false, false},
		{"Azure Responses PDF", "azure-gpt-5.6-luna", "responses", "application/pdf", "note.pdf", false, false, false},
		{"Azure Chat PDF", "azure-gpt-5.6-luna", "chat/completions", "application/pdf", "note.pdf", false, false, true},
		{"Azure extracted text", "azure-gpt-5.6-luna", "chat/completions", "text/plain", "note.txt", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var config *policy.Config
			if tc.extract {
				source, err := policy.CompileSource([]byte(`{"plugins":{"stogasTextExtraction":true}}`))
				if err != nil {
					t.Fatal(err)
				}
				config, err = policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
				if err != nil {
					t.Fatal(err)
				}
			}
			// File bytes deliberately remain opaque: the gateway validates metadata;
			// parsing PDF/Office documents and their size limits belongs upstream.
			data := "aGVsbG8="
			if !tc.raw {
				data = "data:" + tc.mime + ";base64," + data
			}
			file := `"file_data":"` + data + `","filename":"` + tc.filename + `"`
			block, field := `{"type":"file","file":{`+file+`}}`, "messages"
			if tc.route == "responses" {
				block, field = `{"type":"input_file",`+file+`}`, "input"
			}
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + tc.route, Policy: config, Body: []byte(`{"model":"` + tc.model + `","` + field + `":[{"role":"user","content":[` + block + `]}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
			err = state.Adapter.ValidateRequest(state)
			if tc.reject {
				if err == nil || !strings.Contains(err.Error(), "file") {
					t.Fatalf("native format accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.extract {
				if resolved.InputFiles().Opaque {
					t.Fatal("extracted file remained opaque")
				}
			} else if estimate, _ := resolved.EstimatedInputTokens(); estimate != resolved.Deployment.MaxInputTokens {
				t.Fatal("native document lost full input hold")
			}
		})
	}
}
