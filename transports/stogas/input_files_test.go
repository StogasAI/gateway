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
				resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + route, Body: []byte(`{"model":"provider:openai gpt-5.5","` + field + `":[{"role":"user","content":[` + block + `]}]}`)})
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
			{"opt in", `"textExtraction":"always"`, "aGVsbG8=", false, false, false},
			{"redaction after extraction", `"textExtraction":"always","redaction":{"customPattern":"hello"}`, "aGVsbG8=", false, false, false},
			{"encrypted redaction after extraction", `"textExtraction":"always","redaction":{"customPattern":"hello"}`, "aGVsbG8=", false, false, true},
			{"ASCII after extraction", `"textExtraction":"always"`, "w6k=", true, true, false},
			{"opaque cannot bypass ASCII", `"textExtraction":"off"`, "aGVsbG8=", true, true, false},
			{"opaque cannot bypass redaction", `"redaction":{"customPattern":"hello"}`, "aGVsbG8=", false, true, false},
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
					const envelope = `{"version":1,"keyId":"3a1121028ba40964d5f10b47662650a021d736bd671f4083b5066d9bd51c9ef0","salt":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","nonce":"BAQEBAQEBAQEBAQE","blob":"MUgKUlBwNjuw0aMvsAVKMdfwJ_mzeyhYggR0-E20ahBYWNcbmyo_HmA"}`
					document := []byte(`{"plugins":{"textExtraction":"always","redaction":{"encrypted":` + envelope + `}}}`)
					if _, missingErr := policy.OpenSource(document, "org-test", nil); missingErr == nil {
						t.Fatal("encrypted redaction accepted without key")
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
				resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + route, Policy: config, Body: []byte(`{"model":"provider:openai gpt-5.5","` + field + `":[{"role":"user","content":[` + block + `]}]}`)})
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
				if resolved.InputFiles().InlineBytes != 5 || resolved.InputFiles().Opaque != "" {
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
	resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(`{"model":"provider:openai gpt-5.5","input":[{"role":"user","content":[{"type":"input_file","file_id":"file-owned-by-someone-else"}]}]}`)})
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

// customerOpenAICredential prepares a customer's own encrypted OpenAI
// credential, as the gateway does for each pair.
func customerOpenAICredential(t *testing.T) (*billing.KeyConfigSnapshot, *billing.PreparedCredential) {
	t.Helper()
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
		PolicySnapshot: billing.PolicySnapshot{Config: &policy.Config{}, EncryptionKeys: map[string]string{"default": key.ID()}},
		Credentials:    map[string][]billing.CredentialSelection{"openai": {{Mode: "encrypted", ID: id, Credential: &billing.CachedCredential{ID: id, OrganizationID: "org-test", Provider: "openai", Kind: "encrypted", Enabled: true, EncryptionKeyID: key.ID(), EncryptedSecret: envelope}}}},
	}
	prepared, err := (&billing.Service{}).PrepareCredential(snapshot, "openai", 0, customerkey.Keys{"default": key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(prepared.Clear)
	return snapshot, prepared
}

func TestProviderFileIDWithPreparedBYOKHoldsFullInput(t *testing.T) {
	snapshot, prepared := customerOpenAICredential(t)
	for _, kind := range []string{"input_file", "input_image"} {
		t.Run(kind, func(t *testing.T) {
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(`{"model":"provider:openai gpt-5.5","max_output_tokens":100,"input":[{"role":"user","content":[{"type":"` + kind + `","file_id":"file-customer-owned"}]}]}`)})
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
	for _, model := range []string{"provider:anthropic anthropic-claude-opus-5-fast-us", "provider:azure azure-claude-opus-4-8"} {
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
	for _, model := range []string{"provider:openai gpt-5.5", "provider:anthropic anthropic-claude-opus-5-fast-us"} {
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
					// No OpenAI Chat deployment fetches a URL, so routing refuses one.
					if model == "provider:openai gpt-5.5" && route == "chat/completions" && file.name == "URL" {
						if catalog.PublicError(err).Code != catalog.AttachmentUnsupported {
							t.Fatalf("OpenAI Chat admitted a URL requiring gateway fetch: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
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
	const (
		chatPart      = "messages[0].content[0]"
		responsesPart = "input[0].content[0]"
		subject       = " any deployment that this request can use"
		hint          = ". Turn on plugins.textExtraction to send it as text"
		// text is "hello", and binary are bytes that no format's signature matches.
		text   = "aGVsbG8="
		binary = "AAECAwQ="
	)
	for _, tc := range []struct {
		name, model, route, mime, filename, payload string
		extract, raw                                bool
		// refusal is the error of a file that the model's one deployment cannot read.
		refusal string
	}{
		{"OpenAI Chat PDF", "openai-gpt-5.6-luna", "chat/completions", "application/pdf", "note.pdf", binary, false, false, ""},
		{"OpenAI Chat CSV", "openai-gpt-5.6-luna", "chat/completions", "text/csv", "note.csv", text, false, false, chatPart + " is text/csv, which is not supported by" + subject + hint},
		{"OpenAI Chat untyped source file", "openai-gpt-5.6-luna", "chat/completions", "", "main.rs", text, false, true, chatPart + " has no media type, and its filename extension is not supported by" + subject + hint},
		{"OpenAI Chat extracted CSV", "openai-gpt-5.6-luna", "chat/completions", "text/csv", "note.csv", text, true, false, ""},
		{"OpenAI Responses CSV", "openai-gpt-5.6-luna", "responses", "text/csv", "note.csv", text, false, false, ""},
		{"OpenAI Responses DOCX", "openai-gpt-5.6-luna", "responses", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "note.docx", binary, false, false, ""},
		{"OpenAI Responses unknown binary", "openai-gpt-5.6-luna", "responses", "application/x-unknown", "note.pdf", binary, false, false, responsesPart + " is application/x-unknown, which is not supported by" + subject},
		{"OpenAI raw PDF filename", "openai-gpt-5.6-luna", "chat/completions", "", "note.PDF", binary, false, true, ""},
		{"OpenAI unknown filename", "openai-gpt-5.6-luna", "responses", "", "note.unknown", binary, false, true, responsesPart + " has no media type, and its filename extension is not supported by" + subject},
		{"OpenAI octet-stream PDF filename", "openai-gpt-5.6-luna", "responses", "application/octet-stream", "note.pdf", binary, false, false, ""},
		{"Anthropic plain text", "anthropic-claude-opus-4-8", "responses", "text/plain", "note.txt", text, false, false, ""},
		{"Anthropic untyped raw binary", "anthropic-claude-opus-4-8", "responses", "", "note.txt", binary, false, true, responsesPart + " needs a base64 data URL that names its media type, such as application/pdf, for" + subject},
		{"Anthropic extracted CSV", "anthropic-claude-opus-4-8", "responses", "text/csv", "note.csv", text, true, false, ""},
		{"Azure Responses PDF", "azure-gpt-5.6-luna", "responses", "application/pdf", "note.pdf", binary, false, false, ""},
		{"Azure Chat PDF", "azure-gpt-5.6-luna", "chat/completions", "application/pdf", "note.pdf", binary, false, false, chatPart + " documents are not supported by" + subject},
		{"Azure extracted text", "azure-gpt-5.6-luna", "chat/completions", "text/plain", "note.txt", text, true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var config *policy.Config
			if tc.extract {
				source, err := policy.CompileSource([]byte(`{"plugins":{"textExtraction":"always"}}`))
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
			data := tc.payload
			if !tc.raw {
				data = "data:" + tc.mime + ";base64," + data
			}
			file := `"file_data":"` + data + `","filename":"` + tc.filename + `"`
			block, field := `{"type":"file","file":{`+file+`}}`, "messages"
			if tc.route == "responses" {
				block, field = `{"type":"input_file",`+file+`}`, "input"
			}
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + tc.route, Policy: config, Body: []byte(`{"model":"` + tc.model + `","` + field + `":[{"role":"user","content":[` + block + `]}]}`)})
			// The model has one deployment, so routing refuses a file that it cannot read.
			if tc.refusal != "" {
				if public := catalog.PublicError(err); public.Code != catalog.AttachmentUnsupported || public.Message != tc.refusal {
					t.Fatalf("want %q: %v", tc.refusal, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatal(err)
			}
			// The gateway reads a text file, as a file or as extracted text, and holds its tokens.
			// Any other file holds the deployment's whole input.
			estimate, _ := resolved.EstimatedInputTokens()
			if opaque := resolved.InputFiles().Opaque != ""; opaque != (tc.payload == binary) || opaque != (estimate == resolved.Deployment.MaxInputTokens) {
				t.Fatalf("opaque %v, hold %d of %d", opaque, estimate, resolved.Deployment.MaxInputTokens)
			}
		})
	}
}

// A text file stays a file wherever the deployment reads plain text, declared as the provider
// reads it, and its name and type never decide that: source files reach a browser with no media
// type, and providers list few text types. Elsewhere it needs text extraction.
func TestTextFilesReachTheProviderAsItReadsThem(t *testing.T) {
	const (
		claude = "anthropic-claude-opus-4-8"
		openai = "openai-gpt-5.6-luna"
		// claudeText is how Claude reads a text file.
		claudeText = `"source":{"type":"text","media_type":"text/plain","data":"hello"}`
	)
	for _, tc := range []struct {
		name, model, route, policy, file string
		// want is in the provider's request, and opaque whether the gateway could not read the file.
		want   string
		opaque bool
	}{
		{"Claude reads Markdown as plain text", claude, "responses", `{}`, `"file_data":"data:text/markdown;base64,aGVsbG8=","filename":"README.md"`, claudeText, false},
		{"Claude reads a type that core does not convert", claude, "chat/completions", `{}`, `"file_data":"data:application/toml;base64,aGVsbG8=","filename":"Cargo.toml"`, claudeText, false},
		{"Claude reads a source file with no type", claude, "responses", `{}`, `"file_data":"aGVsbG8=","filename":"main.rs"`, claudeText, false},
		{"Claude reads a source file that a browser calls binary", claude, "chat/completions", `{}`, `"file_data":"data:application/octet-stream;base64,aGVsbG8=","filename":"main.go"`, claudeText, false},
		{"Claude reads raw text with file_type", claude, "chat/completions", `{}`, `"file_data":"aGVsbG8=","file_type":"text/plain","filename":"note.txt"`, claudeText, false},
		{"auto keeps a file that Claude reads", claude, "responses", `{"plugins":{"textExtraction":"auto"}}`, `"file_data":"data:text/x-python;base64,aGVsbG8=","filename":"main.py"`, claudeText, false},
		{"OpenAI Responses reads a type that it lists as it is", openai, "responses", `{}`, `"file_data":"data:text/csv;base64,aGVsbG8=","filename":"orders.csv"`, `"file_data":"data:text/csv;base64,aGVsbG8="`, false},
		{"OpenAI Responses reads a type that it does not list as plain text", openai, "responses", `{}`, `"file_data":"data:text/x-zig;base64,aGVsbG8=","filename":"main.zig"`, `"file_data":"data:text/plain;base64,aGVsbG8="`, false},
		// Core names the type of a file that names none, from its content.
		{"OpenAI Responses reads an extension that it lists", openai, "responses", `{}`, `"file_data":"aGVsbG8=","filename":"main.py"`, `"file_data":"data:text/plain;base64,aGVsbG8="`, false},
		{"OpenAI Responses reads an extension that it does not list", openai, "responses", `{}`, `"file_data":"aGVsbG8=","filename":"main.zig"`, `"file_data":"data:text/plain;base64,aGVsbG8="`, false},
		{"OpenAI Chat needs extraction", openai, "chat/completions", `{"plugins":{"textExtraction":"auto"}}`, `"file_data":"data:text/csv;base64,aGVsbG8=","filename":"orders.csv"`, `"text":"orders.csv (text/csv)\nhello"`, false},
		{"extraction names a file with no type", openai, "chat/completions", `{"plugins":{"textExtraction":"auto"}}`, `"file_data":"aGVsbG8=","filename":"main.rs"`, `"text":"main.rs\nhello"`, false},
		{"always extracts a file that the deployment reads", openai, "responses", `{"plugins":{"textExtraction":"always"}}`, `"file_data":"aGVsbG8=","filename":"main.py"`, `"text":"main.py\nhello"`, false},
		// "café" in Latin-1 starts as text and is not UTF-8.
		{"text in another encoding with no type stays a file", openai, "responses", `{"plugins":{"textExtraction":"always"}}`, `"file_data":"Y2Fm6Q==","filename":"note.txt"`, `"file_data":"data:text/plain;base64,Y2Fm6Q=="`, true},
		{"the provider decides on text in another encoding", openai, "responses", `{}`, `"file_data":"data:text/x-zig;base64,Y2Fm6Q==","filename":"main.zig"`, `"file_data":"data:text/plain;base64,Y2Fm6Q=="`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := policy.CompileSource([]byte(tc.policy))
			if err != nil {
				t.Fatal(err)
			}
			config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
			if err != nil {
				t.Fatal(err)
			}
			block, field := `{"type":"file","file":{`+tc.file+`}}`, "messages"
			if tc.route == "responses" {
				block, field = `{"type":"input_file",`+tc.file+`}`, "input"
			}
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + tc.route, Policy: config, Body: []byte(`{"model":"` + tc.model + `","` + field + `":[{"role":"user","content":[` + block + `]}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			estimate, _ := resolved.EstimatedInputTokens()
			if opaque := resolved.InputFiles().Opaque != ""; opaque != tc.opaque || opaque != (estimate == resolved.Deployment.MaxInputTokens) {
				t.Fatalf("opaque %v, hold %d of %d", opaque, estimate, resolved.Deployment.MaxInputTokens)
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
			if !bytes.Contains(body, []byte(tc.want)) {
				t.Fatalf("provider request lacks %s: %s", tc.want, body)
			}
		})
	}
}

// Auto extraction turns a text file into prompt text where the selected deployment reads no text
// file, or where input checks must read it.
func TestAutoTextExtractionFollowsTheDeployment(t *testing.T) {
	for _, tc := range []struct {
		name, model, route, mime, policy string
		extracted                        bool
	}{
		{"Anthropic reads plain text", "anthropic-claude-opus-4-8", "responses", "text/plain", `{"plugins":{"textExtraction":"auto"}}`, false},
		{"Anthropic reads CSV as plain text", "anthropic-claude-opus-4-8", "responses", "text/csv", `{"plugins":{"textExtraction":"auto"}}`, false},
		{"OpenAI Responses reads CSV", "openai-gpt-5.6-luna", "responses", "text/csv", `{"plugins":{"textExtraction":"auto"}}`, false},
		{"OpenAI Chat does not read CSV", "openai-gpt-5.6-luna", "chat/completions", "text/csv", `{"plugins":{"textExtraction":"auto"}}`, true},
		{"input checks read the text", "openai-gpt-5.6-luna", "responses", "text/csv", `{"plugins":{"textExtraction":"auto"},"input":{"asciiOnly":true}}`, true},
		{"redaction reads the text", "anthropic-claude-opus-4-8", "responses", "text/plain", `{"plugins":{"textExtraction":"auto","redaction":{"email_address":true}}}`, true},
		{"always", "anthropic-claude-opus-4-8", "responses", "text/plain", `{"plugins":{"textExtraction":"always"}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := policy.CompileSource([]byte(tc.policy))
			if err != nil {
				t.Fatal(err)
			}
			config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
			if err != nil {
				t.Fatal(err)
			}
			file := `"file_data":"data:` + tc.mime + `;base64,aGVsbG8=","filename":"note"`
			block, field := `{"type":"file","file":{`+file+`}}`, "messages"
			if tc.route == "responses" {
				block, field = `{"type":"input_file",`+file+`}`, "input"
			}
			body := []byte(`{"model":"` + tc.model + `","` + field + `":[{"role":"user","content":[` + block + `]}]}`)
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + tc.route, Policy: config, Body: body})
			if err != nil {
				t.Fatal(err)
			}
			// The name of a file counts as text, and extraction adds the file's text to it.
			if text, _ := resolved.InputTextBytes(); (text != len("note")) != tc.extracted || resolved.InputFiles().Count != 1 {
				t.Fatalf("%d text bytes, files %+v", text, resolved.InputFiles())
			}
			state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatal(err)
			}
		})
	}
}
