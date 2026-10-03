package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
	"github.com/maximhq/bifrost/transports/stogas/tokenizer"
)

// The local reservation includes text, its buffer and message framing. This is
// a synthetic three-million-token deployment, not a provider acceptance claim.
// Adversarial shapes stay within that estimate and the 128-MiB wire limit; some
// deliberately maximize bytes or structure instead of filling the token budget.
func BenchmarkRequestThreeMillionContext(b *testing.B) {
	const contextTokens = 3_000_000
	snap, err := loadSnapshot()
	if err != nil {
		b.Fatal(err)
	}
	deployment := snap.graph.Deployments["openai-gpt-5.6-sol"]
	deployment.ContextWindowTokens = contextTokens
	snap.graph.Deployments["openai-gpt-5.6-sol"] = deployment
	previous := active.Swap(snap)
	b.Cleanup(func() { active.Store(previous) })
	codec, err := tokenizer.Get(tokenizer.O200kBase)
	if err != nil {
		b.Fatal(err)
	}
	scopes := []policy.Scope{policy.OrganizationScope, policy.FolderScope, policy.GrantScope, policy.RoleScope, policy.MemberScope, policy.CredentialScope, policy.KeyScope}
	sources := make([]policy.ScopedSource, len(scopes))
	for i, scope := range scopes {
		literals := make([]string, 0, 143)
		exactLiterals := make([]string, 0, 16)
		for n := 1000 * i / len(scopes); n < 1000*(i+1)/len(scopes); n++ {
			value := fmt.Sprintf("CONFIDENTIAL_CUSTOMER_%04d", n)
			if n < 984 {
				literals = append(literals, value+strings.Repeat("X", 64-len(value)))
			} else {
				exactLiterals = append(exactLiterals, value+strings.Repeat("X", 160-len(value)))
			}
		}
		groups := []map[string]any{{"values": literals, "ignoreCase": true, "fuzzy": true}}
		if len(exactLiterals) > 0 {
			groups = append(groups, map[string]any{"values": exactLiterals, "ignoreCase": true})
		}
		predicates := make([]string, 27)
		for n := range predicates {
			predicates[n] = fmt.Sprintf("provider.id != 'blocked_%d_%d'", i, n)
		}
		document := map[string]any{
			"delegation": map[string]any{"request": true},
			"routing":    map[string]any{"filter": strings.Join(predicates, " && "), "sort": []map[string]any{{"by": "deployment.id", "direction": "asc"}}},
			"limits": map[string]any{
				"spend": map[string]any{"lifetimeUsd": "1000000", "recurring": map[string]any{
					"daily":   map[string]any{"maxUsd": "100000", "timeZone": "UTC", "window": map[string]any{"count": 1, "unit": "day"}},
					"monthly": map[string]any{"maxUsd": "100000", "timeZone": "UTC", "window": map[string]any{"count": 1, "unit": "month"}},
				}},
				"requests":       map[string]any{"rate": map[string]any{"max": 60, "window": map[string]any{"count": 1, "unit": "second"}}},
				"tokens":         map[string]any{"tokens": map[string]any{"max": 1_000_000_000, "window": map[string]any{"count": 1, "unit": "minute"}}},
				"lifetimeTokens": 1_000_000_000_000, "concurrentRequests": 10000,
			},
			"rules": map[string]any{
				"selected_provider": map[string]any{
					"when":    "provider.id == 'openai'",
					"limits":  map[string]any{"spend": map[string]any{"lifetimeUsd": "100000"}},
					"plugins": map[string]any{"stogasRedaction": map[string]any{"email_address": true}},
				},
			},
			"plugins": map[string]any{"stogasRedaction": map[string]any{
				"email_address": true, "phone_number": true, "social_security_number": true,
				"credit_card_number": true, "ip_address": true, "api_keys_and_secrets": true,
				"bank_identifiers": true, "national_identifiers": true, "health_identifiers": true,
				"customPattern": fmt.Sprintf("CONFIDENTIAL_%d_[0-9]{8}", i%3),
				"literals":      groups,
			}},
		}
		raw, _ := json.Marshal(document)
		source, err := policy.CompileSource(raw)
		if err != nil {
			b.Fatal(err)
		}
		sources[i] = policy.ScopedSource{Scope: scope, Value: source}
	}
	config, err := policy.ComposeSources(sources)
	if err != nil {
		b.Fatal(err)
	}
	plan, err := policy.CompileRedaction(config)
	if err != nil {
		b.Fatal(err)
	}
	for _, shape := range []string{"prose", "wide", "unbroken", "unicode", "messages", "escaped_prose", "escaped_unicode", "whitespace_max", "fuzzy_seeds", "dense_matches", "tool_schema"} {
		b.Run(shape, func(b *testing.B) {
			var messages any
			var tools json.RawMessage
			if shape == "messages" {
				// One text token and the existing per-message/block framing.
				const perMessageBps = openAIInputHoldTextBufferBps + 10000*(openAIInputHoldMessageTokens+openAIInputHoldBlockTokens)
				count := (contextTokens - openAIInputHoldBaseTokens - 100) * 10000 / perMessageBps
				messages = json.RawMessage(`[` + strings.Repeat(`{"role":"user","content":"a"},`, int(count)-1) + `{"role":"user","content":"a"}]`)
			} else if shape == "tool_schema" {
				messages = []map[string]string{{"role": "user", "content": "Select one allowed value."}}
				// A large schema puts many short strings through JSON traversal,
				// redaction and compact-schema token counting. Duplicate enum
				// values are intentionally untrusted input, not useful schema data.
				tools = json.RawMessage(`[{"type":"function","function":{"name":"choose","parameters":{"type":"string","enum":[` + strings.Repeat(`"a",`, 1_000_000-1) + `"a"]}}}]`)
			} else {
				seed := "The project explains how distributed services handle retries and resource allocation. Testing covers ordinary source code and document handling.\n"
				switch shape {
				case "wide":
					seed = strings.Repeat(" ", 96) + "a\n"
				case "unbroken":
					seed = strings.Repeat("x", 64)
				case "unicode", "escaped_unicode":
					seed = "这是一个用于测试的文本。"
				case "whitespace_max":
					seed = strings.Repeat(" ", 128)
				case "fuzzy_seeds":
					seed = "CONFIDENTIAL_CUSTOMER_9999" + strings.Repeat("X", 40) + " "
				case "dense_matches":
					seed = "person@corp.io "
				}
				seedTokens, err := codec.Count(seed)
				if err != nil {
					b.Fatal(err)
				}
				count := (contextTokens - openAIInputHoldBaseTokens - 100) * 10000 / (seedTokens * openAIInputHoldTextBufferBps)
				if shape == "whitespace_max" {
					// Leave room for the small JSON wrapper, checked below.
					count = ((128 << 20) - 1024) / len(seed)
				}
				if strings.HasPrefix(shape, "escaped_") {
					var escaped strings.Builder
					for _, r := range seed {
						fmt.Fprintf(&escaped, `\u%04x`, r)
					}
					messages = json.RawMessage(`[{"role":"user","content":"` + strings.Repeat(escaped.String(), count) + `"}]`)
				} else {
					messages = []map[string]string{{"role": "user", "content": strings.Repeat(seed, count)}}
				}
			}
			document := map[string]any{
				"model": "openai-gpt-5.6-sol", "max_completion_tokens": 16, "messages": messages,
				"policy": map[string]any{"routing": map[string]any{"filter": "provider.id == 'openai'"}},
			}
			if tools != nil {
				document["tools"] = tools
			}
			body, err := json.Marshal(document)
			if err != nil {
				b.Fatal(err)
			}
			if len(body) > 128<<20 {
				b.Fatalf("fixture exceeds 128-MiB request limit: %d bytes", len(body))
			}
			fields, err := DecodeRequestBody(body, nil)
			structureRejected := errors.Is(err, errRequestMessageLimit) || errors.Is(err, errRequestJSONValueLimit)
			if structureRejected {
				// Count the original adversarial fixture independently of admission.
				err = json.Unmarshal(body, &fields)
			}
			if err != nil {
				b.Fatal(err)
			}
			stats := requestInputHoldStats(fields, RouteChat)
			estimate, err := estimateInputHold(stats, tokenizationOpenAI, 0)
			if err != nil || estimate > contextTokens {
				b.Fatalf("fixture estimate=%d: %v", estimate, err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			var maximum time.Duration
			for b.Loop() {
				start := time.Now()
				resolved, err := ResolveRequest(RequestInput{
					Body: body, Method: "POST", Path: "/v1/chat/completions", Policy: config,
					AvailableCredentials: map[string][]int{"openai": {0}}, RedactionPolicy: plan,
				})
				maximum = max(maximum, time.Since(start))
				if structureRejected || shape == "unbroken" || shape == "fuzzy_seeds" || shape == "dense_matches" {
					if PublicError(err).StatusCode != 413 || resolved != nil {
						b.Fatalf("expected bounded redaction rejection: %v", err)
					}
				} else if err != nil || resolved == nil {
					b.Fatalf("resolve: %v", err)
				}
			}
			b.ReportMetric(float64(estimate), "estimated_context_tokens")
			b.ReportMetric(float64(len(body)), "request_bytes")
			b.ReportMetric(float64(maximum.Microseconds())/1000, "observed_max_ms")
		})
	}
}

func BenchmarkRequestMessageShape(b *testing.B) {
	snap, err := loadSnapshot()
	if err != nil {
		b.Fatal(err)
	}
	previous := active.Swap(snap)
	b.Cleanup(func() { active.Store(previous) })
	literals := make([]redaction.Literal, 1000)
	for i := range literals {
		literals[i] = redaction.Literal{Text: fmt.Sprintf("CONFIDENTIAL_CUSTOMER_%04d", i), Fuzzy: true, IgnoreCase: true}
	}
	plan, err := redaction.CompilePolicy(redaction.Options{
		Literals:       literals,
		Patterns:       []redaction.Pattern{redaction.PatternEmailAddress, redaction.PatternPhoneNumber, redaction.PatternSocialSecurityNumber, redaction.PatternCreditCardNumber, redaction.PatternIPAddress, redaction.PatternAPIKeysAndSecrets, redaction.PatternBankIdentifiers, redaction.PatternNationalIdentifiers, redaction.PatternHealthIdentifiers},
		CustomPatterns: []redaction.CustomPattern{{Expression: "CONFIDENTIAL_0_[0-9]{8}"}, {Expression: "CONFIDENTIAL_1_[0-9]{8}"}, {Expression: "CONFIDENTIAL_2_[0-9]{8}"}},
	})
	if err != nil {
		b.Fatal(err)
	}
	for _, count := range []int{10_000, maxRequestMessages, 3_000_000} {
		body := []byte(`{"model":"openai-gpt-5.6-sol","messages":[` + strings.Repeat(`{"role":"user","content":"a"},`, count-1) + `{"role":"user","content":"a"}]}`)
		b.Run(fmt.Sprintf("%d/validate", count), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				_, err := validateRequestJSON(body)
				if count > maxRequestJSONValues/3 && errors.Is(err, errRequestJSONValueLimit) {
					continue
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("%d/raw_decode", count), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				fields, err := DecodeRequestBody(body, nil)
				if count > maxRequestMessages && errors.Is(err, errRequestMessageLimit) {
					continue
				}
				if err != nil || len(fields["messages"]) == 0 {
					b.Fatalf("decode: %v", err)
				}
			}
		})
		b.Run(fmt.Sprintf("%d/typed_decode", count), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				var request openaiprovider.OpenAIChatRequest
				if err := sonic.Unmarshal(body, &request); err != nil || len(request.Messages) != count {
					b.Fatalf("typed decode: %v", err)
				}
			}
		})
		var raw map[string]json.RawMessage
		if err := sonic.Unmarshal(body, &raw); err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%d/hold_stats", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				stats := requestInputHoldStats(raw, RouteChat)
				if stats.Messages != count || len(stats.TextFields) != count {
					b.Fatalf("message stats = %d/%d", stats.Messages, len(stats.TextFields))
				}
			}
		})
		b.Run(fmt.Sprintf("%d/redaction", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				r := redaction.NewWithPolicy(plan)
				if err := r.RedactRequestFields(raw, redaction.SurfaceChat, nil); err != nil || r.Summary().ItemsRedacted != 0 {
					b.Fatalf("redaction = %v, %v", r.Summary(), err)
				}
			}
		})
		b.Run(fmt.Sprintf("%d/resolve", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				resolved, err := ResolveRequest(RequestInput{Body: body, Method: "POST", Path: "/v1/chat/completions", RedactionPolicy: plan})
				if count > maxRequestMessages && errors.Is(err, errRequestMessageLimit) && resolved == nil {
					continue
				}
				if err != nil || resolved == nil || len(resolved.chat.Messages) != count {
					b.Fatalf("resolve = %v", err)
				}
			}
		})
	}
}

// Compare the strict scan's scratch with map materialization after admission.
// Input construction is outside the measurement; rejected requests retain only
// their already-admitted body and parser scratch, never a decoded request map.
func BenchmarkRequestJSONAdmission(b *testing.B) {
	var names, escapedNames strings.Builder
	names.WriteByte('{')
	escapedNames.WriteByte('{')
	for i := range 100_000 {
		if i != 0 {
			names.WriteByte(',')
			escapedNames.WriteByte(',')
		}
		fmt.Fprintf(&names, `"%x":0`, i)
		fmt.Fprintf(&escapedNames, `"\u006b%x":0`, i)
	}
	names.WriteByte('}')
	escapedNames.WriteByte('}')
	for _, shape := range []struct {
		name string
		body string
	}{
		{"dense_values", `{"schema":[` + strings.Repeat("0,", maxRequestJSONValues-3) + "0]}"},
		{"top_level_names", names.String()},
		{"escaped_names", escapedNames.String()},
		{"long_escaped_string", `{"input":"` + strings.Repeat(`\u0061`, 1_000_000) + `"}`},
	} {
		body := []byte(shape.body)
		for _, reject := range []bool{true, false} {
			phase := "admitted"
			if reject {
				phase = "rejected"
			}
			b.Run(shape.name+"/"+phase, func(b *testing.B) {
				rejection := errors.New("capacity unavailable")
				admit := func(int) error {
					if reject {
						return rejection
					}
					return nil
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(body)))
				for b.Loop() {
					fields, err := DecodeRequestBody(body, admit)
					if reject {
						if !errors.Is(err, rejection) || fields != nil {
							b.Fatalf("rejected decode: %v", err)
						}
					} else if err != nil || fields == nil {
						b.Fatalf("admitted decode: %v", err)
					}
				}
				b.ReportMetric(float64(len(body)), "request_bytes")
			})
		}
	}
}
