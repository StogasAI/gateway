package stogas

import (
	"fmt"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func toolScaleBodies(count int) (chat, responses string) {
	chatTools := make([]string, count)
	responsesTools := make([]string, count)
	allowed := make([]string, count)
	for index := range count {
		chatTools[index] = fmt.Sprintf(`{"type":"function","function":{"name":"tool_%d","parameters":{"type":"object"}}}`, index)
		responsesTools[index] = fmt.Sprintf(`{"type":"function","name":"tool_%d","parameters":{"type":"object"}}`, index)
		allowed[index] = fmt.Sprintf(`{"type":"function","name":"tool_%d"}`, index)
	}
	chat = `{"model":"openai/gpt-5.6-luna","messages":[{"role":"user","content":"hi"}],"tools":[` + strings.Join(chatTools, ",") + `]}`
	responses = `{"model":"openai/gpt-5.6-luna","input":"hi","tools":[` + strings.Join(responsesTools, ",") +
		`],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[` + strings.Join(allowed, ",") + `]}}`
	return chat, responses
}

func admitToolScaleRequest(b *testing.B, path, body string) *State {
	b.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: path, Body: []byte(body)})
	if err != nil {
		b.Fatal(err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		b.Fatal(err)
	}
	return state
}

// Response checks read the callable tools once per request, so each call or stream
// event costs the same for any tool count.
func BenchmarkProviderToolChecks(b *testing.B) {
	for _, count := range []int{128, 10_000} {
		chatBody, responsesBody := toolScaleBodies(count)
		chat := admitToolScaleRequest(b, "/v1/chat/completions", chatBody)
		responses := admitToolScaleRequest(b, "/v1/responses", responsesBody)
		last := fmt.Sprintf("tool_%d", count-1)
		b.Run(fmt.Sprintf("chat_name/%d", count), func(b *testing.B) {
			for b.Loop() {
				if !providerChatToolNameAllowed(chat, last) {
					b.Fatal("declared tool rejected")
				}
			}
		})
		b.Run(fmt.Sprintf("responses_type/%d", count), func(b *testing.B) {
			for b.Loop() {
				if !providerResponsesToolTypeAllowed(responses, schemas.ResponsesToolTypeFunction) {
					b.Fatal("declared tool type rejected")
				}
			}
		})
		b.Run(fmt.Sprintf("responses_name/%d", count), func(b *testing.B) {
			for b.Loop() {
				if !providerResponsesToolNameAllowed(responses, schemas.ResponsesToolTypeFunction, last) {
					b.Fatal("allowed tool rejected")
				}
			}
		})
	}
}

// Tools cost about as much per byte to admit as messages, so the body and JSON-value
// bounds also bound tool work.
func BenchmarkToolRequestAdmission(b *testing.B) {
	chat, responses := toolScaleBodies(4_096)
	messages := `{"model":"openai/gpt-5.6-luna","messages":[` +
		strings.Repeat(`{"role":"user","content":"hi"},`, 99_999) + `{"role":"user","content":"hi"}]}`
	for _, request := range []struct{ name, path, body string }{
		{"chat_4096_tools", "/v1/chat/completions", chat},
		{"responses_4096_tools", "/v1/responses", responses},
		{"chat_100000_messages", "/v1/chat/completions", messages},
	} {
		b.Run(request.name, func(b *testing.B) {
			b.SetBytes(int64(len(request.body)))
			b.ReportAllocs()
			for b.Loop() {
				admitToolScaleRequest(b, request.path, request.body)
			}
		})
	}
}
