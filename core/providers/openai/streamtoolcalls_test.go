package openai

import (
	"fmt"
	"strings"
	"testing"
)

// TestChatStreamNumbersApartToolCallsThatShareAnIndex streams five tool calls as Gemma 4 on Google
// Cloud does, each at index 0 under its own ID with the arguments after it (capture
// google-cloud/chat-completions-fields), and as servers that number calls apart do, with the
// arguments of two calls interleaved. Joined by index, each stream gives the client every call
// with its own arguments.
func TestChatStreamNumbersApartToolCallsThatShareAnIndex(t *testing.T) {
	cities := []string{"Paris", "Rome", "Berlin", "Madrid", "Vienna"}
	delta := func(index int, id, name, arguments string) string {
		call := fmt.Sprintf(`{"index":%d,"type":"function","id":%s,"function":{"name":%s,"arguments":%q}}`,
			index, id, name, arguments)
		return `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m",` +
			`"choices":[{"index":0,"delta":{"tool_calls":[` + call + `]},"finish_reason":null}]}` + "\n\n"
	}
	end := `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m",` +
		`"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\ndata: [DONE]\n\n"
	var gemma, apart strings.Builder
	for i, city := range cities {
		gemma.WriteString(delta(0, fmt.Sprintf(`"call_%d"`, i), `"get_weather"`, ""))
		gemma.WriteString(delta(0, "null", "null", `{"city": "`+city+`"}`))
	}
	for i := range cities {
		apart.WriteString(delta(i, fmt.Sprintf(`"call_%d"`, i), `"get_weather"`, ""))
	}
	for i, city := range cities {
		// The ID again on each delta, which some servers send.
		apart.WriteString(delta(i, fmt.Sprintf(`"call_%d"`, i), "null", `{"city": "`+city+`"}`))
	}
	for name, body := range map[string]string{"one index": gemma.String(), "apart": apart.String()} {
		t.Run(name, func(t *testing.T) {
			server := completeSSEServer(t, body+end)
			defer server.Close()
			stream, err := newStreamTestProvider(server.URL).ChatCompletionStream(newStreamTestContext(), passthroughPostHook, nil, testKey(), basicChatRequest())
			if err != nil {
				t.Fatal(err)
			}
			ids := map[uint16]string{}
			arguments := map[uint16]string{}
			for _, chunk := range collectChunks(t, stream) {
				if chunk.BifrostError != nil {
					t.Fatal(chunk.BifrostError.Error)
				}
				if chunk.BifrostChatResponse == nil {
					continue
				}
				for _, choice := range chunk.BifrostChatResponse.Choices {
					if choice.ChatStreamResponseChoice == nil || choice.ChatStreamResponseChoice.Delta == nil {
						continue
					}
					for _, call := range choice.ChatStreamResponseChoice.Delta.ToolCalls {
						if call.ID != nil && ids[call.Index] == "" {
							ids[call.Index] = *call.ID
						}
						arguments[call.Index] += call.Function.Arguments
					}
				}
			}
			for i, city := range cities {
				index := uint16(i)
				if ids[index] != fmt.Sprintf("call_%d", i) || arguments[index] != `{"city": "`+city+`"}` {
					t.Fatalf("index %d: call %q with arguments %q", i, ids[index], arguments[index])
				}
			}
			if len(arguments) != len(cities) {
				t.Fatalf("the client got %d calls", len(arguments))
			}
		})
	}
}
