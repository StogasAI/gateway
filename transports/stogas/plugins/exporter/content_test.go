package exporter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestChatReasoningWireAliasesAndDetails(t *testing.T) {
	for _, tc := range []struct {
		name, fields, reasoning, summary string
		omitted                          bool
	}{
		{"reasoning", `"reasoning":"thinking"`, "thinking", "", false},
		{"reasoning_content", `"reasoning_content":"thinking"`, "thinking", "", false},
		{"both aliases and details", `"reasoning":"thinking","reasoning_content":"thinking","reasoning_details":[{"type":"reasoning.text","text":"thinking","index":0}]`, "thinking", "", false},
		{"detail only", `"reasoning_details":[{"type":"reasoning.text","text":"think","index":0},{"type":"reasoning.text","text":"ing","index":1},{"type":"reasoning.summary","summary":"summary","index":2}]`, "thinking", "summary", false},
		{"signed and encrypted", `"reasoning_details":[{"type":"reasoning.text","text":"thinking","signature":"secret-signature","index":0},{"type":"reasoning.encrypted","data":"secret-ciphertext","index":1}]`, "thinking", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := New(context.Background(), Options{})
			defer e.Close()
			for _, mode := range []string{"input", "unary", "stream"} {
				t.Run(mode, func(t *testing.T) {
					c := e.Start("org", mode, testConfig("https://example.com/v1/traces"))
					defer c.Discard()
					wire := `{"role":"assistant","content":"answer",` + tc.fields + `}`
					if mode == "stream" {
						var d schemas.ChatStreamResponseChoiceDelta
						if err := json.Unmarshal([]byte(wire), &d); err != nil {
							t.Fatal(err)
						}
						c.Chunk(&schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &d}}}}})
					} else {
						var m schemas.ChatMessage
						if err := json.Unmarshal([]byte(wire), &m); err != nil {
							t.Fatal(err)
						}
						if mode == "input" {
							c.Input(&schemas.BifrostRequest{ChatRequest: &schemas.BifrostChatRequest{Input: []schemas.ChatMessage{m}}})
						} else {
							c.Response(&schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{Message: &m}}}}})
						}
					}
					conversation := &c.output
					if mode == "input" {
						conversation = &c.input
					}
					raw, _, truncated := conversation.encode(65536)
					if truncated || conversation.omitted != tc.omitted || strings.Contains(raw, "secret-") {
						t.Fatalf("capture flags/content: %s", raw)
					}
					var got []genAIMessage
					if err := json.Unmarshal([]byte(raw), &got); err != nil {
						t.Fatal(err)
					}
					want := []map[string]any{{"type": "reasoning", "content": tc.reasoning}}
					if tc.summary != "" {
						want = append(want, map[string]any{"type": "reasoning", "content": tc.summary})
					}
					want = append(want, map[string]any{"type": "text", "content": "answer"})
					actual, _ := json.Marshal(got[0].Parts)
					expected, _ := json.Marshal(want)
					if string(actual) != string(expected) {
						t.Fatalf("parts %s; want %s", actual, expected)
					}
				})
			}
		})
	}
}

func TestResponsesReasoningAndCustomTools(t *testing.T) {
	const output = `[{"type":"reasoning","content":[{"type":"reasoning_text","text":"raw thinking","signature":"secret-signature"}],"summary":[{"type":"summary_text","text":"summary"}],"encrypted_content":"secret-ciphertext"},{"type":"custom_tool_call","call_id":"call_1","name":"freeform","input":"123"}]`
	const reply = `{"type":"custom_tool_call_output","call_id":"call_1","output":[{"type":"input_text","text":"tool reply"},{"type":"input_image","image_url":"https://example.com/private.png"}]}`
	for _, mode := range []string{"unary", "stream"} {
		t.Run(mode, func(t *testing.T) {
			e := New(context.Background(), Options{})
			defer e.Close()
			c := e.Start("org", "id", testConfig("https://example.com/v1/traces"))
			defer c.Discard()
			var req schemas.BifrostResponsesRequest
			if err := json.Unmarshal([]byte(`{"input":`+strings.TrimSuffix(output, "]")+`,`+reply+`]}`), &req); err != nil {
				t.Fatal(err)
			}
			c.Input(&schemas.BifrostRequest{ResponsesRequest: &req})
			if mode == "stream" {
				for _, wire := range []string{
					`{"type":"response.output_item.added","output_index":0,"item":{"type":"reasoning","summary":[]}}`,
					`{"type":"response.reasoning_summary_text.delta","output_index":0,"content_index":0,"summary_index":0,"delta":"raw "}`,
					`{"type":"response.reasoning_summary_text.delta","output_index":0,"summary_index":0,"delta":"sum"}`,
					`{"type":"response.output_item.added","output_index":1,"item":{"type":"custom_tool_call","call_id":"call_1","name":"freeform","input":""}}`,
					`{"type":"response.custom_tool_call_input.delta","output_index":1,"delta":"1"}`,
					`{"type":"response.custom_tool_call_input.delta","output_index":1,"delta":"23"}`,
					`{"type":"response.completed","response":{"status":"completed","output":` + output + `}}`,
				} {
					var chunk schemas.BifrostResponsesStreamResponse
					if err := json.Unmarshal([]byte(wire), &chunk); err != nil {
						t.Fatal(err)
					}
					c.Chunk(&schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: &chunk})
				}
			} else {
				var response schemas.BifrostResponsesResponse
				if err := json.Unmarshal([]byte(`{"status":"completed","output":`+output+`}`), &response); err != nil {
					t.Fatal(err)
				}
				c.Response(&schemas.BifrostResponse{ResponsesResponse: &response})
			}
			raw, _, truncated := c.output.encode(65536)
			const want = `[{"role":"assistant","parts":[{"content":"raw thinking","type":"reasoning"},{"content":"summary","type":"reasoning"},{"arguments":"123","id":"call_1","name":"freeform","type":"tool_call"}],"finish_reason":"tool_call"}]`
			if raw != want || truncated || !c.output.omitted {
				t.Fatalf("output %s truncated=%v omitted=%v", raw, truncated, c.output.omitted)
			}
			raw, _, truncated = c.input.encode(65536)
			const inputWant = `[{"role":"assistant","parts":[{"content":"raw thinking","type":"reasoning"},{"content":"summary","type":"reasoning"}]},{"role":"assistant","parts":[{"arguments":"123","id":"call_1","name":"freeform","type":"tool_call"}]},{"role":"tool","parts":[{"id":"call_1","response":"tool reply","type":"tool_call_response"}]}]`
			if raw != inputWant || truncated || !c.input.omitted {
				t.Fatalf("input %s truncated=%v omitted=%v", raw, truncated, c.input.omitted)
			}
		})
	}
}
