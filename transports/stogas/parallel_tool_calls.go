package stogas

import "github.com/maximhq/bifrost/core/schemas"

// A request with parallel_tool_calls false asks for at most one tool call per turn. OpenAI's models
// and Claude keep to it, while other models ignore it or have no such control: Gemma 4 and
// DeepSeek V4.1 Flash on Google Cloud call several tools at once (capture
// google-cloud/chat-completions-fields), as Kimi K3 does on Bedrock (capture
// aws/chat-completions-tools), and Gemini has no such setting. So the gateway delivers only the
// first tool call of each Chat Completions reply, as vLLM does for the models that it serves, and
// every deployment can serve the request. A reply in another interface comes from a model that
// keeps to the field itself.

// keepFirstToolCall leaves a reply with its first tool call when the client asked for one.
func keepFirstToolCall(state *State, response *schemas.BifrostChatResponse) {
	if response == nil || !oneToolCall(state) {
		return
	}
	for _, choice := range response.Choices {
		reply := choice.ChatNonStreamResponseChoice
		if reply == nil || reply.Message == nil || reply.Message.ChatAssistantMessage == nil {
			continue
		}
		if calls := reply.Message.ChatAssistantMessage.ToolCalls; len(calls) > 1 {
			reply.Message.ChatAssistantMessage.ToolCalls = calls[:1]
		}
	}
}

// keepFirstStreamedToolCall leaves a stream with the deltas of its first tool call when the client
// asked for one. A stream has one choice, because the gateway refuses n other than 1, and names
// each call by its index.
func (s *State) keepFirstStreamedToolCall(response *schemas.BifrostChatResponse) {
	if response == nil || !oneToolCall(s) {
		return
	}
	for _, choice := range response.Choices {
		stream := choice.ChatStreamResponseChoice
		if stream == nil || stream.Delta == nil || len(stream.Delta.ToolCalls) == 0 {
			continue
		}
		var kept []schemas.ChatAssistantMessageToolCall
		for _, call := range stream.Delta.ToolCalls {
			if s.streamToolCall == nil {
				first := call.Index
				s.streamToolCall = &first
			}
			if call.Index == *s.streamToolCall {
				kept = append(kept, call)
			}
		}
		stream.Delta.ToolCalls = kept
	}
}

// oneToolCall reports whether the client asked for at most one tool call per turn: the field
// remains only as false, and only with tools (catalog's dropNoOpCompatibilityFields).
func oneToolCall(state *State) bool {
	return state != nil && state.Resolution != nil && rawJSONValueSet(state.Resolution.RawBody()["parallel_tool_calls"])
}
