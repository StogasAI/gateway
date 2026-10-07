package exporter

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
)

// Each field owns its bytes. No pooled Bifrost objects or full request graphs
// survive a capture call. Structural charges bound even arrays of empty items.
type text []byte

type message struct {
	FinishReason string
	Role         string
	Content      text
	Reasoning    text
	Summary      text
	Refusal      text
	ToolCallID   text
	ToolCalls    []toolCall
}
type toolCall struct {
	ID       text
	Function toolFunction
}
type toolFunction struct {
	Name      text
	Arguments text
	Custom    bool
}
type conversation struct {
	messages              []message
	keys                  map[int]int
	limit, used           int
	truncated, omitted    bool
	budget                *reservation
	output, combineOutput bool
	instructions          text
	snapshotOffsets       map[*text]int
}

func (c *conversation) take(n int) bool {
	if n > c.limit-c.used || !c.budget.grow(n*16) {
		c.truncated = true
		return false
	}
	c.used += n
	return true
}
func (c *conversation) add(key int, role string) *message {
	if i, ok := c.keys[key]; ok {
		return &c.messages[i]
	}
	if !c.take(256) {
		return nil
	}
	if c.keys == nil {
		c.keys = make(map[int]int)
	}
	c.keys[key] = len(c.messages)
	c.messages = append(c.messages, message{Role: strings.Clone(role), Content: text{}})
	return &c.messages[len(c.messages)-1]
}
func (c *conversation) append(dst *text, value string) {
	if c.snapshotOffsets != nil {
		offset := c.snapshotOffsets[dst]
		c.snapshotOffsets[dst] = offset + len(value)
		value = value[min(len(value), max(0, len(*dst)-offset)):]
	}
	n := min(len(value), max(0, c.limit-c.used))
	if n < len(value) {
		c.truncated = true
		for n > 0 && !utf8.RuneStart(value[n]) {
			n--
		}
	}
	if n == 0 || !c.take(n) {
		return
	}
	*dst = append(*dst, value[:n]...)
}
func (c *conversation) tool(m *message, index int) *toolCall {
	if index < 0 || index > exportconfig.MaxCaptureBytes/256 {
		c.truncated = true
		return nil
	}
	for len(m.ToolCalls) <= index {
		if !c.take(256) {
			return nil
		}
		m.ToolCalls = append(m.ToolCalls, toolCall{})
	}
	return &m.ToolCalls[index]
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

func (c *conversation) chat(key int, input schemas.ChatMessage) {
	m := c.add(key, string(input.Role))
	if m == nil {
		return
	}
	if input.Content != nil {
		c.append(&m.Content, value(input.Content.ContentStr))
		for _, block := range input.Content.ContentBlocks {
			if block.Text != nil {
				c.append(&m.Content, *block.Text)
			} else if block.Refusal != nil {
				c.append(&m.Refusal, *block.Refusal)
			} else {
				c.omitted = true
			}
			if c.truncated {
				break
			}
		}
	}
	if input.ChatToolMessage != nil {
		c.append(&m.ToolCallID, value(input.ToolCallID))
	}
	if input.ChatAssistantMessage != nil {
		c.chatReasoning(m, input.Reasoning, input.ReasoningDetails)
		c.append(&m.Refusal, value(input.Refusal))
		for i, t := range input.ToolCalls {
			c.chatTool(m, i, t)
			if c.truncated {
				break
			}
		}
		if input.Audio != nil {
			c.omitted = true
		}
	}
}
func (c *conversation) chatReasoning(m *message, reasoning *string, details []schemas.ChatReasoningDetails) {
	c.append(&m.Reasoning, value(reasoning))
	for _, detail := range details {
		switch detail.Type {
		case schemas.BifrostReasoningDetailsTypeText:
			// Bifrost may expose the same text in both fields, including details
			// synthesized while decoding OpenAI-compatible reasoning aliases.
			if reasoning == nil || *reasoning == "" {
				c.append(&m.Reasoning, value(detail.Text))
			}
		case schemas.BifrostReasoningDetailsTypeSummary:
			c.append(&m.Summary, value(detail.Summary))
		default:
			c.omitted = true
		}
		if detail.Signature != nil || detail.Data != nil {
			c.omitted = true
		}
		if c.truncated {
			break
		}
	}
}
func (c *conversation) chatTool(m *message, index int, t schemas.ChatAssistantMessageToolCall) {
	dst := c.tool(m, index)
	if dst == nil {
		return
	}
	c.append(&dst.ID, value(t.ID))
	c.append(&dst.Function.Name, value(t.Function.Name))
	c.append(&dst.Function.Arguments, t.Function.Arguments)
}
func (c *conversation) responses(key int, input schemas.ResponsesMessage) {
	if input.Type != nil {
		switch string(*input.Type) {
		case "message", "reasoning", "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output":
		default:
			c.omitted = true
			return
		}
	}
	role := value(input.Role)
	if role == "" {
		role = "assistant"
	}
	if value(input.Type) == "function_call_output" || value(input.Type) == "custom_tool_call_output" {
		role = "tool"
	}
	m := c.add(key, role)
	if m == nil {
		return
	}
	if input.Content != nil {
		c.append(&m.Content, value(input.Content.ContentStr))
		c.blocks(m, input.Content.ContentBlocks)
	}
	if input.ResponsesReasoning != nil {
		for _, part := range input.Summary {
			c.append(&m.Summary, part.Text)
			if c.truncated {
				break
			}
		}
		if input.EncryptedContent != nil {
			c.omitted = true
		}
	}
	if t := input.ResponsesToolMessage; t != nil {
		if t.Arguments != nil || t.Name != nil || t.ResponsesCustomToolCall != nil {
			dst := c.tool(m, 0)
			if dst != nil {
				c.append(&dst.ID, value(t.CallID))
				c.append(&dst.Function.Name, value(t.Name))
				dst.Function.Custom = value(input.Type) == "custom_tool_call"
				if dst.Function.Custom && t.ResponsesCustomToolCall != nil {
					c.append(&dst.Function.Arguments, t.ResponsesCustomToolCall.Input)
				} else {
					c.append(&dst.Function.Arguments, value(t.Arguments))
				}
			}
		}
		if t.Output != nil {
			c.append(&m.ToolCallID, value(t.CallID))
			c.append(&m.Content, value(t.Output.ResponsesToolCallOutputStr))
			c.blocks(m, t.Output.ResponsesFunctionToolCallOutputBlocks)
		}
	}
}
func (c *conversation) blocks(m *message, blocks []schemas.ResponsesMessageContentBlock) {
	for _, b := range blocks {
		switch {
		case b.Type == schemas.ResponsesOutputMessageContentTypeReasoning:
			c.append(&m.Reasoning, value(b.Text))
		case b.Text != nil:
			c.append(&m.Content, *b.Text)
		case b.ResponsesOutputMessageContentRefusal != nil:
			c.append(&m.Refusal, b.Refusal)
		default:
			c.omitted = true
		}
		if b.Signature != nil || b.EncryptedContent != nil {
			c.omitted = true
		}
		if c.truncated {
			break
		}
	}
}

func (c *Capture) Input(req *schemas.BifrostRequest) {
	if c == nil || req == nil {
		return
	}
	c.captureParameters(req)
	if c.input.limit == 0 {
		return
	}
	if req.ChatRequest != nil {
		for i, m := range req.ChatRequest.Input {
			c.input.chat(i, m)
			if c.input.truncated {
				break
			}
		}
	}
	if r := req.ResponsesRequest; r != nil {
		if r.Params != nil && r.Params.Instructions != nil {
			c.input.append(&c.input.instructions, *r.Params.Instructions)
		}
		for i, m := range r.Input {
			c.input.responses(i, m)
			if c.input.truncated {
				break
			}
		}
	}
}
func (c *Capture) Response(resp *schemas.BifrostResponse) {
	if c == nil || c.output.limit == 0 || resp == nil {
		return
	}
	if resp.ChatResponse != nil {
		for _, choice := range resp.ChatResponse.Choices {
			if choice.ChatNonStreamResponseChoice != nil && choice.Message != nil {
				c.output.chat(choice.Index, *choice.Message)
				if i, ok := c.output.keys[choice.Index]; ok {
					c.output.messages[i].FinishReason = finishReason(value(choice.FinishReason))
				}
			}
		}
	}
	if resp.ResponsesResponse != nil {
		c.output.combineOutput = true
		for i, m := range resp.ResponsesResponse.Output {
			c.output.responses(i, m)
			if c.output.truncated {
				break
			}
		}
		c.responseFinish(resp.ResponsesResponse)
	}
}
func (c *Capture) Chunk(chunk *schemas.BifrostStreamChunk) {
	if c == nil || c.output.limit == 0 || c.output.truncated || chunk == nil {
		return
	}
	if chat := chunk.BifrostChatResponse; chat != nil {
		for _, choice := range chat.Choices {
			m := c.output.add(choice.Index, "assistant")
			if m != nil && choice.FinishReason != nil {
				m.FinishReason = finishReason(*choice.FinishReason)
			}
			if choice.ChatStreamResponseChoice == nil || choice.Delta == nil {
				continue
			}
			d := choice.Delta
			if m == nil {
				return
			}
			c.output.append(&m.Content, value(d.Content))
			c.output.chatReasoning(m, d.Reasoning, d.ReasoningDetails)
			if d.Audio != nil {
				c.output.omitted = true
			}
			c.output.append(&m.Refusal, value(d.Refusal))
			for _, t := range d.ToolCalls {
				c.output.chatTool(m, int(t.Index), t)
			}
		}
	}
	if r := chunk.BifrostResponsesStreamResponse; r != nil {
		c.responseChunk(r)
	}
}
func (c *Capture) responseChunk(r *schemas.BifrostResponsesStreamResponse) {
	c.output.combineOutput = true
	if r.Signature != nil {
		c.output.omitted = true
	}
	key := 0
	if r.OutputIndex != nil {
		key = *r.OutputIndex
	}
	switch string(r.Type) {
	case "response.output_item.added":
		if r.Item != nil {
			c.output.responses(key, *r.Item)
		}
	case "response.output_text.delta", "response.refusal.delta", "response.reasoning_summary_text.delta", "response.reasoning_text.delta", "response.function_call_arguments.delta", "response.custom_tool_call_input.delta":
		m := c.output.add(key, "assistant")
		if m == nil {
			return
		}
		switch string(r.Type) {
		case "response.output_text.delta":
			c.output.append(&m.Content, value(r.Delta))
		case "response.refusal.delta":
			c.output.append(&m.Refusal, value(r.Delta))
		case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
			// Core also uses summary-named events for raw reasoning content.
			// ContentIndex takes precedence, including Anthropic's dual indexes.
			if r.Type == "response.reasoning_summary_text.delta" && r.ContentIndex == nil {
				c.output.append(&m.Summary, value(r.Delta))
			} else {
				c.output.append(&m.Reasoning, value(r.Delta))
			}
		default:
			t := c.output.tool(m, 0)
			if t != nil {
				if r.Type == "response.custom_tool_call_input.delta" {
					t.Function.Custom = true
				}
				c.output.append(&t.Function.Arguments, value(r.Delta))
			}
		}
	case "response.output_item.done":
		if r.Item != nil {
			c.output.responseSnapshot(key, *r.Item)
		}
	case "response.completed", "response.incomplete":
		if r.Response != nil {
			for i, m := range r.Response.Output {
				c.output.responseSnapshot(i, m)
				if c.output.truncated {
					break
				}
			}
			c.responseFinish(r.Response)
		}
	}
}

func (c *conversation) responseSnapshot(key int, m schemas.ResponsesMessage) {
	// Snapshot fields repeat the prefix already observed through deltas. Consume
	// that prefix across content blocks, then capture only any missing suffix.
	c.snapshotOffsets = map[*text]int{}
	c.responses(key, m)
	c.snapshotOffsets = nil
}
func finishReason(reason string) string {
	if reason == "tool_calls" {
		return "tool_call"
	}
	return strings.Clone(reason)
}
func (c *Capture) responseFinish(r *schemas.BifrostResponsesResponse) {
	reason := "stop"
	if r.IncompleteDetails != nil {
		reason = "length"
		if r.IncompleteDetails.Reason == "content_filter" {
			reason = "content_filter"
		}
	}
	if r.Status != nil && (*r.Status == "failed" || *r.Status == "cancelled") {
		reason = "error"
	}
	for i := range c.output.messages {
		m := &c.output.messages[i]
		m.FinishReason = reason
		if reason == "stop" && len(m.ToolCalls) > 0 {
			m.FinishReason = "tool_call"
		}
	}
}

// These parts follow the OpenTelemetry GenAI message schemas. Tool JSON stays
// raw when valid, avoiding an unbounded object expansion solely for telemetry.
type genAIMessage struct {
	Role         string           `json:"role"`
	Parts        []map[string]any `json:"parts"`
	FinishReason *string          `json:"finish_reason,omitempty"`
}

func jsonValue(v text) any {
	if json.Valid(v) {
		return json.RawMessage(v)
	}
	return string(v)
}

// encode projects the shared capture into a destination's own smaller limit.
// It always emits valid JSON and independently reports truncation.
func (c *conversation) encode(limit int) (string, string, bool) {
	result := make([]genAIMessage, 0, len(c.messages))
	left := limit
	truncated := c.truncated
	clip := func(v text) text {
		n := min(len(v), max(0, left))
		if n < len(v) {
			truncated = true
			for n > 0 && !utf8.RuneStart(v[n]) {
				n--
			}
		}
		left -= n
		return v[:n]
	}
	instructions := clip(c.instructions)
	for _, m := range c.messages {
		if left < 256 {
			truncated = true
			break
		}
		left -= 256
		out := genAIMessage{Role: m.Role, Parts: []map[string]any{}}
		if c.output {
			reason := m.FinishReason
			if reason == "" {
				reason = "unknown"
			}
			out.FinishReason = &reason
		}
		content, reasoning, summary, refusal, callID := clip(m.Content), clip(m.Reasoning), clip(m.Summary), clip(m.Refusal), clip(m.ToolCallID)
		for _, part := range []text{reasoning, summary} {
			if len(part) > 0 {
				out.Parts = append(out.Parts, map[string]any{"type": "reasoning", "content": string(part)})
			}
		}
		if m.Role == "tool" {
			out.Parts = append(out.Parts, map[string]any{"type": "tool_call_response", "id": string(callID), "response": jsonValue(content)})
		} else if len(content) > 0 {
			out.Parts = append(out.Parts, map[string]any{"type": "text", "content": string(content)})
		}
		if len(refusal) > 0 {
			out.Parts = append(out.Parts, map[string]any{"type": "refusal", "content": string(refusal)})
		}
		for _, t := range m.ToolCalls {
			if left < 256 {
				truncated = true
				break
			}
			left -= 256
			id, name, args := clip(t.ID), clip(t.Function.Name), clip(t.Function.Arguments)
			arguments := jsonValue(args)
			if t.Function.Custom {
				arguments = string(args)
			}
			out.Parts = append(out.Parts, map[string]any{"type": "tool_call", "id": string(id), "name": string(name), "arguments": arguments})
		}
		if c.combineOutput && len(result) > 0 {
			result[0].Parts = append(result[0].Parts, out.Parts...)
			if out.FinishReason != nil && *out.FinishReason != "stop" {
				result[0].FinishReason = out.FinishReason
			}
		} else {
			result = append(result, out)
		}
	}
	raw, _ := json.Marshal(result)
	system := ""
	if len(c.instructions) > 0 {
		encoded, _ := json.Marshal([]map[string]any{{"type": "text", "content": string(instructions)}})
		system = string(encoded)
	}
	return string(raw), system, truncated
}

func (c *conversation) clear() {
	clear(c.instructions)
	c.instructions = nil
	for _, m := range c.messages {
		clear(m.Content)
		clear(m.Reasoning)
		clear(m.Summary)
		clear(m.Refusal)
		clear(m.ToolCallID)
		for _, t := range m.ToolCalls {
			clear(t.ID)
			clear(t.Function.Name)
			clear(t.Function.Arguments)
		}
	}
	c.messages = nil
	c.keys = nil
}

// A request ID gives a consistent early sampling decision across destinations.
func sampleValue(id string) float64 {
	h := sha256ID(id)
	n, _ := strconv.ParseUint(h[:13], 16, 64)
	return float64(n) / float64(uint64(1)<<52)
}
