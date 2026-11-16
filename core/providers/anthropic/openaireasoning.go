package anthropic

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// A client of OpenAI's Responses keeps a reasoning item's id, summary, content and
// encrypted_content, and sends the item back in a later request. Claude's thinking and
// redacted_thinking blocks reach such a client as OpenAI gives reasoning: one item per
// block, the thinking text as its summary, and the block itself in encrypted_content.
// Anthropic rejects a block whose text or signature changed, and a client may shorten or
// drop a summary, so the request rebuilds each block from encrypted_content alone.

// encryptedThinkingPrefix starts encrypted_content that holds a Claude block. OpenAI's
// encrypted reasoning is URL-safe base64, which has no colon.
const encryptedThinkingPrefix = "claude:"

// thinkingBlockState is the part of a thinking or redacted_thinking block that
// Anthropic checks when the block comes back.
type thinkingBlockState struct {
	Type      AnthropicContentBlockType `json:"type"`
	Thinking  *string                   `json:"thinking,omitempty"`
	Signature *string                   `json:"signature,omitempty"`
	Data      *string                   `json:"data,omitempty"`
}

// EncodeThinkingBlock returns the encrypted_content that holds block, and false for a
// block that Anthropic would not take back: thinking without a signature, or
// redacted_thinking without data.
func EncodeThinkingBlock(block AnthropicContentBlock) (string, bool) {
	state := thinkingBlockState{Type: block.Type}
	switch block.Type {
	case AnthropicContentBlockTypeThinking:
		if block.Signature == nil || *block.Signature == "" {
			return "", false
		}
		thinking := ""
		if block.Thinking != nil {
			thinking = *block.Thinking
		}
		state.Thinking, state.Signature = &thinking, block.Signature
	case AnthropicContentBlockTypeRedactedThinking:
		if block.Data == nil || *block.Data == "" {
			return "", false
		}
		state.Data = block.Data
	default:
		return "", false
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return "", false
	}
	return encryptedThinkingPrefix + base64.RawURLEncoding.EncodeToString(encoded), true
}

// HoldsThinkingBlock reports whether a reasoning item's encrypted_content holds a
// Claude block rather than another provider's reasoning.
func HoldsThinkingBlock(encryptedContent string) bool {
	return strings.HasPrefix(encryptedContent, encryptedThinkingPrefix)
}

// DecodeThinkingBlock returns the Claude block that encrypted_content holds, and false
// when it holds none or is malformed.
func DecodeThinkingBlock(encryptedContent string) (AnthropicContentBlock, bool) {
	payload, ok := strings.CutPrefix(encryptedContent, encryptedThinkingPrefix)
	if !ok {
		return AnthropicContentBlock{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return AnthropicContentBlock{}, false
	}
	var state thinkingBlockState
	if err := json.Unmarshal(raw, &state); err != nil {
		return AnthropicContentBlock{}, false
	}
	switch {
	case state.Type == AnthropicContentBlockTypeThinking && state.Thinking != nil &&
		state.Signature != nil && *state.Signature != "" && state.Data == nil:
	case state.Type == AnthropicContentBlockTypeRedactedThinking && state.Data != nil && *state.Data != "" &&
		state.Thinking == nil && state.Signature == nil:
	default:
		return AnthropicContentBlock{}, false
	}
	return AnthropicContentBlock{Type: state.Type, Thinking: state.Thinking, Signature: state.Signature, Data: state.Data}, true
}

type openAIReasoningKeyType struct{}

var openAIReasoningKey = openAIReasoningKeyType{}

// SetOpenAIReasoning makes the Responses reply to this request carry each thinking and
// redacted_thinking block as its own reasoning item: the thinking text as the summary
// and the block in encrypted_content. Without it, the reply keeps core's shape, with
// thinking text and signatures in reasoning_text blocks, which the conversion back to
// Anthropic's format reads.
func SetOpenAIReasoning(ctx *schemas.BifrostContext) {
	if ctx != nil {
		ctx.SetValue(openAIReasoningKey, true)
	}
}

// usesOpenAIReasoning reports whether SetOpenAIReasoning applies to the request.
func usesOpenAIReasoning(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if bc, ok := ctx.(*schemas.BifrostContext); ok && bc == nil {
		return false
	}
	set, _ := ctx.Value(openAIReasoningKey).(bool)
	return set
}

// openAIReasoningOf returns the reasoning of one block's item.
func openAIReasoningOf(block AnthropicContentBlock) *schemas.ResponsesReasoning {
	reasoning := &schemas.ResponsesReasoning{Summary: []schemas.ResponsesReasoningSummary{}}
	if block.Thinking != nil && *block.Thinking != "" {
		reasoning.Summary = append(reasoning.Summary, schemas.ResponsesReasoningSummary{
			Type: schemas.ResponsesReasoningContentBlockTypeSummaryText,
			Text: *block.Thinking,
		})
	}
	if encoded, ok := EncodeThinkingBlock(block); ok {
		reasoning.EncryptedContent = &encoded
	}
	return reasoning
}

// openAIReasoningItems gives each thinking and redacted_thinking block of a reply its
// own reasoning item. It reads the conversion that keeps thinking where the reply has it: a run of
// thinking blocks becomes one item with a reasoning_text block for each, and a
// redacted_thinking block an item with its data as encrypted content.
func openAIReasoningItems(converted []schemas.ResponsesMessage) []schemas.ResponsesMessage {
	items := make([]schemas.ResponsesMessage, 0, len(converted))
	add := func(block AnthropicContentBlock) {
		items = append(items, schemas.ResponsesMessage{
			ID:                 schemas.Ptr("rs_" + schemas.GetRandomString(50)),
			Type:               schemas.Ptr(schemas.ResponsesMessageTypeReasoning),
			ResponsesReasoning: openAIReasoningOf(block),
		})
	}
	for _, item := range converted {
		if item.Type == nil || *item.Type != schemas.ResponsesMessageTypeReasoning {
			items = append(items, item)
			continue
		}
		if item.Content != nil {
			for _, block := range item.Content.ContentBlocks {
				if block.Type == schemas.ResponsesOutputMessageContentTypeReasoning && block.Text != nil {
					add(AnthropicContentBlock{Type: AnthropicContentBlockTypeThinking, Thinking: block.Text, Signature: block.Signature})
				}
			}
		}
		if item.ResponsesReasoning != nil && item.ResponsesReasoning.EncryptedContent != nil {
			add(AnthropicContentBlock{Type: AnthropicContentBlockTypeRedactedThinking, Data: item.ResponsesReasoning.EncryptedContent})
		}
	}
	return items
}

// openAIReasoningAdded opens the reasoning item of a thinking or redacted_thinking
// block. A redacted block arrives whole, so its item is complete when content_block_stop
// sends it.
func (state *AnthropicResponsesStreamState) openAIReasoningAdded(block *AnthropicContentBlock, contentIndex *int, outputIndex, sequenceNumber int) []*schemas.BifrostResponsesStreamResponse {
	itemID := fmt.Sprintf("reasoning_%d", outputIndex)
	if state.MessageID != nil {
		itemID = fmt.Sprintf("msg_%s_reasoning_%d", *state.MessageID, outputIndex)
	}
	state.ItemIDs[outputIndex] = itemID
	// OpenAI's reasoning items have no role, and a client that sends one back as it came would
	// send a role that the Responses API refuses on a reasoning item.
	added := &schemas.ResponsesMessage{
		ID:                 &itemID,
		Type:               schemas.Ptr(schemas.ResponsesMessageTypeReasoning),
		Status:             schemas.Ptr("in_progress"),
		ResponsesReasoning: &schemas.ResponsesReasoning{Summary: []schemas.ResponsesReasoningSummary{}},
	}
	stored := *added
	responses := []*schemas.BifrostResponsesStreamResponse{{
		Type:           schemas.ResponsesStreamResponseTypeOutputItemAdded,
		SequenceNumber: sequenceNumber,
		OutputIndex:    schemas.Ptr(outputIndex),
		ContentIndex:   contentIndex,
		Item:           added,
	}}
	if block.Type == AnthropicContentBlockTypeRedactedThinking {
		stored.ResponsesReasoning = openAIReasoningOf(*block)
		state.OutputItems[outputIndex] = &stored
		return responses
	}
	state.OutputItems[outputIndex] = &stored
	if contentIndex != nil {
		state.ReasoningContentIndices[*contentIndex] = true
	}
	if block.Signature != nil && *block.Signature != "" {
		state.ReasoningSignatures[outputIndex] = *block.Signature
	}
	if block.Thinking != nil && *block.Thinking != "" {
		responses = append(responses, state.openAIReasoningText(*block.Thinking, outputIndex, sequenceNumber+len(responses))...)
	}
	return responses
}

// openAIReasoningText streams thinking text as its item's summary, and opens the
// summary part with the first text. A block with display "omitted" has none.
func (state *AnthropicResponsesStreamState) openAIReasoningText(text string, outputIndex, sequenceNumber int) []*schemas.BifrostResponsesStreamResponse {
	itemID := state.ItemIDs[outputIndex]
	var responses []*schemas.BifrostResponsesStreamResponse
	if state.ReasoningTextBuffers == nil {
		state.ReasoningTextBuffers = make(map[int]*strings.Builder)
	}
	buffer := state.ReasoningTextBuffers[outputIndex]
	if buffer == nil {
		buffer = &strings.Builder{}
		state.ReasoningTextBuffers[outputIndex] = buffer
		responses = append(responses, &schemas.BifrostResponsesStreamResponse{
			Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded,
			SequenceNumber: sequenceNumber,
			OutputIndex:    schemas.Ptr(outputIndex),
			ItemID:         schemas.Ptr(itemID),
			SummaryIndex:   schemas.Ptr(anthropicReasoningSummaryIndex),
			Part: &schemas.ResponsesMessageContentBlock{
				Type: schemas.ResponsesOutputMessageContentTypeSummaryText,
				Text: schemas.Ptr(""),
			},
		})
	}
	buffer.WriteString(text)
	return append(responses, &schemas.BifrostResponsesStreamResponse{
		Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		SequenceNumber: sequenceNumber + len(responses),
		OutputIndex:    schemas.Ptr(outputIndex),
		ItemID:         schemas.Ptr(itemID),
		SummaryIndex:   schemas.Ptr(anthropicReasoningSummaryIndex),
		Delta:          schemas.Ptr(text),
	})
}

// openAIReasoningDone closes a thinking block's summary part and completes its stored
// item, which content_block_stop then sends.
func (state *AnthropicResponsesStreamState) openAIReasoningDone(outputIndex, sequenceNumber int) []*schemas.BifrostResponsesStreamResponse {
	itemID := state.ItemIDs[outputIndex]
	block := AnthropicContentBlock{Type: AnthropicContentBlockTypeThinking, Thinking: schemas.Ptr("")}
	var responses []*schemas.BifrostResponsesStreamResponse
	if buffer := state.ReasoningTextBuffers[outputIndex]; buffer != nil {
		text := buffer.String()
		delete(state.ReasoningTextBuffers, outputIndex)
		block.Thinking = &text
		responses = append(responses,
			&schemas.BifrostResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone,
				SequenceNumber: sequenceNumber,
				OutputIndex:    schemas.Ptr(outputIndex),
				ItemID:         schemas.Ptr(itemID),
				SummaryIndex:   schemas.Ptr(anthropicReasoningSummaryIndex),
				Text:           schemas.Ptr(text),
			},
			&schemas.BifrostResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryPartDone,
				SequenceNumber: sequenceNumber + 1,
				OutputIndex:    schemas.Ptr(outputIndex),
				ItemID:         schemas.Ptr(itemID),
				SummaryIndex:   schemas.Ptr(anthropicReasoningSummaryIndex),
				Part: &schemas.ResponsesMessageContentBlock{
					Type: schemas.ResponsesOutputMessageContentTypeSummaryText,
					Text: schemas.Ptr(text),
				},
			},
		)
	}
	if signature, ok := state.ReasoningSignatures[outputIndex]; ok {
		block.Signature = &signature
		delete(state.ReasoningSignatures, outputIndex)
	}
	if stored := state.OutputItems[outputIndex]; stored != nil {
		stored.ResponsesReasoning = openAIReasoningOf(block)
	}
	return responses
}
