package anthropic

// Claude binds each thinking block to everything before it, the earlier blocks of its own
// reply included, and refuses a block whose earlier content changed or moved ("The block is
// bound to a different conversation"). History in OpenAI's shapes cannot keep a block's place
// among the other blocks of a reply: Chat Completions returns reasoning apart from the text and
// tool calls, and a Responses client or a proxy can leave out or rewrite an item, such as a
// hosted tool call, before a later reasoning item. Anthropic accepts history that leaves out
// the newest thinking blocks of a reply, so a Chat reply returns in reasoning_details, and a
// request with OpenAI's reasoning items (SetOpenAIReasoning) sends, only the thinking that
// starts each reply. Later thinking, such as a progress update before a tool call, stays
// readable in a Chat reply's reasoning text and in Responses summaries.

func isAnthropicThinkingBlock(blockType AnthropicContentBlockType) bool {
	return blockType == AnthropicContentBlockTypeThinking || blockType == AnthropicContentBlockTypeRedactedThinking
}

// leaveOutLaterThinking leaves out each thinking and redacted_thinking block that follows
// another block of its assistant turn, and an assistant message that holds nothing else.
// Anthropic reads consecutive assistant messages as one turn.
func leaveOutLaterThinking(messages []AnthropicMessage) []AnthropicMessage {
	kept := messages[:0]
	answered := false
	for _, message := range messages {
		switch {
		case message.Role != AnthropicMessageRoleAssistant:
			answered = false
		case message.Content.ContentStr != nil:
			answered = answered || *message.Content.ContentStr != ""
		default:
			blocks := message.Content.ContentBlocks
			message.Content.ContentBlocks, answered = withoutLaterThinking(blocks, answered)
			if len(message.Content.ContentBlocks) == 0 && len(blocks) > 0 {
				continue
			}
		}
		kept = append(kept, message)
	}
	return kept
}

// withoutLaterThinking returns blocks without the thinking that follows another block, or
// any thinking when the turn has already answered, and whether the turn has answered after
// them. It copies blocks only when it leaves one out.
func withoutLaterThinking(blocks []AnthropicContentBlock, answered bool) ([]AnthropicContentBlock, bool) {
	var kept []AnthropicContentBlock
	for i, block := range blocks {
		thinking := isAnthropicThinkingBlock(block.Type)
		if thinking && answered {
			if kept == nil {
				kept = append(make([]AnthropicContentBlock, 0, len(blocks)-1), blocks[:i]...)
			}
			continue
		}
		answered = answered || !thinking
		if kept != nil {
			kept = append(kept, block)
		}
	}
	if kept == nil {
		return blocks, answered
	}
	return kept, answered
}
