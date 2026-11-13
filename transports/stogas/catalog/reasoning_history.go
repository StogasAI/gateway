package catalog

import (
	"encoding/json"
	"strings"

	"github.com/bytedance/sonic"
	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// ReasoningFormat is the format of reasoning history, the reasoning of an earlier reply that a
// client sends back. Each kind of deployment returns one format and takes back only that format.
type ReasoningFormat uint8

const (
	// ClaudeReasoning is Claude's signed thinking and its redacted thinking.
	ClaudeReasoning ReasoningFormat = iota + 1
	// EncryptedReasoning is OpenAI's encrypted reasoning, which belongs to the ID of its item, and
	// which only the provider account that produced it can decrypt.
	EncryptedReasoning
	// PlainReasoning is reasoning text without a signature.
	PlainReasoning
)

// ReadsReasoning reports whether the deployment takes back reasoning history of the format. The
// gateway leaves out the history that the deployment does not take back, as Anthropic leaves out
// thinking that the current model cannot read, so that a conversation can move to another model or
// account. Of OpenAI's encrypted reasoning, it takes back only what its own account produced
// (BindEncryptedReasoning).
func (r *ResolvedRequest) ReadsReasoning(format ReasoningFormat) bool {
	if r == nil {
		return false
	}
	switch format {
	case ClaudeReasoning:
		return UsesClaudeWire(r.Provider, r.Deployment.ModelID)
	case EncryptedReasoning:
		// Only OpenAI's own models return it, and they take it back only on Responses.
		return r.runsOpenAIModel() && r.Deployment.ReasoningSupported && r.WireRoute() == RouteResponses
	case PlainReasoning:
		return r.Provider == ProviderChutes
	}
	return false
}

// encryptedReasoningPrefix starts OpenAI's encrypted reasoning as the gateway returns it: the
// prefix, the tag of the provider account that produced it, a colon and the provider's own content.
// Each account decrypts only its own: on November 11, 2026, OpenAI and Azure each refused the
// other's with invalid_encrypted_content, while every model of one OpenAI account took it.
const encryptedReasoningPrefix = "openai:"

// SetAccountTag names the provider account that the pair's credential reaches
// (billing.KeyConfigSnapshot.AccountTag), before the request's checks. Without one, the pair takes
// back no encrypted reasoning.
func (r *ResolvedRequest) SetAccountTag(tag string) {
	r.accountTag = tag
}

// RebindAccount names the account that serves the pair after its checks, when it can differ from
// the one that SetAccountTag named. For another account, the pair leaves out the encrypted
// reasoning that its checks kept: that carries the provider's own content, which no account claims.
func (r *ResolvedRequest) RebindAccount(tag string) {
	if r == nil || r.accountTag == tag {
		return
	}
	r.accountTag = tag
	if r.wire != nil {
		r.wire.accountTag = tag
	}
	r.KeepReadableReasoning()
}

// BindEncryptedReasoning returns encrypted reasoning that the deployment returned, bound to the
// account that produced it, so that a later request sends it only to that account
// (KeepReadableReasoning). Without an account, it returns the content as it is, which no
// deployment takes back.
func (r *ResolvedRequest) BindEncryptedReasoning(content string) string {
	if r == nil || r.accountTag == "" || content == "" || strings.HasPrefix(content, encryptedReasoningPrefix) || !r.ReadsReasoning(EncryptedReasoning) {
		return content
	}
	return encryptedReasoningPrefix + r.accountTag + ":" + content
}

// IntactEncryptedReasoning reports whether encrypted content that a client sent back keeps the
// form that BindEncryptedReasoning gave it, when it has that form's prefix.
func IntactEncryptedReasoning(content string) bool {
	_, _, bound := cutEncryptedReasoning(content)
	return bound || !strings.HasPrefix(content, encryptedReasoningPrefix)
}

// cutEncryptedReasoning returns the account tag and the provider's content of bound encrypted
// reasoning.
func cutEncryptedReasoning(content string) (account, provider string, ok bool) {
	rest, ok := strings.CutPrefix(content, encryptedReasoningPrefix)
	if !ok {
		return "", "", false
	}
	account, provider, ok = strings.Cut(rest, ":")
	return account, provider, ok && account != "" && provider != ""
}

// ownEncryptedReasoning returns the provider's content of encrypted reasoning that the pair's
// account produced, and false for any other: another account's, and content that the gateway did
// not bind.
func (r *ResolvedRequest) ownEncryptedReasoning(content *string) (string, bool) {
	if content == nil {
		return "", false
	}
	account, provider, ok := cutEncryptedReasoning(*content)
	if !ok || account != r.accountTag || !r.ReadsReasoning(EncryptedReasoning) {
		return "", false
	}
	return provider, true
}

// chatReasoningDetailFormat is the format of a Chat Completions reasoning detail. Claude's thinking
// is signed text and its redacted thinking is encrypted data without an ID. OpenAI's encrypted
// reasoning keeps the ID of its item or the account that BindEncryptedReasoning bound it to, so a
// client can drop the ID, which OpenAI takes it back without. Text without a signature is plain. A
// detail of another type has no format, and no deployment takes it back.
func chatReasoningDetailFormat(detail schemas.ChatReasoningDetails) ReasoningFormat {
	switch detail.Type {
	case schemas.BifrostReasoningDetailsTypeText:
		if detail.Signature != nil && *detail.Signature != "" {
			return ClaudeReasoning
		}
		return PlainReasoning
	case schemas.BifrostReasoningDetailsTypeEncrypted:
		if detail.ID != nil && *detail.ID != "" || detail.Data != nil && strings.HasPrefix(*detail.Data, encryptedReasoningPrefix) {
			return EncryptedReasoning
		}
		return ClaudeReasoning
	}
	return 0
}

// responsesReasoningFormat is the format of a Responses reasoning item. Its encrypted content holds
// a Claude block or OpenAI's encrypted reasoning, and an item without it holds plain reasoning
// text in its content. An item with neither has no format, and no deployment takes it back: a
// summary is what a client shows, not reasoning that a model continues from.
func responsesReasoningFormat(item *schemas.ResponsesMessage) ReasoningFormat {
	if reasoning := item.ResponsesReasoning; reasoning != nil && reasoning.EncryptedContent != nil && *reasoning.EncryptedContent != "" {
		if anthropicprovider.HoldsThinkingBlock(*reasoning.EncryptedContent) {
			return ClaudeReasoning
		}
		return EncryptedReasoning
	}
	if item.Content == nil || len(item.Content.ContentBlocks) == 0 {
		return 0
	}
	return PlainReasoning
}

// chatEncryptedReasoningHistory reports whether a message of a Chat Completions request carries
// OpenAI's encrypted reasoning, which only Responses take back.
func chatEncryptedReasoningHistory(raw json.RawMessage) bool {
	messages, err := rawjson.Array(raw)
	if err != nil {
		return false
	}
	for _, message := range messages {
		object, err := rawjson.Object(message)
		if err != nil || len(object["reasoning_details"]) == 0 || rawJSONNullOrEmptyArray(object["reasoning_details"]) {
			continue
		}
		var details []schemas.ChatReasoningDetails
		if err := sonic.Unmarshal(object["reasoning_details"], &details); err != nil {
			continue
		}
		for _, detail := range details {
			if chatReasoningDetailFormat(detail) == EncryptedReasoning {
				return true
			}
		}
	}
	return false
}

// KeepReadableReasoning leaves out the reasoning history that the deployment does not take back
// (ReadsReasoning), and an assistant message that held nothing else. The request's checks have
// refused history that no deployment takes back. Translate reads what remains.
func (r *ResolvedRequest) KeepReadableReasoning() {
	switch {
	case r == nil:
	case r.chat != nil:
		r.chat.Messages = r.readableChatMessages(r.chat.Messages)
	case r.responses != nil && r.responses.Input.OpenAIResponsesRequestInputArray != nil:
		r.responses.Input.OpenAIResponsesRequestInputArray = r.readableResponsesInput(r.responses.Input.OpenAIResponsesRequestInputArray)
	}
}

// readableResponsesInput is the input with only the reasoning items that the deployment takes
// back. Other requests of the same input share its items, so it never changes them.
func (r *ResolvedRequest) readableResponsesInput(input []schemas.ResponsesMessage) []schemas.ResponsesMessage {
	var kept []schemas.ResponsesMessage
	for index := range input {
		item, keep, changed := r.readableResponsesItem(input[index])
		if kept == nil {
			if !changed {
				continue
			}
			kept = append(make([]schemas.ResponsesMessage, 0, len(input)), input[:index]...)
		}
		if keep {
			kept = append(kept, item)
		}
	}
	if kept == nil {
		return input
	}
	return kept
}

// readableResponsesItem returns an input item as the deployment gets it, OpenAI's encrypted
// reasoning with the provider's own content, whether the deployment gets it at all, and whether
// either differs from the item.
func (r *ResolvedRequest) readableResponsesItem(item schemas.ResponsesMessage) (schemas.ResponsesMessage, bool, bool) {
	if item.Type == nil || *item.Type != schemas.ResponsesMessageTypeReasoning {
		return item, true, false
	}
	format := responsesReasoningFormat(&item)
	if format != EncryptedReasoning {
		if !r.ReadsReasoning(format) {
			return item, false, true
		}
		// Plain reasoning goes without a summary, which Chat Completions history has no place for.
		if format != PlainReasoning || item.ResponsesReasoning == nil || len(item.ResponsesReasoning.Summary) == 0 {
			return item, true, false
		}
		reasoning := *item.ResponsesReasoning
		reasoning.Summary = []schemas.ResponsesReasoningSummary{}
		item.ResponsesReasoning = &reasoning
		return item, true, true
	}
	content, ok := r.ownEncryptedReasoning(item.ResponsesReasoning.EncryptedContent)
	if !ok {
		return item, false, true
	}
	reasoning := *item.ResponsesReasoning
	reasoning.EncryptedContent = &content
	item.ResponsesReasoning = &reasoning
	return item, true, true
}

// readableChatMessages is the messages with only the reasoning history that the deployment takes
// back. An assistant message that held only reasoning that it leaves out goes too, since providers
// refuse an empty one. Other requests of the same body share the messages, so it never changes
// them.
func (r *ResolvedRequest) readableChatMessages(messages []openaiprovider.OpenAIMessage) []openaiprovider.OpenAIMessage {
	var kept []openaiprovider.OpenAIMessage
	for index, message := range messages {
		assistant, changed := r.readableAssistantReasoning(message.OpenAIChatAssistantMessage)
		if !changed {
			if kept != nil {
				kept = append(kept, message)
			}
			continue
		}
		if kept == nil {
			kept = append(make([]openaiprovider.OpenAIMessage, 0, len(messages)), messages[:index]...)
		}
		message.OpenAIChatAssistantMessage = assistant
		if !chatAssistantMessageEmpty(message) {
			kept = append(kept, message)
		}
	}
	if kept == nil {
		return messages
	}
	return kept
}

// readableAssistantReasoning is the assistant message with only the reasoning details that the
// deployment takes back, OpenAI's encrypted reasoning with the provider's own content, and whether
// it differs. The reasoning text goes with the details: it stays when the deployment takes every
// detail or, for a message without details, plain reasoning.
func (r *ResolvedRequest) readableAssistantReasoning(message *openaiprovider.OpenAIChatAssistantMessage) (*openaiprovider.OpenAIChatAssistantMessage, bool) {
	if message == nil || message.Reasoning == nil && message.ReasoningAlias == nil && len(message.ReasoningDetails) == 0 {
		return message, false
	}
	var details []schemas.ChatReasoningDetails
	unbound := false
	for _, detail := range message.ReasoningDetails {
		switch format := chatReasoningDetailFormat(detail); {
		case format == EncryptedReasoning:
			content, ok := r.ownEncryptedReasoning(detail.Data)
			if !ok {
				continue
			}
			detail.Data, unbound = &content, true
		case !r.ReadsReasoning(format):
			continue
		}
		detail.Index = len(details)
		details = append(details, detail)
	}
	every := len(details) == len(message.ReasoningDetails)
	textKept := every && (len(details) > 0 || r.ReadsReasoning(PlainReasoning))
	if !unbound && every && (textKept || message.Reasoning == nil && message.ReasoningAlias == nil) {
		return message, false
	}
	readable := *message
	readable.ReasoningDetails = details
	if !textKept {
		readable.Reasoning, readable.ReasoningAlias = nil, nil
	}
	return &readable, true
}

// chatAssistantMessageEmpty reports whether an assistant message holds nothing that a provider
// reads: no text, refusal, annotations, tool calls or reasoning.
func chatAssistantMessageEmpty(message openaiprovider.OpenAIMessage) bool {
	if content := message.Content; content != nil {
		if content.ContentStr != nil && strings.TrimSpace(*content.ContentStr) != "" {
			return false
		}
		for _, block := range content.ContentBlocks {
			if block.Type != schemas.ChatContentBlockTypeText || block.Text != nil && strings.TrimSpace(*block.Text) != "" {
				return false
			}
		}
	}
	assistant := message.OpenAIChatAssistantMessage
	return assistant == nil || assistant.Refusal == nil && assistant.Reasoning == nil && assistant.ReasoningAlias == nil &&
		len(assistant.ReasoningDetails) == 0 && len(assistant.Annotations) == 0 && len(assistant.ToolCalls) == 0
}
