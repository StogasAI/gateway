package catalog

import (
	"bytes"
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
	// GeminiReasoning is Gemini's thought signatures, each of a function call or of the text of a
	// reply, which only the provider account that produced them takes back (BindGeminiSignature).
	GeminiReasoning
)

// ReadsReasoning reports whether the deployment takes back reasoning history of the format. The
// gateway leaves out the history that the deployment does not take back, as Anthropic leaves out
// thinking that the current model cannot read, so that a conversation can move to another model or
// account. Of OpenAI's encrypted reasoning and Gemini's signatures, it takes back only what its own
// account produced (BindEncryptedReasoning, BindGeminiSignature).
func (r *ResolvedRequest) ReadsReasoning(format ReasoningFormat) bool {
	if r == nil {
		return false
	}
	switch format {
	case ClaudeReasoning:
		return UsesClaudeWire(r.Provider, r.Deployment.ModelID)
	case EncryptedReasoning:
		// Only OpenAI's own models return it, and they take it back only on Responses.
		return r.RunsOpenAIModel() && r.Deployment.ReasoningSupported && r.WireRoute() == RouteResponses
	case GeminiReasoning:
		// Every Gemini model takes the signatures of another and drops the thoughts that it cannot
		// read, as Flash-Lite models do with those of other models
		// (testdata/provider/google-cloud/generate-content-thought-signatures.json).
		return r.RunsGeminiModel()
	case PlainReasoning:
		// The other models return reasoning as text, and Azure's and Chutes' take it back after an
		// answer and beside a tool call (testdata/provider/azure/open-model-reasoning-history.json,
		// testdata/provider/chutes/reasoning-history.json). Models that think between tool calls,
		// such as DeepSeek's, read it, and the others ignore it
		// (testdata/provider/azure/open-model-reasoning-tool-loop.json). Azure's Mistral models refuse
		// it in an assistant message under either name
		// (testdata/provider/azure/other-model-formats-request-fields.json) and return none to take
		// back. Gemini continues from its signatures, and core sends it no reasoning text.
		return !UsesClaudeWire(r.Provider, r.Deployment.ModelID) && !r.RunsOpenAIModel() && !r.RunsGeminiModel() &&
			!(r.Provider == schemas.Azure && r.Deployment.Upstream.ModelFormat == "Mistral AI")
	}
	return false
}

// encryptedReasoningPrefix starts OpenAI's encrypted reasoning as the gateway returns it: the
// prefix, the tag of the provider account that produced it, a colon and the provider's own content.
// Each account decrypts only its own: on November 11, 2026, OpenAI and Azure each refused the
// other's with invalid_encrypted_content, while every model of one OpenAI account took it.
const encryptedReasoningPrefix = "openai:"

// geminiSignaturePrefix starts Gemini's thought signatures in the same form. Google states nothing
// about a signature that another project produced, so each goes back only to its own account, and
// a model on another one continues without it.
const geminiSignaturePrefix = "gemini:"

// boundReasoningPrefix is the prefix of the reasoning of a format that the gateway binds.
func boundReasoningPrefix(format ReasoningFormat) string {
	switch format {
	case EncryptedReasoning:
		return encryptedReasoningPrefix
	case GeminiReasoning:
		return geminiSignaturePrefix
	}
	return ""
}

// boundReasoning reports whether content has the prefix of reasoning that the gateway binds.
func boundReasoning(content string) bool {
	return strings.HasPrefix(content, encryptedReasoningPrefix) || strings.HasPrefix(content, geminiSignaturePrefix)
}

// SetAccountTag names the provider account that the pair's credential reaches
// (billing.KeyConfigSnapshot.AccountTag), before the request's checks. Without one, the pair takes
// back no encrypted reasoning.
func (r *ResolvedRequest) SetAccountTag(tag string) {
	r.accountTag = tag
}

// RebindAccount names the account that serves the pair after its checks, when it can differ from
// the one that SetAccountTag named, and reports whether it did. For another account, the pair
// leaves out the encrypted reasoning that its checks kept: that carries the provider's own content,
// which no account claims.
func (r *ResolvedRequest) RebindAccount(tag string) bool {
	if r == nil || r.accountTag == tag {
		return false
	}
	r.accountTag = tag
	if r.wire != nil {
		r.wire.accountTag = tag
	}
	r.KeepReadableHistory()
	return true
}

// BindEncryptedReasoning returns encrypted reasoning that the deployment returned, bound to the
// account that produced it, so that a later request sends it only to that account
// (KeepReadableHistory). Without an account, it returns the content as it is, which no
// deployment takes back.
func (r *ResolvedRequest) BindEncryptedReasoning(content string) string {
	if r == nil || r.accountTag == "" || content == "" || strings.HasPrefix(content, encryptedReasoningPrefix) || !r.ReadsReasoning(EncryptedReasoning) {
		return content
	}
	return encryptedReasoningPrefix + r.accountTag + ":" + content
}

// BindGeminiSignature returns a thought signature that the deployment returned, bound to the account
// that produced it (geminiSignaturePrefix), and false without an account, when no deployment would
// take it back.
func (r *ResolvedRequest) BindGeminiSignature(signature string) (string, bool) {
	if r == nil || r.accountTag == "" || signature == "" || !r.ReadsReasoning(GeminiReasoning) {
		return "", false
	}
	return geminiSignaturePrefix + r.accountTag + ":" + signature, true
}

// IntactEncryptedReasoning reports whether encrypted content that a client sent back keeps the
// form that BindEncryptedReasoning or BindGeminiSignature gave it, when it has that form's prefix.
func IntactEncryptedReasoning(content string) bool {
	for _, format := range []ReasoningFormat{EncryptedReasoning, GeminiReasoning} {
		if prefix := boundReasoningPrefix(format); strings.HasPrefix(content, prefix) {
			_, _, bound := cutBoundReasoning(content, prefix)
			return bound
		}
	}
	return true
}

// cutBoundReasoning returns the account tag and the provider's content of reasoning that the
// gateway bound with prefix.
func cutBoundReasoning(content, prefix string) (account, provider string, ok bool) {
	rest, ok := strings.CutPrefix(content, prefix)
	if !ok {
		return "", "", false
	}
	account, provider, ok = strings.Cut(rest, ":")
	return account, provider, ok && account != "" && provider != ""
}

// ownBoundReasoning returns the provider's content of reasoning of a bound format that the pair's
// account produced, and false for any other: another account's, and content that the gateway did
// not bind.
func (r *ResolvedRequest) ownBoundReasoning(content *string, format ReasoningFormat) (string, bool) {
	if content == nil {
		return "", false
	}
	account, provider, ok := cutBoundReasoning(*content, boundReasoningPrefix(format))
	if !ok || account != r.accountTag || !r.ReadsReasoning(format) {
		return "", false
	}
	return provider, true
}

// OpenRouter names the provider whose reasoning an entry holds in its format: Claude's is
// openRouterClaudeFormat, and an absent format or "unknown" names none. The gateway's own replies
// carry no format, and its markers, the account binding of OpenAI's encrypted reasoning and of
// Gemini's signatures and the Claude block in encrypted content, decide before any format.
const openRouterClaudeFormat = "anthropic-claude-v1"

// otherProviderFormat reports whether an OpenRouter format names a provider other than Claude, such
// as OpenAI, xAI or Gemini, whose signed or encrypted reasoning no deployment takes back unbound.
func otherProviderFormat(format string) bool {
	return format != "" && format != "unknown" && format != openRouterClaudeFormat
}

// chatReasoningDetailFormat is the format of a Chat Completions reasoning detail. Claude's thinking
// is signed text and its redacted thinking is encrypted data without an ID. OpenAI's encrypted
// reasoning keeps the ID of its item or the account that BindEncryptedReasoning bound it to, so a
// client can drop the ID, which OpenAI takes it back without. Gemini's signatures keep the account
// that BindGeminiSignature bound them to. OpenRouter's format overrides the
// shape: its Claude data may carry an ID, and another provider's data may lack one. Text without a
// signature is plain. Signed or encrypted reasoning of another provider's format, and a detail of
// another type, have no format, and no deployment takes them back: redaction leaves signed and
// encrypted reasoning as the client sent it, so it may reach only the provider that checks it.
func chatReasoningDetailFormat(detail schemas.ChatReasoningDetails) ReasoningFormat {
	format := ""
	if detail.Format != nil {
		format = *detail.Format
	}
	switch detail.Type {
	case schemas.BifrostReasoningDetailsTypeText:
		switch {
		case detail.Signature == nil || *detail.Signature == "":
			return PlainReasoning
		case otherProviderFormat(format):
			return 0
		}
		return ClaudeReasoning
	case schemas.BifrostReasoningDetailsTypeEncrypted:
		switch {
		case detail.Data != nil && strings.HasPrefix(*detail.Data, geminiSignaturePrefix):
			return GeminiReasoning
		case detail.Data != nil && strings.HasPrefix(*detail.Data, encryptedReasoningPrefix):
			return EncryptedReasoning
		case format == openRouterClaudeFormat:
			return ClaudeReasoning
		case otherProviderFormat(format):
			return 0
		case detail.ID != nil && *detail.ID != "":
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
		switch content := *reasoning.EncryptedContent; {
		case strings.HasPrefix(content, geminiSignaturePrefix):
			return GeminiReasoning
		case anthropicprovider.HoldsThinkingBlock(content):
			return ClaudeReasoning
		}
		return EncryptedReasoning
	}
	if item.Content == nil || len(item.Content.ContentBlocks) == 0 {
		return 0
	}
	return PlainReasoning
}

// claudeBlocksFromOpenRouter gives each reasoning item that holds a Claude block as OpenRouter
// returns it the form that the gateway's own replies give one: the whole block in encrypted content,
// so that only Claude deployments take it back. OpenRouter returns Claude's thinking as the text of
// one content block with the block's signature beside it, and its redacted thinking as encrypted
// content with Claude's format. Encrypted content that the gateway bound or that holds a Claude block
// already stays as it is. An item signed in another provider's format loses its content, so that
// no deployment takes it back: redaction leaves a signed item as the client sent it. The request's
// checks allowed at most one content block beside a signature.
func claudeBlocksFromOpenRouter(raw json.RawMessage, input []schemas.ResponsesMessage) {
	items, err := rawjson.Array(raw)
	if err != nil || len(items) != len(input) {
		return
	}
	for index := range input {
		item := &input[index]
		if item.Type == nil || *item.Type != schemas.ResponsesMessageTypeReasoning {
			continue
		}
		fields, err := rawjson.Object(items[index])
		if err != nil {
			continue
		}
		var format, signature string
		_ = sonic.Unmarshal(fields["format"], &format)
		_ = sonic.Unmarshal(fields["signature"], &signature)
		block := anthropicprovider.AnthropicContentBlock{Type: anthropicprovider.AnthropicContentBlockTypeThinking, Signature: &signature}
		if reasoning := item.ResponsesReasoning; reasoning != nil && reasoning.EncryptedContent != nil && *reasoning.EncryptedContent != "" {
			data := *reasoning.EncryptedContent
			if format != openRouterClaudeFormat || anthropicprovider.HoldsThinkingBlock(data) || boundReasoning(data) {
				continue
			}
			block = anthropicprovider.AnthropicContentBlock{Type: anthropicprovider.AnthropicContentBlockTypeRedactedThinking, Data: &data}
		} else {
			if signature == "" {
				continue
			}
			if otherProviderFormat(format) {
				item.Content = nil
				continue
			}
			thinking := ""
			if item.Content != nil && len(item.Content.ContentBlocks) > 0 && item.Content.ContentBlocks[0].Text != nil {
				thinking = *item.Content.ContentBlocks[0].Text
			}
			block.Thinking = &thinking
		}
		encoded, ok := anthropicprovider.EncodeThinkingBlock(block)
		if !ok {
			continue
		}
		item.Content = nil
		item.ResponsesReasoning = &schemas.ResponsesReasoning{Summary: []schemas.ResponsesReasoningSummary{}, EncryptedContent: &encoded}
	}
}

// joinStreamedReasoningDetails joins the parts of each reasoning detail that a client sends back as
// a stream gave them. A Chat stream sends a detail's text in parts and then its signature, each with
// the detail's index, and some clients keep every part as a detail of its own. Joined, the text is
// whole beside its signature again, so Claude takes it back and no other model reads it as plain
// reasoning. Only consecutive text parts with the same explicit index, format and ID join, and
// only up to a part with a signature, which a stream sends last.
func joinStreamedReasoningDetails(rawData map[string]json.RawMessage) error {
	raw := rawData["messages"]
	// JSON can spell the key only plainly or with \u escapes.
	if !bytes.Contains(raw, []byte("reasoning_details")) && !bytes.Contains(raw, []byte(`\u`)) {
		return nil
	}
	messages, err := rawjson.Array(raw)
	if err != nil {
		return nil
	}
	changed := false
	for index, messageRaw := range messages {
		message, err := rawjson.Object(messageRaw)
		if err != nil {
			continue
		}
		details, err := rawjson.Array(message["reasoning_details"])
		if err != nil || len(details) < 2 {
			continue
		}
		joined, ok := joinStreamedParts(details)
		if !ok {
			continue
		}
		message["reasoning_details"] = joinRawArray(joined)
		if messages[index], err = sonic.Marshal(message); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		rawData["messages"] = joinRawArray(messages)
	}
	return nil
}

// streamedPart is a reasoning.text detail with an explicit index, the form in which a Chat stream
// sends each part of one.
type streamedPart struct {
	Type      schemas.BifrostReasoningDetailsType `json:"type"`
	Index     int                                 `json:"index"`
	Text      *string                             `json:"text,omitempty"`
	Signature *string                             `json:"signature,omitempty"`
	Format    *string                             `json:"format,omitempty"`
	ID        *string                             `json:"id,omitempty"`
}

// parseStreamedPart reads a detail as a streamed part. A detail with another key or value type is
// none, and the request's checks name what is wrong with it.
func parseStreamedPart(raw json.RawMessage) (streamedPart, bool) {
	fields, err := rawjson.Object(raw)
	if err != nil || rawStringValue(fields["type"]) != string(schemas.BifrostReasoningDetailsTypeText) {
		return streamedPart{}, false
	}
	if _, ok := fields["index"]; !ok {
		return streamedPart{}, false
	}
	for key := range fields {
		switch key {
		case "type", "index", "text", "signature", "format", "id":
		default:
			return streamedPart{}, false
		}
	}
	var part streamedPart
	if sonic.Unmarshal(raw, &part) != nil {
		return streamedPart{}, false
	}
	return part, true
}

// joinStreamedParts joins each run of parts of one detail, and reports whether any joined.
func joinStreamedParts(details []json.RawMessage) ([]json.RawMessage, bool) {
	joined := make([]json.RawMessage, 0, len(details))
	var open streamedPart
	opened, changed := false, false
	for _, raw := range details {
		part, ok := parseStreamedPart(raw)
		if ok && opened && part.Index == open.Index && equalStrings(part.Format, open.Format) && equalStrings(part.ID, open.ID) &&
			(open.Signature == nil || *open.Signature == "") {
			if part.Text != nil {
				text := *part.Text
				if open.Text != nil {
					text = *open.Text + text
				}
				open.Text = &text
			}
			if part.Signature != nil {
				open.Signature = part.Signature
			}
			encoded, err := sonic.Marshal(open)
			if err != nil {
				return nil, false
			}
			joined[len(joined)-1] = encoded
			changed = true
			continue
		}
		joined = append(joined, raw)
		open, opened = part, ok
	}
	return joined, changed
}

func equalStrings(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// chatEncryptedReasoningHistory reports whether a message of a Chat Completions request carries
// OpenAI's encrypted reasoning bound to an account, which only Responses take back. Unbound content
// goes to no deployment, so it leaves the request on the interface that the client called.
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
			if chatReasoningDetailFormat(detail) != EncryptedReasoning || detail.Data == nil {
				continue
			}
			if _, _, bound := cutBoundReasoning(*detail.Data, encryptedReasoningPrefix); bound {
				return true
			}
		}
	}
	return false
}

// KeepReadableHistory leaves out the history that the deployment does not take back: reasoning
// (ReadsReasoning), an assistant message that held nothing else, the calls of hosted tools that it
// does not read (readsHostedCall), and an assistant message without text, which only OpenAI's
// models take back on Responses (emptyAssistantMessage). The request's checks have refused history
// that no deployment takes back. Translate reads what remains.
func (r *ResolvedRequest) KeepReadableHistory() {
	switch {
	case r == nil:
	case r.chat != nil:
		r.chat.Messages = r.readableChatMessages(r.chat.Messages)
	case r.responses != nil && r.responses.Input.OpenAIResponsesRequestInputArray != nil:
		r.responses.Input.OpenAIResponsesRequestInputArray = r.readableResponsesInput(r.responses.Input.OpenAIResponsesRequestInputArray)
	}
}

// readableResponsesInput is the input with only the reasoning and hosted tool items that the
// deployment takes back. Other requests of the same input share its items, so it never changes
// them.
func (r *ResolvedRequest) readableResponsesInput(input []schemas.ResponsesMessage) []schemas.ResponsesMessage {
	var kept []schemas.ResponsesMessage
	shells := hostedShellCalls(input)
	for index := range input {
		item, keep, changed := r.readableResponsesItem(input[index], shells)
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
// either differs from the item. A reasoning item goes without its summary, which no provider reads
// back: OpenAI and Azure bill encrypted reasoning the same with its summary as returned, empty or
// changed (testdata/provider/openai/encrypted-reasoning-summary.json), Claude's block comes back
// whole from encrypted content, and Chat Completions history has no place for one. Redaction keeps
// the summary of an item with encrypted content as the client sent it, so it must not reach a
// provider.
func (r *ResolvedRequest) readableResponsesItem(item schemas.ResponsesMessage, shells map[string]bool) (schemas.ResponsesMessage, bool, bool) {
	if tool, hosted := hostedCallTool(&item, shells); hosted {
		keep := r.readsHostedCall(&item, tool)
		return item, keep, !keep
	}
	if emptyAssistantMessage(&item) && (!r.RunsOpenAIModel() || r.WireRoute() != RouteResponses) {
		return item, false, true
	}
	if item.Type == nil || *item.Type != schemas.ResponsesMessageTypeReasoning {
		return item, true, false
	}
	format := responsesReasoningFormat(&item)
	bound := format == EncryptedReasoning || format == GeminiReasoning
	switch {
	case bound:
	case !r.ReadsReasoning(format):
		return item, false, true
	case item.ResponsesReasoning == nil || len(item.ResponsesReasoning.Summary) == 0:
		return item, true, false
	}
	reasoning := *item.ResponsesReasoning
	reasoning.Summary = []schemas.ResponsesReasoningSummary{}
	if bound {
		content, ok := r.ownBoundReasoning(reasoning.EncryptedContent, format)
		if !ok {
			return item, false, true
		}
		reasoning.EncryptedContent = &content
	}
	item.ResponsesReasoning = &reasoning
	return item, true, true
}

// emptyAssistantMessage reports whether an item is an assistant message whose text and refusals
// hold no visible character. OpenAI's reply holds one after an image, and OpenAI takes it back
// (capture openai/image-generation), where a reasoning item can need it as the item that follows.
// Claude refuses a text block without a visible character, and the message holds nothing for any
// model to read.
func emptyAssistantMessage(item *schemas.ResponsesMessage) bool {
	if item.Role == nil || *item.Role != schemas.ResponsesInputMessageRoleAssistant || item.Content == nil ||
		item.Type != nil && *item.Type != schemas.ResponsesMessageTypeMessage {
		return false
	}
	if text := item.Content.ContentStr; text != nil {
		return strings.TrimSpace(*text) == ""
	}
	for _, block := range item.Content.ContentBlocks {
		if block.Text != nil && strings.TrimSpace(*block.Text) != "" ||
			block.ResponsesOutputMessageContentRefusal != nil && strings.TrimSpace(block.Refusal) != "" {
			return false
		}
	}
	return true
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
		case format == EncryptedReasoning || format == GeminiReasoning:
			content, ok := r.ownBoundReasoning(detail.Data, format)
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
