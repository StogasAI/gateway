package catalog

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// A request field is a requirement or a preference. A requirement is something that its provider
// documents as a guarantee: what the reply holds and how it is structured, the tools that the
// model may call, a limit on the output, what the request may cost at most, or where its data is
// kept. A deployment that cannot meet one does not serve the request. A preference only tunes how
// the model samples, how much it writes, how fast it answers or how its provider caches the
// prompt, which providers document as a tendency, as best effort or as advice. A deployment that
// has no control for a preference serves the request without it, because the reply still means
// what the client asked for, costs no more than the deployment's own prices and keeps no more
// data. So one set of settings works for every model, and a setting that one provider lacks never
// costs a request its fallbacks. OpenRouter ignores a parameter that a provider lacks unless the
// request sets require_parameters, Anthropic's and Google's OpenAI-compatible endpoints ignore
// these fields, and LiteLLM's proxy drops them with drop_params. A policy that needs a setting
// applied filters on the deployment facts that say so, such as deployment.sampling.seed.
//
// preferences lists each top-level preference with the deployments that take it. A provider
// decides the values of a preference that reaches it.
var preferences = []struct {
	field   string
	carried func(*ResolvedRequest) bool
	clear   func(*ResolvedRequest)
}{
	{"temperature", func(r *ResolvedRequest) bool { return r.Deployment.Sampling.Temperature && !r.openAIRefusesSampling() }, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.Temperature = nil }, func(p *schemas.ResponsesParameters) { p.Temperature = nil })
	}},
	{"top_p", func(r *ResolvedRequest) bool { return r.Deployment.Sampling.TopP && !r.openAIRefusesSampling() }, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.TopP = nil }, func(p *schemas.ResponsesParameters) { p.TopP = nil })
	}},
	// ApplyProviderSamplingParameters gives Claude top_k from the body, so it needs no typed field.
	{"top_k", func(r *ResolvedRequest) bool { return r.Deployment.Sampling.TopK }, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.TopK = nil }, nil)
	}},
	{"frequency_penalty", func(r *ResolvedRequest) bool { return r.Deployment.Sampling.FrequencyPenalty }, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.FrequencyPenalty = nil }, func(p *schemas.ResponsesParameters) { p.FrequencyPenalty = nil })
	}},
	{"presence_penalty", func(r *ResolvedRequest) bool { return r.Deployment.Sampling.PresencePenalty }, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.PresencePenalty = nil }, func(p *schemas.ResponsesParameters) { p.PresencePenalty = nil })
	}},
	{"repetition_penalty", func(r *ResolvedRequest) bool { return r.Deployment.Sampling.RepetitionPenalty }, func(r *ResolvedRequest) {}},
	{"seed", func(r *ResolvedRequest) bool { return r.Deployment.Sampling.Seed }, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.Seed = nil }, nil)
	}},
	// A predicted output only makes the same reply arrive sooner, on OpenAI's Chat Completions.
	{"prediction", func(r *ResolvedRequest) bool { return r.usesOpenAIWire() && r.WireRoute() == RouteChat }, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.Prediction = nil }, nil)
	}},
	{"verbosity", (*ResolvedRequest).usesOpenAIWire, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.Verbosity = nil }, nil)
	}},
	// Anthropic calls a task budget advisory, and documents it on every hosting but Bedrock.
	{"task_budget", func(r *ResolvedRequest) bool {
		return UsesClaudeWire(r.Provider, r.Deployment.ModelID) && r.Deployment.Hosting != CompanyAmazon
	}, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.TaskBudget = nil }, nil)
	}},
	// Claude caches only what a request marks. OpenAI's models and Chutes cache without marks.
	{"cache_control", func(r *ResolvedRequest) bool { return UsesClaudeWire(r.Provider, r.Deployment.ModelID) }, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.CacheControl = nil }, nil)
	}},
	{"prompt_cache_retention", func(r *ResolvedRequest) bool {
		return r.usesOpenAIWire() && r.Deployment.Capabilities.ImplicitPromptCaching
	}, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.PromptCacheRetention = nil }, func(p *schemas.ResponsesParameters) { p.PromptCacheRetention = nil })
	}},
	{"prompt_cache_options", (*ResolvedRequest).marksPromptCache, func(r *ResolvedRequest) {
		r.clearParameters(func(p *schemas.ChatParameters) { p.PromptCacheOptions = nil }, func(p *schemas.ResponsesParameters) { p.PromptCacheOptions = nil })
	}},
	// Without automatic truncation, input that exceeds the context window fails as it does by
	// default, which the client sees.
	{"truncation", (*ResolvedRequest).takesResponsesControls, func(r *ResolvedRequest) {
		r.clearParameters(nil, func(p *schemas.ResponsesParameters) { p.Truncation = nil })
	}},
	// A deployment without reasoning serves every reasoning control without it, and routing has
	// chosen the deployment of the request's reasoning mode.
	{"reasoning", reasons, clearReasoning},
	{"reasoning_effort", reasons, clearReasoning},
	{"reasoning_max_tokens", reasons, clearReasoning},
	{"reasoning_display", reasons, clearReasoning},
	{"reasoning.effort", reasons, clearReasoning},
}

// reasons reports whether the deployment's model reasons.
func reasons(r *ResolvedRequest) bool { return r.Deployment.ReasoningSupported }

// clearReasoning clears the request's reasoning controls.
func clearReasoning(r *ResolvedRequest) {
	r.clearParameters(func(p *schemas.ChatParameters) { p.Reasoning = nil }, func(p *schemas.ResponsesParameters) { p.Reasoning = nil })
}

// usesOpenAIWire reports whether the deployment takes requests in OpenAI's format from a provider
// that serves OpenAI's own interfaces: OpenAI, and Azure for every model but Claude.
func (r *ResolvedRequest) usesOpenAIWire() bool {
	return r.Provider == schemas.OpenAI || r.Provider == schemas.Azure && !UsesClaudeWire(r.Provider, r.Deployment.ModelID)
}

// takesResponsesControls reports whether the deployment takes the controls that only OpenAI's
// Responses have: truncation and reasoning.context.
func (r *ResolvedRequest) takesResponsesControls() bool {
	return r.usesOpenAIWire() && r.WireRoute() == RouteResponses
}

// marksPromptCache reports whether the deployment takes OpenAI's explicit prompt cache marks:
// prompt_cache_options and the prompt_cache_breakpoint of a content block. Every deployment in
// OpenAI's format that caches explicitly takes them, Kimi on AWS included (capture
// aws/chat-completions-prompt-caching), and Claude takes its own cache_control instead.
func (r *ResolvedRequest) marksPromptCache() bool {
	return !UsesClaudeWire(r.Provider, r.Deployment.ModelID) && r.Deployment.Capabilities.ExplicitPromptCaching
}

// PromptCacheTTL12h is the longer lifetime of OpenAI's explicit cache writes, which cost twice the
// default 30 minutes'.
const PromptCacheTTL12h = "12h"

// WritesLongPromptCache reports whether the deployment gets OpenAI's 12-hour prompt cache lifetime.
// Responses takes it and Chat Completions refuses it, on OpenAI and Azure alike (captures
// openai/prompt-cache-lifetimes and azure/prompt-cache-lifetimes), and only a deployment whose
// catalog record prices the writes may make them. Another deployment writes for the default 30
// minutes, which costs less.
func (r *ResolvedRequest) WritesLongPromptCache() bool {
	return r.marksPromptCache() && r.WireRoute() == RouteResponses &&
		len(r.Deployment.Pricing[billing.MeterCacheWrite12hInputTokens]) > 0
}

// keepCarriedPromptCacheTTL leaves out the request's 12-hour prompt cache lifetime where the
// deployment does not write it.
func (r *ResolvedRequest) keepCarriedPromptCacheTTL(raw map[string]json.RawMessage) {
	if r.WritesLongPromptCache() {
		return
	}
	without := func(options *schemas.PromptCacheOptions) *schemas.PromptCacheOptions {
		if options == nil || options.TTL == nil || *options.TTL != PromptCacheTTL12h {
			return options
		}
		if options.Mode == nil {
			return nil
		}
		return &schemas.PromptCacheOptions{Mode: options.Mode}
	}
	var options struct {
		TTL string `json:"ttl"`
	}
	if sonic.Unmarshal(raw["prompt_cache_options"], &options) == nil && options.TTL == PromptCacheTTL12h {
		dropRawMember(raw, "prompt_cache_options", "ttl")
	}
	r.clearParameters(func(p *schemas.ChatParameters) { p.PromptCacheOptions = without(p.PromptCacheOptions) },
		func(p *schemas.ResponsesParameters) { p.PromptCacheOptions = without(p.PromptCacheOptions) })
}

// openAIRefusesSampling reports whether the request's GPT model refuses temperature and top_p.
// OpenAI and Azure take them from a GPT model only while reasoning is off
// (testdata/provider/openai/reasoning-sampling.json), and the catalog's sampling facts say only
// whether some reasoning setting takes them. A request that sets no reasoning gets the model's
// default, which the catalog states.
func (r *ResolvedRequest) openAIRefusesSampling() bool {
	if !r.RunsOpenAIModel() || !r.Deployment.ReasoningSupported {
		return false
	}
	if effort, enabled, set := r.requestedReasoning(); set {
		return effort != "none" && enabled
	}
	return r.Deployment.ReasoningDefault != nil && *r.Deployment.ReasoningDefault != "none"
}

// requestedReasoning returns the effort that the request asks for and whether it leaves reasoning
// on, and reports whether the request sets either.
func (r *ResolvedRequest) requestedReasoning() (effort string, enabled bool, set bool) {
	switch {
	case r.chat != nil && r.chat.ChatParameters.Reasoning != nil:
		reasoning := r.chat.ChatParameters.Reasoning
		if reasoning.Effort != nil {
			return *reasoning.Effort, true, true
		}
		if reasoning.Enabled != nil {
			return "", *reasoning.Enabled, true
		}
		return "", true, reasoning.MaxTokens != nil
	case r.responses != nil && r.responses.ResponsesParameters.Reasoning != nil:
		reasoning := r.responses.ResponsesParameters.Reasoning
		if reasoning.Effort != nil {
			return *reasoning.Effort, true, true
		}
		return "", true, reasoning.MaxTokens != nil
	}
	return "", true, false
}

// clearParameters clears a field of the typed request, which belongs to this pair alone.
func (r *ResolvedRequest) clearParameters(chat func(*schemas.ChatParameters), responses func(*schemas.ResponsesParameters)) {
	if r.chat != nil && chat != nil {
		chat(&r.chat.ChatParameters)
	}
	if r.responses != nil && responses != nil {
		responses(&r.responses.ResponsesParameters)
	}
}

// KeepCarriedPreferences leaves out the preferences that the deployment has no control for, from
// the body that the provider's checks, the hold and the request log read and from the request
// that the provider gets, so each shows what was sent. The request's checks have checked every
// preference's form on every deployment, so a request's validity never depends on routing.
func (r *ResolvedRequest) KeepCarriedPreferences() {
	if r == nil {
		return
	}
	raw := r.pricing.RawBody
	for _, preference := range preferences {
		if _, sent := raw[preference.field]; !sent || preference.carried(r) {
			continue
		}
		delete(raw, preference.field)
		preference.clear(r)
		r.dropExtraParam(preference.field)
	}
	if r.responses != nil {
		r.keepCarriedResponsesMembers(raw)
	}
	r.keepCarriedPromptCacheTTL(raw)
	r.keepCarriedContent()
}

// keepCarriedResponsesMembers leaves out the preferences that a Responses request holds inside an
// object: text.verbosity and reasoning.context, which chooses the earlier reasoning that OpenAI's
// models read.
func (r *ResolvedRequest) keepCarriedResponsesMembers(raw map[string]json.RawMessage) {
	params := &r.responses.ResponsesParameters
	if params.Text != nil && params.Text.Verbosity != nil && !r.usesOpenAIWire() {
		text := *params.Text
		text.Verbosity = nil
		params.Text = &text
		dropRawMember(raw, "text", "verbosity")
	}
	if params.Reasoning != nil && params.Reasoning.Context != nil && !r.takesResponsesControls() {
		reasoning := *params.Reasoning
		reasoning.Context = nil
		params.Reasoning = &reasoning
		dropRawMember(raw, "reasoning", "context")
	}
}

// dropRawMember removes a member of a top-level object, and the object when nothing else is in it.
func dropRawMember(raw map[string]json.RawMessage, field, member string) {
	var object map[string]json.RawMessage
	if sonic.Unmarshal(raw[field], &object) != nil {
		return
	}
	delete(object, member)
	if len(object) == 0 {
		delete(raw, field)
		return
	}
	if encoded, err := sonic.Marshal(object); err == nil {
		raw[field] = encoded
	}
}

// dropExtraParam removes a field from the parameters that reach the provider beside the typed ones.
func (r *ResolvedRequest) dropExtraParam(name string) {
	switch {
	case r.chat != nil:
		if _, ok := r.chat.ExtraParams[name]; ok {
			params := copyStringAnyMap(r.chat.ExtraParams)
			delete(params, name)
			r.chat.SetExtraParams(params)
		}
	case r.responses != nil:
		if _, ok := r.responses.ExtraParams[name]; ok {
			params := copyStringAnyMap(r.responses.ExtraParams)
			delete(params, name)
			r.responses.SetExtraParams(params)
		}
	}
}

// withoutChatPreferences clears the preferences that Responses has no field for, so that a Chat
// Completions request with one still reaches a deployment that serves it through Responses.
func withoutChatPreferences(request *openaiprovider.OpenAIChatRequest) {
	params := &request.ChatParameters
	params.Seed, params.Prediction, params.TopK, params.CacheControl, params.TaskBudget = nil, nil, nil, nil, nil
	for index := range request.Messages {
		request.Messages[index].Name = nil
	}
}

// withoutResponsesPreferences clears the preferences that Chat Completions has no field for, so
// that a Responses request with one still reaches a deployment that serves it through Chat
// Completions.
func withoutResponsesPreferences(request *openaiprovider.OpenAIResponsesRequest) {
	params := &request.ResponsesParameters
	params.Truncation = nil
	if params.Reasoning != nil && params.Reasoning.Context != nil {
		reasoning := *params.Reasoning
		reasoning.Context = nil
		params.Reasoning = &reasoning
	}
}

// keepCarriedContent leaves out of the messages what the deployment has no place for and no need
// of, and writes the rest in the form that the deployment takes: message names, OpenAI's prompt
// cache breakpoints, the annotations and log probabilities of an earlier reply, an earlier
// refusal, and tool call IDs that the deployment's model does not take. Other requests of the same
// body share the messages, so it never changes them.
func (r *ResolvedRequest) keepCarriedContent() {
	claude := UsesClaudeWire(r.Provider, r.Deployment.ModelID)
	ids := r.toolCallIDs(claude)
	switch {
	case r.chat != nil:
		var kept []openaiprovider.OpenAIMessage
		for index, message := range r.chat.Messages {
			carried, changed := r.carriedChatMessage(message, claude, ids)
			if changed && kept == nil {
				kept = append(make([]openaiprovider.OpenAIMessage, 0, len(r.chat.Messages)), r.chat.Messages[:index]...)
			}
			if kept != nil {
				kept = append(kept, carried)
			}
		}
		if kept != nil {
			r.chat.Messages = kept
		}
	case r.responses != nil && r.responses.Input.OpenAIResponsesRequestInputArray != nil:
		input := r.responses.Input.OpenAIResponsesRequestInputArray
		var kept []schemas.ResponsesMessage
		for index, item := range input {
			carried, changed := r.carriedResponsesItem(item, claude, ids)
			if changed && kept == nil {
				kept = append(make([]schemas.ResponsesMessage, 0, len(input)), input[:index]...)
			}
			if kept != nil {
				kept = append(kept, carried)
			}
		}
		if kept != nil {
			r.responses.Input.OpenAIResponsesRequestInputArray = kept
		}
	}
}

// toolCallIDs returns how the deployment's model takes a tool call ID of another provider, or nil
// when it takes every ID.
func (r *ResolvedRequest) toolCallIDs(claude bool) func(string) (string, bool) {
	switch {
	case claude:
		return claudeToolCallID
	case r.runsMistralModel():
		return mistralToolCallID
	}
	return nil
}

// runsMistralModel reports a deployment of a model by Mistral AI.
func (r *ResolvedRequest) runsMistralModel() bool {
	if r.Deployment.snapshot == nil {
		return false
	}
	model, ok := r.Deployment.snapshot.graph.Models[r.Deployment.ModelID]
	return ok && model.AuthorID == "mistral-ai"
}

// carriedChatMessage returns a message as the deployment gets it and whether it differs.
func (r *ResolvedRequest) carriedChatMessage(message openaiprovider.OpenAIMessage, claude bool, ids func(string) (string, bool)) (openaiprovider.OpenAIMessage, bool) {
	changed := false
	// A name tells OpenAI's models who speaks. Claude, Gemini and OpenAI's Responses have no place
	// for it, as Anthropic's own OpenAI-compatible endpoint ignores it, and Azure refuses it for
	// Mistral's models outside a tool message
	// (testdata/provider/azure/other-model-formats-request-fields.json).
	if message.Name != nil && (claude || r.RunsGeminiModel() || r.WireRoute() != RouteChat || r.Provider == schemas.Azure &&
		r.Deployment.Upstream.ModelFormat == "Mistral AI" && message.Role != schemas.ChatMessageRoleTool) {
		message.Name, changed = nil, true
	}
	if content := message.Content; content != nil {
		if blocks, differs := r.carriedChatBreakpoints(content.ContentBlocks); differs {
			message.Content, changed = &schemas.ChatMessageContent{ContentStr: content.ContentStr, ContentBlocks: blocks}, true
		}
	}
	if tool := message.ChatToolMessage; ids != nil && tool != nil && tool.ToolCallID != nil {
		if id, mapped := ids(*tool.ToolCallID); mapped {
			copied := *tool
			copied.ToolCallID = &id
			message.ChatToolMessage, changed = &copied, true
		}
	}
	assistant := message.OpenAIChatAssistantMessage
	if assistant == nil {
		return message, changed
	}
	copied := *assistant
	// Only OpenAI's models take back the citations of an earlier reply, which no model reads.
	if len(copied.Annotations) > 0 && !r.usesOpenAIWire() {
		copied.Annotations, changed = nil, true
	}
	// Claude and Gemini have no refusal field, so an earlier refusal is the text that the assistant
	// wrote.
	if copied.Refusal != nil && r.refusalAsText(claude) {
		if chatMessageWithoutText(message.Content) && strings.TrimSpace(*copied.Refusal) != "" {
			message.Content = &schemas.ChatMessageContent{ContentStr: copied.Refusal}
		}
		copied.Refusal, changed = nil, true
	}
	if ids != nil {
		for index, call := range copied.ToolCalls {
			if call.ID == nil {
				continue
			}
			if id, mapped := ids(*call.ID); mapped {
				if &copied.ToolCalls[0] == &assistant.ToolCalls[0] {
					copied.ToolCalls = slices.Clone(assistant.ToolCalls)
				}
				copied.ToolCalls[index].ID, changed = &id, true
			}
		}
	}
	if changed {
		message.OpenAIChatAssistantMessage = &copied
	}
	return message, changed
}

// refusalAsText reports whether the deployment gets an earlier refusal as the text that the
// assistant wrote, and an earlier reply without its log probabilities: Claude and Gemini, which take
// neither.
func (r *ResolvedRequest) refusalAsText(claude bool) bool {
	return claude || r.RunsGeminiModel()
}

// chatMessageWithoutText reports whether a message holds no text.
func chatMessageWithoutText(content *schemas.ChatMessageContent) bool {
	if content == nil {
		return true
	}
	if content.ContentStr != nil && strings.TrimSpace(*content.ContentStr) != "" {
		return false
	}
	return !slices.ContainsFunc(content.ContentBlocks, func(block schemas.ChatContentBlock) bool {
		return block.Text != nil && strings.TrimSpace(*block.Text) != ""
	})
}

// carriedChatBreakpoints returns content blocks with OpenAI's prompt cache breakpoints as the
// deployment gets them, and whether they differ.
func (r *ResolvedRequest) carriedChatBreakpoints(blocks []schemas.ChatContentBlock) ([]schemas.ChatContentBlock, bool) {
	if !slices.ContainsFunc(blocks, func(block schemas.ChatContentBlock) bool {
		return r.breakpointDiffers(block.PromptCacheBreakpoint)
	}) {
		return blocks, false
	}
	blocks = slices.Clone(blocks)
	for index := range blocks {
		blocks[index].PromptCacheBreakpoint = r.carriedBreakpoint(blocks[index].PromptCacheBreakpoint)
	}
	return blocks, true
}

// breakpointDiffers reports whether a prompt cache breakpoint changes on its way to the deployment:
// one that marks no cache gets none, and one that marks gets no ttl that it does not take. Chat
// Completions takes no ttl in a breakpoint, which OpenAI, Azure and Bedrock refuse (captures
// openai/prompt-cache-lifetimes and aws/chat-completions-prompt-caching), and Responses takes 12
// hours only where the deployment writes them. A breakpoint without its ttl lasts as long as the
// request's lifetime, which keepCarriedPromptCacheTTL leaves at 12 hours only where it is taken.
func (r *ResolvedRequest) breakpointDiffers(breakpoint *schemas.PromptCacheBreakpoint) bool {
	if breakpoint == nil {
		return false
	}
	if !r.marksPromptCache() {
		return true
	}
	return breakpoint.TTL != nil && (r.WireRoute() == RouteChat || *breakpoint.TTL == PromptCacheTTL12h && !r.WritesLongPromptCache())
}

// carriedBreakpoint returns a prompt cache breakpoint as the deployment gets it.
func (r *ResolvedRequest) carriedBreakpoint(breakpoint *schemas.PromptCacheBreakpoint) *schemas.PromptCacheBreakpoint {
	if !r.breakpointDiffers(breakpoint) {
		return breakpoint
	}
	if !r.marksPromptCache() {
		return nil
	}
	return &schemas.PromptCacheBreakpoint{Mode: breakpoint.Mode}
}

// carriedResponsesItem returns an input item as the deployment gets it and whether it differs.
func (r *ResolvedRequest) carriedResponsesItem(item schemas.ResponsesMessage, claude bool, ids func(string) (string, bool)) (schemas.ResponsesMessage, bool) {
	changed := false
	if content := item.Content; content != nil {
		if blocks, differs := r.carriedResponsesBlocks(content.ContentBlocks, r.refusalAsText(claude)); differs {
			item.Content, changed = &schemas.ResponsesMessageContent{ContentStr: content.ContentStr, ContentBlocks: blocks}, true
		}
	}
	tool := item.ResponsesToolMessage
	if tool == nil {
		return item, changed
	}
	copied := *tool
	toolChanged := false
	if ids != nil && copied.CallID != nil {
		if id, mapped := ids(*copied.CallID); mapped {
			copied.CallID, toolChanged = &id, true
		}
	}
	if output := copied.Output; output != nil {
		if blocks, differs := r.carriedResponsesBlocks(output.ResponsesFunctionToolCallOutputBlocks, r.refusalAsText(claude)); differs {
			without := *output
			without.ResponsesFunctionToolCallOutputBlocks = blocks
			copied.Output, toolChanged = &without, true
		}
	}
	if toolChanged {
		item.ResponsesToolMessage = &copied
	}
	return item, changed || toolChanged
}

// carriedResponsesBlocks returns content blocks as the deployment gets them and whether they
// differ: with OpenAI's prompt cache breakpoints as the deployment takes them (carriedBreakpoint),
// and where refusals become text (refusalAsText) without the log probabilities of an earlier reply
// and with an earlier refusal as the text that the assistant wrote.
func (r *ResolvedRequest) carriedResponsesBlocks(blocks []schemas.ResponsesMessageContentBlock, asText bool) ([]schemas.ResponsesMessageContentBlock, bool) {
	differs := func(block schemas.ResponsesMessageContentBlock) bool {
		return r.breakpointDiffers(block.PromptCacheBreakpoint) || asText && (block.Type == schemas.ResponsesOutputMessageContentTypeRefusal ||
			block.ResponsesOutputMessageContentText != nil && len(block.ResponsesOutputMessageContentText.LogProbs) > 0)
	}
	if !slices.ContainsFunc(blocks, differs) {
		return blocks, false
	}
	blocks = slices.Clone(blocks)
	for index := range blocks {
		block := &blocks[index]
		block.PromptCacheBreakpoint = r.carriedBreakpoint(block.PromptCacheBreakpoint)
		if !asText {
			continue
		}
		if block.Type == schemas.ResponsesOutputMessageContentTypeRefusal && block.ResponsesOutputMessageContentRefusal != nil {
			block.Type, block.Text = schemas.ResponsesOutputMessageContentTypeText, &block.ResponsesOutputMessageContentRefusal.Refusal
			block.ResponsesOutputMessageContentRefusal = nil
			block.ResponsesOutputMessageContentText = &schemas.ResponsesOutputMessageContentText{Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{}}
		}
		if text := block.ResponsesOutputMessageContentText; text != nil && len(text.LogProbs) > 0 {
			block.ResponsesOutputMessageContentText = &schemas.ResponsesOutputMessageContentText{Annotations: text.Annotations}
		}
	}
	return blocks, true
}

// claudeToolCallID returns the ID under which Claude takes a tool call whose ID holds characters
// outside Claude's alphabet of letters, digits, "_" and "-", and reports whether it differs. An ID
// only pairs a call with its result inside one request, and other providers write theirs with
// other characters, as Kimi's "functions.name:0", so a conversation that moves to Claude keeps its
// calls under a hash of each ID. The same ID always gets the same hash, which keeps Claude's
// cached prefix across turns, and two IDs never share one, as they can when each foreign
// character becomes "_", which is how LiteLLM writes them.
func claudeToolCallID(id string) (string, bool) {
	for index := 0; index < len(id); index++ {
		if c := id[index]; isAlphanumeric(c) || c == '_' || c == '-' {
			continue
		}
		sum := sha256.Sum256([]byte(id))
		return "call_" + hex.EncodeToString(sum[:16]), true
	}
	return id, false
}

// mistralToolCallID returns the ID under which a model by Mistral AI takes a tool call, nine
// letters and digits, and reports whether it differs. Mistral's chat format takes no other ID, and
// providers refuse a conversation that holds one: Azure refuses any other ID, and Bedrock refuses
// one whose last nine characters, which it keeps, are not letters and digits (captures
// azure/mistral-tool-call-ids and aws/chat-completions-in-region-tool-call-ids). Other IDs map to
// nine characters of their hash, as claudeToolCallID maps them, where keeping their first or last
// nine letters and digits, as opencode and vLLM do, gives Kimi's "functions.get_weather:0" and
// "functions.get_weather:1" one ID.
func mistralToolCallID(id string) (string, bool) {
	valid := len(id) == 9
	for index := 0; valid && index < len(id); index++ {
		valid = isAlphanumeric(id[index])
	}
	if valid {
		return id, false
	}
	sum := sha256.Sum256([]byte(id))
	value := binary.BigEndian.Uint64(sum[:8])
	mapped := make([]byte, 9)
	for index := range mapped {
		mapped[index] = alphanumeric[value%uint64(len(alphanumeric))]
		value /= uint64(len(alphanumeric))
	}
	return string(mapped), true
}

const alphanumeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func isAlphanumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
