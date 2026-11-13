package anthropic

// A request can ask what a reply shows of Claude's thinking (Chat reasoning.display, Responses
// reasoning.summary) without an effort or a budget, as Anthropic's own examples do with
// thinking {"type":"adaptive","display":"summarized"}. The request then keeps the model's
// default thinking. Upstream sent thinking "disabled" for it on Chat, which turned reasoning
// off on the models that think unasked, and sent no thinking on Responses and on the models
// that refuse "disabled", which dropped the display, so the reply stayed without summaries and
// progress updates.

// DefaultThinksUnasked reports whether the model thinks when a request has no thinking field:
// Claude 5 and later models and Mythos Preview
// (https://platform.claude.com/docs/en/build-with-claude/thinking, "Configuring thinking").
func DefaultThinksUnasked(model string) bool {
	return IsFableFamily(model) || IsOpus5Plus(model) || IsSonnet5Plus(model) || IsHaiku5Plus(model)
}

// defaultThinkingForDisplay is the thinking object for a display without an effort or a budget:
// "adaptive", which is what a model that thinks unasked does without the object, so that the
// display has an object to go on. A model that does not think unasked gets no object, because
// it has nothing to display, and a request without a display gets none either.
func defaultThinkingForDisplay(model string, display *string) *AnthropicThinking {
	if display == nil || !DefaultThinksUnasked(model) {
		return nil
	}
	return &AnthropicThinking{Type: "adaptive"}
}
