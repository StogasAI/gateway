package policy

import "slices"

// Prompt caching modes, from the weakest to the strongest. A deployment that caches only the
// prefixes that a request marks, as Claude does, caches nothing for a client that marks none,
// which no client of OpenAI's interfaces does. Any mode but off has the gateway mark such a
// request, and the mode is the lifetime of the cache entries that the provider then writes. Off
// is the neutral value that replaces a default, and the mode where no policy sets one: the
// gateway changes no request unless a policy says so.
const (
	PromptCachingOff = "off"
	PromptCaching5m  = "5m"
	PromptCaching1h  = "1h"
)

var promptCachingModes = []string{PromptCachingOff, PromptCaching5m, PromptCaching1h}

// PromptCaching returns the strongest mode that the policy's plugins set, or off where none sets
// one. A longer lifetime only costs more to write, so a policy that requires one gets it.
func (c *Config) PromptCaching() string {
	if c == nil {
		return PromptCachingOff
	}
	parts := c.PluginSources
	if len(parts) == 0 && c.Plugins != nil {
		parts = []*Plugins{c.Plugins}
	}
	if mode := combinePromptCaching(parts); mode != "" {
		return mode
	}
	return PromptCachingOff
}

// combinePromptCaching returns the strongest mode that the parts set, or "" where none sets one.
func combinePromptCaching(parts []*Plugins) string {
	mode := ""
	for _, part := range parts {
		if part != nil && slices.Index(promptCachingModes, part.PromptCaching) > slices.Index(promptCachingModes, mode) {
			mode = part.PromptCaching
		}
	}
	return mode
}

func validatePromptCaching(mode string) error {
	if !slices.Contains(promptCachingModes, mode) {
		return configError("plugins.promptCaching must be off, 5m or 1h")
	}
	return nil
}
