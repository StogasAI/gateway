package stogas

import (
	"strconv"
	"strings"

	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// gatewayPromptCache returns the lifetime of the cache entries that the gateway has the pair's
// provider write, or "" where it adds no cache marks: the client marked something to cache, which
// then decides alone, or the pair's policy and deployment ask for none.
func gatewayPromptCache(state *State) string {
	if state == nil || state.Resolution == nil {
		return ""
	}
	resolution := state.Resolution
	if anthropicRawRequestContainsCacheControl(resolution.Route, resolution.RawBody()) || anthropicToolCacheControlExists(resolution.RawTools()) {
		return ""
	}
	return resolution.PromptCaching()
}

// promptCacheWriteMeter is the meter of a cache write that lasts the lifetime.
func promptCacheWriteMeter(lifetime string) string {
	if lifetime == policy.PromptCaching1h {
		return billing.MeterCacheWrite1hInputTokens
	}
	return billing.MeterCacheWrite5mInputTokens
}

// markAnthropicPromptCache has Claude cache a Messages body that marks nothing, in entries that
// last the lifetime. The top-level mark caches the request up to its last block that a cache can
// end at, which Claude chooses, so each turn of a conversation reads the turns before it. A mark at
// the end of the system prompt, or of the tools where no system block takes one, also caches that
// prefix on its own, so that a new conversation with the same system prompt and tools reads it.
// Claude bills each written token once, however many marks a request holds, and writes nothing
// shorter than its smallest cache entry. Five minutes is every Claude platform's default lifetime,
// so only an hour is named.
func markAnthropicPromptCache(body []byte, lifetime string) ([]byte, error) {
	mark := map[string]string{"type": "ephemeral"}
	if lifetime == policy.PromptCaching1h {
		mark["ttl"] = lifetime
	}
	body, err := providerutils.SetJSONField(body, "cache_control", mark)
	if err != nil {
		return nil, err
	}
	system := providerutils.GetJSONField(body, "system")
	if strings.HasPrefix(system.Raw, `"`) && system.String() != "" {
		return providerutils.SetJSONField(body, "system", []map[string]any{{"type": "text", "text": system.String(), "cache_control": mark}})
	}
	last := -1
	for index, block := range system.Array() {
		if block.Get("type").String() == "text" && block.Get("text").String() != "" {
			last = index
		}
	}
	if last >= 0 {
		return providerutils.SetJSONField(body, "system."+strconv.Itoa(last)+".cache_control", mark)
	}
	if tools := providerutils.GetJSONField(body, "tools").Array(); len(tools) > 0 {
		return providerutils.SetJSONField(body, "tools."+strconv.Itoa(len(tools)-1)+".cache_control", mark)
	}
	return body, nil
}
