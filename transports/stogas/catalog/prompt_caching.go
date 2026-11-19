package catalog

import "github.com/maximhq/bifrost/transports/stogas/policy"

// PromptCaching returns the lifetime of the cache entries, 5m or 1h, that the pair's policy asks
// the gateway to have the provider write for a request that marks nothing to cache, or "" where
// it asks for none. Only a deployment that caches nothing unmarked needs marks; one that caches
// on its own, as OpenAI's do, gets none.
func (r *ResolvedRequest) PromptCaching() string {
	if r == nil || !r.Deployment.Capabilities.ExplicitPromptCaching || r.Deployment.Capabilities.ImplicitPromptCaching ||
		r.promptCaching == policy.PromptCachingOff {
		return ""
	}
	return r.promptCaching
}
