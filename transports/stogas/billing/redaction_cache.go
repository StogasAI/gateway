package billing

import (
	"crypto/sha256"
	"runtime"
	"slices"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

type sharedRedactionPlan struct {
	owner    *keyConfigCache
	digest   [32]byte
	config   *policy.Config
	compiled *redaction.Policy
	bytes    int64
	refs     int
	building bool
}

func redactionPlanDigest(config *policy.Config) [32]byte {
	var plugins *policy.Plugins
	if config != nil {
		plugins = config.Plugins
	}
	return plugins.CacheDigest()
}

func redactionSourcesDigest(config *policy.Config) [32]byte {
	if config == nil {
		return sha256.Sum256(nil)
	}
	sections := config.PluginSources
	if len(sections) == 0 && config.Plugins != nil {
		sections = []*policy.Plugins{config.Plugins}
	}
	parts := make([]string, 0, len(sections))
	for _, plugins := range sections {
		digest := redactionPlanDigest(&policy.Config{Plugins: plugins})
		parts = append(parts, string(digest[:]))
	}
	slices.Sort(parts)
	parts = slices.Compact(parts)
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (snapshot *PolicySnapshot) RedactionIdentity() [32]byte {
	if snapshot.shared != nil {
		return snapshot.shared.redactionID
	}
	return redactionSourcesDigest(snapshot.Config)
}

func (plan *sharedRedactionPlan) get() (*redaction.Policy, error) {
	c := plan.owner
	c.mu.Lock()
	if plan.compiled != nil {
		c.planStats.Hits++
		compiled := plan.compiled
		c.mu.Unlock()
		return compiled, nil
	}
	c.planStats.Misses++
	// Bound scratch memory and CPU for distinct cold dictionaries as well as duplicate builds.
	if plan.building || c.planStats.Building >= runtime.GOMAXPROCS(0) {
		c.planStats.Busy++
		c.mu.Unlock()
		return nil, ErrGatewayUnavailable
	}
	plan.building = true
	c.planStats.Building++
	c.mu.Unlock()
	started := time.Now()
	compiled, err := policy.CompileRedaction(plan.config)
	micros := uint64(time.Since(started).Microseconds())
	c.mu.Lock()
	defer c.mu.Unlock()
	plan.building = false
	c.planStats.Building--
	c.planStats.Builds++
	c.planStats.BuildTotalMicros += micros
	c.planStats.BuildMaxMicros = max(c.planStats.BuildMaxMicros, micros)
	if err != nil {
		c.planStats.BuildFailures++
		return nil, err
	}
	plan.compiled = compiled
	weight := compiled.MemoryBytes()
	plan.bytes += weight
	c.planStats.LargestEntryBytes = max(c.planStats.LargestEntryBytes, plan.bytes)
	// A build may outlive the last cached key reference. Its active request
	// still owns the result, but must not repopulate the cache after eviction.
	if plan.refs > 0 {
		c.bytes += weight
		c.trimLocked()
	}
	return compiled, nil
}

type PolicyCacheDiagnostics struct {
	Entries           int    `json:"entries"`
	SharedPolicies    int    `json:"sharedPolicies"`
	EstimatedBytes    int64  `json:"estimatedBytes"`
	BudgetBytes       int64  `json:"budgetBytes"`
	Hits              uint64 `json:"hits"`
	Misses            uint64 `json:"misses"`
	Evictions         uint64 `json:"evictions"`
	Expired           uint64 `json:"expired"`
	Building          int    `json:"building"`
	Busy              uint64 `json:"busy"`
	Builds            uint64 `json:"builds"`
	BuildFailures     uint64 `json:"buildFailures"`
	BuildTotalMicros  uint64 `json:"buildTotalMicros"`
	BuildMaxMicros    uint64 `json:"buildMaxMicros"`
	EvictedBytes      uint64 `json:"evictedBytes"`
	LargestEntryBytes int64  `json:"largestEntryBytes"`
}

// RedactionPolicy is lazy: cheap access/catalog checks and outer admission must
// precede a cold build. Identical redaction content shares the same matcher,
// even when other fields of the effective policies differ.
func (snapshot *PolicySnapshot) RedactionPolicy() (*redaction.Policy, error) {
	if snapshot == nil {
		return nil, ErrGatewayUnavailable
	}
	if len(snapshot.matchers) == 0 {
		return policy.CompileRedaction(snapshot.Config)
	}
	parts := make([]*redaction.Policy, 0, len(snapshot.matchers))
	for _, plan := range snapshot.matchers {
		compiled, err := plan.get()
		if err != nil {
			return nil, err
		}
		parts = append(parts, compiled)
	}
	if snapshot.shared == nil {
		return redaction.CombinePolicies(parts)
	}
	shared := snapshot.shared
	shared.redactionOnce.Do(func() { shared.redaction, shared.redactionErr = redaction.CombinePolicies(parts) })
	return shared.redaction, shared.redactionErr
}

// ActivePlugins opens only the settings selected by this request.
// Matchers remain interned with their source, and every encrypted open checks
// its matching root even when an earlier caller warmed the compiled source.
func (snapshot *KeyConfigSnapshot) ActivePlugins(config *policy.Config, keys customerkey.Keys) (*policy.ActivePlugins, error) {
	if snapshot == nil || snapshot.owner == nil || snapshot.Claims == nil || config == nil {
		return nil, ErrGatewayUnavailable
	}
	if err := keys.Validate(config.EncryptionKeys); err != nil {
		return nil, err
	}
	c := snapshot.owner
	sections := append([]*policy.Plugins{}, config.PluginSources...)
	if len(sections) == 0 && config.Plugins != nil {
		sections = append(sections, config.Plugins)
	}
	var opened []*sharedPolicySource
	defer func() { c.releaseSources(opened) }()
	for _, document := range config.ActiveEncryptedPlugins {
		if !customerkey.Registered(config.EncryptionKeys, document.EncryptionKeyID()) {
			return nil, customerkey.ErrKey
		}
		source, err := c.acquireSourceDocument(document, nil, snapshot.Claims.OrganizationID, keys, false)
		if err != nil {
			return nil, err
		}
		opened = append(opened, source)
		c.mu.Lock()
		if snapshot.retained && snapshot.conditionalSources[source.cacheKey] == nil {
			if snapshot.conditionalSources == nil {
				snapshot.conditionalSources = map[string]*sharedPolicySource{}
			}
			snapshot.conditionalSources[source.cacheKey] = source
			source.refs++
			c.bytes += conditionalReferenceBytes(source)
			c.trimLocked()
		}
		c.mu.Unlock()
		sections = append(sections, source.value.Config.Plugins)
	}
	// Decrypted sections must pass the same aggregate bounds before any scan.
	active := *config
	active.PluginSources = sections
	if err := active.ValidatePlugins(); err != nil {
		return nil, err
	}
	parts := make([]*redaction.Policy, 0, len(sections))
	for _, plugins := range sections {
		if plugins == nil {
			continue
		}
		c.mu.Lock()
		plan := c.plans[redactionPlanDigest(&policy.Config{Plugins: plugins})]
		if plan != nil {
			plan.refs++
		}
		c.mu.Unlock()
		if plan == nil {
			// Request-supplied plaintext is deliberately not retained in the
			// shared cache. Saved rules retain plans through their source.
			compiled, err := policy.CompileRedaction(&policy.Config{Plugins: plugins})
			if err != nil {
				return nil, err
			}
			parts = append(parts, compiled)
			continue
		}
		compiled, err := plan.get()
		c.mu.Lock()
		c.releasePlanLocked(plan)
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		parts = append(parts, compiled)
	}
	combined, err := redaction.CombinePolicies(parts)
	if err != nil {
		return nil, err
	}
	exports, err := active.ExportConfig()
	if err != nil {
		return nil, err
	}
	return &policy.ActivePlugins{Redaction: combined, TextExtraction: active.TextExtractionEnabled(), Export: exports}, nil
}

func conditionalReferenceBytes(source *sharedPolicySource) int64 {
	return int64(128 + len(source.cacheKey))
}
