package billing

import (
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"
	"unsafe"

	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
	"golang.org/x/sync/singleflight"
)

const keyConfigEntryBytes = 4096

type sharedKeyPolicy struct {
	redactionOnce sync.Once
	redaction     *redaction.Policy
	redactionErr  error
	redactionID   [32]byte
	config        *policy.Config
	digest        string
	bytes         int64
	refs          int
}

type keyConfigCacheEntry struct {
	key         string
	expiresAt   time.Time
	invalidated bool
	snapshot    *KeyConfigSnapshot
	weight      int64
}

// Key entries and short-lived source pins own cached references. Removing the final reference drops
// the interned policy and matcher together; active requests retain ordinary Go
// pointers until they finish. PostgreSQL still checks the live generation.
type keyConfigCache struct {
	mu                sync.Mutex
	entries           map[string]*list.Element
	policies          map[string]*sharedKeyPolicy
	sources           map[string]*sharedPolicySource
	sourceOwners      map[policySourceOwner]ownedPolicySource
	sourceFlights     singleflight.Group
	sourceBuilds      int
	plans             map[[32]byte]*sharedRedactionPlan
	credentials       map[[32]byte]*sharedCredential
	credentialSources map[[32]byte]*sharedCredentialPolicy
	oldest            list.List // increasing authority-check time; freshness does not evict compiled data
	bytes             int64
	hits              uint64
	misses            uint64
	evictions         uint64
	expired           uint64
	planStats         PolicyCacheDiagnostics
	closed            bool
}

func (c *keyConfigCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		for c.oldest.Len() > 0 {
			c.removeLocked(c.oldest.Front())
		}
	}
}

func (c *keyConfigCache) get(key string, now time.Time) (*KeyConfigSnapshot, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if element := c.entries[key]; element != nil {
		entry := element.Value.(keyConfigCacheEntry)
		if !entry.invalidated && now.Before(entry.expiresAt) {
			c.hits++
			return entry.snapshot, true
		}
		c.misses++
		c.expired++
		return entry.snapshot, false
	}
	c.misses++
	return nil, false
}

// Retain source references across the database wait even if capacity eviction
// removes this key meanwhile. The caller releases the pins after installation.
func (c *keyConfigCache) pinForRefresh(key string) *KeyConfigSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element := c.entries[key]; element != nil {
		snapshot := element.Value.(keyConfigCacheEntry).snapshot
		for _, source := range snapshot.sourceRefs {
			if source != nil {
				source.refs++
			}
		}
		return snapshot
	}
	return nil
}

func (c *keyConfigCache) put(key string, snapshot *KeyConfigSnapshot, now time.Time) *KeyConfigSnapshot {
	if c == nil || key == "" || snapshot == nil {
		return snapshot
	}
	copy := *snapshot
	copy.shared, copy.matchers = nil, nil
	copy.credentialPolicies = make(map[string]*PolicySnapshot)
	copy.owner, copy.retained = c, false
	copy.credentialRefs = nil
	copy.conditionalSources = nil
	copy.Credentials = make(map[string][]CredentialSelection, len(snapshot.Credentials))
	contents := make(map[string]sharedCredential, len(snapshot.Credentials))
	sources := make(map[string]*sharedCredentialPolicy)
	for provider, selections := range snapshot.Credentials {
		copy.Credentials[provider] = append([]CredentialSelection{}, selections...)
		for _, selection := range selections {
			if selection.Credential != nil {
				raw := selection.Credential.Policy.Source
				source := sources[string(raw)]
				if source == nil {
					source = &sharedCredentialPolicy{raw: raw, digest: sha256.Sum256(raw), bytes: int64(len(raw))*8 + 256}
					sources[string(raw)] = source
				}
				digest, size, err := credentialContent(selection.Credential, source)
				if err != nil {
					return snapshot
				}
				contents[selection.ID] = sharedCredential{digest: digest, bytes: size, policy: source}
			}
		}
	}
	snapshot = &copy
	if snapshot.Config != nil && snapshot.cacheBytes == 0 {
		snapshot.cacheBytes = snapshot.Config.CompositionBytes()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return snapshot
	}
	current := c.entries[key]
	if current != nil {
		entry := current.Value.(keyConfigCacheEntry)
		previous := entry.snapshot
		if previous.Generation > snapshot.Generation || previous.CredentialsGeneration > snapshot.CredentialsGeneration ||
			entry.expiresAt.After(now.Add(keyConfigCacheTTL)) {
			return previous
		}
	}
	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
	}
	c.retainPolicyLocked(&snapshot.PolicySnapshot)
	c.indexSourcesLocked(snapshot.Claims, &snapshot.PolicySnapshot)
	snapshot.retained = true

	for provider, selections := range snapshot.Credentials {
		for index, selection := range selections {
			if selection.Credential == nil {
				continue
			}
			content := contents[selection.ID]
			if c.credentials == nil {
				c.credentials = make(map[[32]byte]*sharedCredential)
			}
			shared := c.credentials[content.digest]
			if shared == nil {
				value := *selection.Credential
				value.azureBindings = indexAzureBindings(value.Bindings)
				if c.credentialSources == nil {
					c.credentialSources = make(map[[32]byte]*sharedCredentialPolicy)
				}
				source := c.credentialSources[content.policy.digest]
				if source == nil {
					source = content.policy
					c.credentialSources[source.digest] = source
					c.bytes += source.bytes
				}
				source.refs++
				value.Policy.Source, value.policySource = source.raw, source
				shared = &sharedCredential{value: &value, digest: content.digest, bytes: content.bytes, policy: source}
				c.credentials[content.digest] = shared
				c.bytes += content.bytes
			}
			shared.refs++
			snapshot.credentialRefs = append(snapshot.credentialRefs, shared)
			selection.Credential = shared.value
			snapshot.Credentials[provider][index] = selection
		}
	}
	// Acquire replacement references before dropping the old entry, preserving
	// an unchanged matcher across an explicit refresh.
	if current != nil {
		c.removeLocked(current)
	}
	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
	}
	weight := int64(keyConfigEntryBytes + len(key))
	for _, selections := range snapshot.Credentials {
		for _, selection := range selections {
			// Per-key selections and reference slices are not part of the shared ciphertext.
			weight += int64(64 + len(selection.ID) + len(selection.Mode))
		}
	}
	entry := keyConfigCacheEntry{key: key, expiresAt: now.Add(keyConfigCacheTTL), snapshot: snapshot, weight: weight}
	previous := c.oldest.Back()
	for previous != nil && previous.Value.(keyConfigCacheEntry).expiresAt.After(entry.expiresAt) {
		previous = previous.Prev()
	}
	if previous == nil {
		c.entries[key] = c.oldest.PushFront(entry)
	} else {
		c.entries[key] = c.oldest.InsertAfter(entry, previous)
	}
	c.bytes += entry.weight
	c.trimLocked()
	return snapshot
}

func (c *keyConfigCache) retainPolicyLocked(snapshot *PolicySnapshot) {
	if snapshot.Config != nil {
		if c.policies == nil {
			c.policies = make(map[string]*sharedKeyPolicy)
		}
		if c.plans == nil {
			c.plans = make(map[[32]byte]*sharedRedactionPlan)
		}
		shared := c.policies[snapshot.Digest]
		if shared == nil {
			shared = &sharedKeyPolicy{config: snapshot.Config, digest: snapshot.Digest, bytes: snapshot.cacheBytes, redactionID: redactionSourcesDigest(snapshot.Config)}
			c.policies[snapshot.Digest] = shared
			c.bytes += shared.bytes
		}
		shared.refs++
		snapshot.shared, snapshot.Config = shared, shared.config
		sections := snapshot.Config.PluginSources
		if len(sections) == 0 {
			sections = []*policy.Plugins{snapshot.Config.Plugins}
		}
		for _, plugins := range sections {
			config := &policy.Config{Plugins: plugins}
			var digest [32]byte
			found := false
			for _, source := range snapshot.sourceRefs {
				if source != nil && source.value.Config.Plugins == plugins {
					digest = source.pluginDigest
					found = true
					break
				}
			}
			if !found {
				digest = redactionPlanDigest(config)
			}
			plan := c.plans[digest]
			if plan == nil {
				// Retain only plugin configuration, not an otherwise unreferenced
				// policy's routing/access/limit trees.
				weight := int64(256)
				if len(snapshot.sourceRefs) == 0 {
					raw, _ := json.Marshal(plugins)
					weight += int64(len(raw)) * 4
				}
				plan = &sharedRedactionPlan{owner: c, digest: digest, config: config, bytes: weight}
				c.plans[digest] = plan
				c.bytes += plan.bytes
			}
			plan.refs++
			snapshot.matchers = append(snapshot.matchers, plan)
		}
	}
	for _, source := range snapshot.sourceRefs {
		if source != nil {
			source.refs++
		}
	}
	c.bytes += policyReferenceBytes(snapshot)
}

func policyReferenceBytes(snapshot *PolicySnapshot) int64 {
	bytes := int64(unsafe.Sizeof(*snapshot)) + int64(len(snapshot.Digest))
	bytes += int64(cap(snapshot.sourceRefs)+cap(snapshot.matchers)) * 8
	if snapshot.Versions != nil {
		bytes += int64(cap(*snapshot.Versions)) * int64(unsafe.Sizeof(PolicyVersion{}))
	}
	return bytes
}

// Returns true only to the first caller that invalidates this exact snapshot.
func (c *keyConfigCache) confirm(key string, snapshot *KeyConfigSnapshot, current bool, checkedAt, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || checkedAt.After(now) {
		return false
	}
	element := c.entries[key]
	if element == nil || element.Value.(keyConfigCacheEntry).snapshot != snapshot {
		return false
	}
	entry := element.Value.(keyConfigCacheEntry)
	if entry.invalidated {
		return false
	}
	if !current {
		entry.invalidated = true
		element.Value = entry
		return true
	}
	expiresAt := checkedAt.Add(keyConfigCacheTTL)
	if !expiresAt.After(entry.expiresAt) {
		return false
	}
	entry.expiresAt = expiresAt
	element.Value = entry
	// Most replies arrive in order. Search backward only for replies that do not.
	previous := c.oldest.Back()
	for previous != nil && previous != element && previous.Value.(keyConfigCacheEntry).expiresAt.After(expiresAt) {
		previous = previous.Prev()
	}
	if previous != element {
		if previous == nil {
			c.oldest.MoveToFront(element)
		} else {
			c.oldest.MoveAfter(element, previous)
		}
	}
	return false
}

func (c *keyConfigCache) trimLocked() {
	for c.bytes > keyConfigCacheBytes && c.oldest.Len() > 0 {
		c.removeLocked(c.oldest.Front())
		c.evictions++
	}
}

func (c *keyConfigCache) removeLocked(element *list.Element) {
	entry := element.Value.(keyConfigCacheEntry)
	c.bytes -= entry.weight
	entry.snapshot.retained = false
	c.releasePolicyLocked(&entry.snapshot.PolicySnapshot)
	for _, variant := range entry.snapshot.credentialPolicies {
		c.releasePolicyLocked(variant)
	}
	for _, source := range entry.snapshot.conditionalSources {
		c.bytes -= conditionalReferenceBytes(source)
		c.releaseSourceLocked(source)
	}
	for _, credential := range entry.snapshot.credentialRefs {
		credential.refs--
		if credential.refs == 0 {
			delete(c.credentials, credential.digest)
			c.bytes -= credential.bytes
			credential.policy.refs--
			if credential.policy.refs == 0 {
				delete(c.credentialSources, credential.policy.digest)
				c.bytes -= credential.policy.bytes
			}
		}
	}
	delete(c.entries, entry.key)
	c.oldest.Remove(element)
	if len(c.entries) == 0 {
		c.entries = nil
	}
	if len(c.policies) == 0 {
		c.policies = nil
	}
	if len(c.credentials) == 0 {
		c.credentials = nil
	}
	if len(c.credentialSources) == 0 {
		c.credentialSources = nil
	}
}

func (c *keyConfigCache) releasePolicyLocked(snapshot *PolicySnapshot) {
	c.bytes -= policyReferenceBytes(snapshot)
	if shared := snapshot.shared; shared != nil {
		shared.refs--
		if shared.refs == 0 {
			delete(c.policies, shared.digest)
			c.bytes -= shared.bytes
		}
	}
	for _, plan := range snapshot.matchers {
		c.releasePlanLocked(plan)
	}
	for _, source := range snapshot.sourceRefs {
		c.releaseSourceLocked(source)
	}
}

// MemoryBytes includes objects this request can retain after cache eviction.
// Sharing counts once within a snapshot; admission may conservatively charge
// concurrent requests for the same objects until their holds finish.
func (s *KeyConfigSnapshot) MemoryBytes() int64 {
	if s == nil || s.owner == nil {
		return 0
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	total := int64(keyConfigEntryBytes)
	seen := make(map[any]bool)
	add := func(identity any, bytes int64) {
		if !seen[identity] {
			seen[identity] = true
			total += bytes
		}
	}
	addPlan := func(plan *sharedRedactionPlan) {
		if plan != nil {
			add(plan, plan.bytes)
		}
	}
	addSource := func(source *sharedPolicySource) {
		if source == nil {
			return
		}
		add(source, source.bytes)
		addPlan(source.plan)
		for _, plan := range source.rulePlans {
			addPlan(plan)
		}
	}
	addPolicy := func(snapshot *PolicySnapshot) {
		total += policyReferenceBytes(snapshot)
		if snapshot.shared != nil {
			add(snapshot.shared, max(snapshot.shared.bytes, snapshot.cacheBytes))
		}
		for _, source := range snapshot.sourceRefs {
			addSource(source)
		}
		for _, plan := range snapshot.matchers {
			addPlan(plan)
		}
	}
	addPolicy(&s.PolicySnapshot)
	for _, selections := range s.Credentials {
		for _, selection := range selections {
			total += int64(64 + len(selection.ID) + len(selection.Mode))
		}
	}
	for _, credential := range s.credentialRefs {
		add(credential, credential.bytes)
		add(credential.policy, credential.policy.bytes)
	}
	for _, snapshot := range s.credentialPolicies {
		addPolicy(snapshot)
	}
	for _, source := range s.conditionalSources {
		addSource(source)
		total += conditionalReferenceBytes(source)
	}
	return total
}

func (c *keyConfigCache) releasePlanLocked(plan *sharedRedactionPlan) {
	if plan == nil {
		return
	}
	plan.refs--
	if plan.refs == 0 {
		delete(c.plans, plan.digest)
		c.bytes -= plan.bytes
		c.planStats.EvictedBytes += uint64(plan.bytes)
		c.planStats.Evictions++
	}
	if len(c.plans) == 0 {
		c.plans = nil
	}
}

func (c *keyConfigCache) remove(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if element := c.entries[key]; element != nil {
		c.removeLocked(element)
	}
}

func (c *keyConfigCache) diagnostics() PolicyCacheDiagnostics {
	c.mu.Lock()
	defer c.mu.Unlock()
	return PolicyCacheDiagnostics{Entries: len(c.entries), SharedPolicies: len(c.policies), EstimatedBytes: c.bytes,
		BudgetBytes: keyConfigCacheBytes, Hits: c.hits, Misses: c.misses, Evictions: c.evictions, Expired: c.expired}
}

func (c *keyConfigCache) redactionDiagnostics() PolicyCacheDiagnostics {
	c.mu.Lock()
	defer c.mu.Unlock()
	stats := c.planStats
	stats.Entries = len(c.plans)
	for _, plan := range c.plans {
		stats.EstimatedBytes += plan.bytes
	}
	// This is a subset of keyConfigCache bytes, not a second budget.
	return stats
}
