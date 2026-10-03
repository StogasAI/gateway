package billing

import (
	"bytes"
	"encoding/json"
	"runtime"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

type sharedPolicySource struct {
	cacheKey     string
	raw          json.RawMessage
	value        *policy.Source
	pluginDigest [32]byte
	plan         *sharedRedactionPlan
	rulePlans    []*sharedRedactionPlan
	bytes        int64
	refs         int
	owners       map[policySourceOwner]struct{}
}

type policySourceOwner struct {
	organization, identity string
}
type ownedPolicySource struct {
	source   *sharedPolicySource
	revision int
}
type policySourcePins struct {
	sources []*sharedPolicySource
	known   map[string]int
	byID    map[string]*sharedPolicySource
}

// Owner indexes only identify reusable content. Every reference must be
// confirmed by PostgreSQL before it becomes part of a request snapshot.
func (c *keyConfigCache) indexSourcesLocked(claims *APIKeyClaims, snapshot *PolicySnapshot) {
	if claims == nil || snapshot.Versions == nil || len(snapshot.sourceRefs) != len(*snapshot.Versions) {
		return
	}
	for i, version := range *snapshot.Versions {
		source := snapshot.sourceRefs[i]
		if source == nil || version.ID == "" || version.Revision < 1 {
			continue
		}
		owner := policySourceOwner{claims.OrganizationID, version.identity()}
		previous, exists := c.sourceOwners[owner]
		if exists && previous.revision > version.Revision {
			continue
		}
		if exists && previous.source != source {
			delete(previous.source.owners, owner)
			previous.source.bytes -= sourceOwnerBytes(owner)
			c.bytes -= sourceOwnerBytes(owner)
		}
		if c.sourceOwners == nil {
			c.sourceOwners = map[policySourceOwner]ownedPolicySource{}
		}
		c.sourceOwners[owner] = ownedPolicySource{source, version.Revision}
		if _, exists := source.owners[owner]; !exists {
			if source.owners == nil {
				source.owners = map[policySourceOwner]struct{}{}
			}
			source.owners[owner] = struct{}{}
			source.bytes += sourceOwnerBytes(owner)
			c.bytes += sourceOwnerBytes(owner)
		}
	}
}

func sourceOwnerBytes(owner policySourceOwner) int64 {
	return int64(192 + len(owner.organization) + len(owner.identity))
}

func (c *keyConfigCache) pinSourcesForClaims(claims *APIKeyClaims, previous *KeyConfigSnapshot) policySourcePins {
	result := policySourcePins{known: map[string]int{}, byID: map[string]*sharedPolicySource{}}
	if claims == nil {
		return result
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return result
	}
	identities := []string{"organization:" + claims.OrganizationID, "key:" + claims.KeyID}
	if claims.GrantID != nil {
		identities = append(identities, "grant:"+*claims.GrantID)
	}
	if previous != nil && previous.Versions != nil {
		for _, selections := range previous.Credentials {
			for _, selection := range selections {
				if selection.ID != "" {
					identities = append(identities, "credential:"+selection.ID)
				}
			}
		}
		for _, version := range *previous.Versions {
			identities = append(identities, version.identity())
		}
	}
	for _, identity := range identities {
		if result.byID[identity] != nil {
			continue
		}
		entry, exists := c.sourceOwners[policySourceOwner{claims.OrganizationID, identity}]
		if !exists {
			continue
		}
		entry.source.refs++
		result.sources = append(result.sources, entry.source)
		result.byID[identity] = entry.source
		result.known[identity] = entry.revision
	}
	return result
}

func (c *keyConfigCache) acquireSourceDelta(records []policySourceRecord, organizationID string, pins policySourcePins, key customerkey.Keys) ([]*sharedPolicySource, error) {
	if len(records) < 1 || len(records) > 36 || organizationID == "" {
		return nil, ErrGatewayUnavailable
	}
	result := make([]*sharedPolicySource, 0, len(records))
	seen := make(map[string]bool, len(records))
	var budget policy.SourceBudget
	for _, record := range records {
		identity := record.identity()
		if !record.Scope.Valid() || record.ID == "" || record.Revision < 1 || seen[identity] {
			c.releaseSources(result)
			return nil, ErrGatewayUnavailable
		}
		seen[identity] = true
		document := record.Source
		if len(document) == 0 {
			source := pins.byID[identity]
			if pins.known[identity] != record.Revision || source == nil {
				c.releaseSources(result)
				return nil, ErrGatewayUnavailable
			}
			if required := source.value.RequiredEncryptionKeyID; required != "" && !key.Matches(required) {
				c.releaseSources(result)
				return nil, customerkey.ErrKey
			}
			if err := budget.AddSource(source.value); err != nil {
				c.releaseSources(result)
				return nil, err
			}
			c.mu.Lock()
			source.refs++
			c.mu.Unlock()
			result = append(result, source)
			continue
		}
		if bytes.Equal(bytes.TrimSpace(document), []byte("null")) {
			document = json.RawMessage(`{}`)
		}
		parsed, err := policy.ParseSourceDocument(document)
		if err == nil {
			err = budget.AddDocument(parsed)
		}
		if err != nil {
			c.releaseSources(result)
			return nil, err
		}
		source, err := c.acquireSourceDocument(parsed, document, organizationID, key, true)
		if err != nil {
			c.releaseSources(result)
			return nil, err
		}
		result = append(result, source)
		if err := budget.AddSource(source.value); err != nil {
			c.releaseSources(result)
			return nil, err
		}
	}
	return result, nil
}

func (c *keyConfigCache) acquireSource(raw []byte, organizationID string, key customerkey.Keys) (*sharedPolicySource, error) {
	document, err := policy.ParseSourceDocument(raw)
	if err != nil {
		return nil, err
	}
	return c.acquireSourceDocument(document, raw, organizationID, key, false)
}

func (c *keyConfigCache) acquireSourceDocument(document *policy.SourceDocument, raw []byte, organizationID string, key customerkey.Keys, routing bool) (*sharedPolicySource, error) {
	cacheKey := document.Digest()
	if document.Encrypted() {
		if !routing && !key.Matches(document.EncryptionKeyID()) {
			return nil, customerkey.ErrKey
		}
		cacheKey = organizationID + ":" + cacheKey
		if routing {
			cacheKey = "routing:" + cacheKey
		}
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrGatewayUnavailable
	}
	if source := c.sources[cacheKey]; source != nil {
		if id := source.value.RequiredEncryptionKeyID; id != "" && !key.Matches(id) {
			c.mu.Unlock()
			return nil, customerkey.ErrKey
		}
		source.refs++
		c.mu.Unlock()
		return source, nil
	}
	c.mu.Unlock()
	value, err, _ := c.sourceFlights.Do(cacheKey, func() (any, error) {
		c.mu.Lock()
		if source := c.sources[cacheKey]; source != nil {
			c.mu.Unlock()
			if id := source.value.RequiredEncryptionKeyID; id != "" && !key.Matches(id) {
				return nil, customerkey.ErrKey
			}
			return source.value, nil
		}
		// Compilation is bounded by available CPUs; misses do not create another queue.
		if c.closed || c.sourceBuilds >= runtime.GOMAXPROCS(0) {
			c.mu.Unlock()
			return nil, ErrGatewayUnavailable
		}
		c.sourceBuilds++
		c.mu.Unlock()
		defer func() { c.mu.Lock(); c.sourceBuilds--; c.mu.Unlock() }()
		if routing {
			return document.RoutingSource()
		}
		return document.Open(organizationID, key)
	})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrGatewayUnavailable
	}
	source := c.sources[cacheKey]
	if source == nil {
		// A coalesced build may outlive an evicted entry. Intern into a private
		// wrapper so a later acquisition cannot mutate its in-flight snapshot.
		compiled := *value.(*policy.Source)
		config := *compiled.Config
		compiled.Config = &config
		if raw == nil {
			raw = document.CanonicalJSON()
		}
		source = &sharedPolicySource{cacheKey: cacheKey, raw: bytes.Clone(raw), value: &compiled, pluginDigest: redactionPlanDigest(compiled.Config)}
		// Intern plugin sections before publishing the immutable source. A
		// limits-only revision must not keep a second identical PII dictionary.
		source.plan = c.internSourcePluginsLocked(compiled.Config)
		compiled.Rules = append([]policy.Rule{}, compiled.Rules...)
		for i := range compiled.Rules {
			rule := &compiled.Rules[i]
			value := *rule.Value
			config := *value.Config
			value.Config, rule.Value = &config, &value
			if plan := c.internSourcePluginsLocked(&config); plan != nil {
				source.rulePlans = append(source.rulePlans, plan)
			}
		}

		exclusive := *compiled.Config
		exclusive.Plugins = nil
		encoded, _ := json.Marshal(exclusive)
		source.bytes = int64(len(encoded))*4 + int64(len(raw))*4 + compiled.ExpressionBytes() + 512
		if c.sources == nil {
			c.sources = map[string]*sharedPolicySource{}
		}
		c.sources[cacheKey] = source
		c.bytes += source.bytes
	}
	source.refs++
	c.trimLocked()
	if c.bytes > keyConfigCacheBytes {
		c.releaseSourceLocked(source)
		return nil, ErrGatewayUnavailable
	}
	return source, nil
}

func (c *keyConfigCache) releaseSources(sources []*sharedPolicySource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, source := range sources {
		c.releaseSourceLocked(source)
	}
}
func (c *keyConfigCache) releaseSourceLocked(source *sharedPolicySource) {
	if source == nil {
		return
	}
	source.refs--
	if source.refs == 0 {
		for owner := range source.owners {
			delete(c.sourceOwners, owner)
		}
		if len(c.sourceOwners) == 0 {
			c.sourceOwners = nil
		}
		delete(c.sources, source.cacheKey)
		c.bytes -= source.bytes
		c.releasePlanLocked(source.plan)
		for _, plan := range source.rulePlans {
			c.releasePlanLocked(plan)
		}
	}
}

func (c *keyConfigCache) composeSources(sources []policy.ScopedSource, digest string) (*policy.Config, error) {
	c.mu.Lock()
	shared := c.policies[digest]
	c.mu.Unlock()
	if shared != nil {
		return shared.config, nil
	}
	return policy.ComposeSources(sources)
}

func (c *keyConfigCache) internSourcePluginsLocked(config *policy.Config) *sharedRedactionPlan {
	if config.Plugins == nil {
		return nil
	}
	if c.plans == nil {
		c.plans = map[[32]byte]*sharedRedactionPlan{}
	}
	digest := redactionPlanDigest(config)
	plan := c.plans[digest]
	if plan == nil {
		raw, _ := json.Marshal(config.Plugins)
		plan = &sharedRedactionPlan{owner: c, digest: digest, config: &policy.Config{Plugins: config.Plugins}, bytes: int64(len(raw))*4 + 256}
		c.plans[digest] = plan
		c.bytes += plan.bytes
	}
	plan.refs++
	config.Plugins = plan.config.Plugins
	return plan
}
