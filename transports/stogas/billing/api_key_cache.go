package billing

import (
	"sync"
	"sync/atomic"
)

type verifiedAPIKeyShard struct {
	mu      sync.Mutex
	entries map[string]APIKeyClaims
}

// verifiedAPIKeyCache saves only immutable claims from valid signed keys.
// PostgreSQL still checks every request-time permission, limit, and balance.
type verifiedAPIKeyCache struct {
	hits    atomic.Uint64
	lookups atomic.Uint64
	shards  [localAdmissionShards]verifiedAPIKeyShard
}

func (c *verifiedAPIKeyCache) get(key string) (*APIKeyClaims, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	c.lookups.Add(1)
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	claims, ok := shard.entries[key]
	shard.mu.Unlock()
	if !ok {
		return nil, false
	}
	c.hits.Add(1)
	return cloneAPIKeyClaims(claims), true
}

func (c *verifiedAPIKeyCache) put(key string, claims *APIKeyClaims) {
	if c == nil || key == "" || claims == nil {
		return
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]APIKeyClaims)
	}
	if _, exists := shard.entries[key]; !exists {
		evictVerifiedAPIKeyEntry(shard.entries)
	}
	shard.entries[key] = *cloneAPIKeyClaims(*claims)
}

func (c *verifiedAPIKeyCache) entryCount() int {
	if c == nil {
		return 0
	}
	total := 0
	for index := range c.shards {
		shard := &c.shards[index]
		shard.mu.Lock()
		total += len(shard.entries)
		shard.mu.Unlock()
	}
	return total
}

func cloneAPIKeyClaims(claims APIKeyClaims) *APIKeyClaims {
	copy := claims
	if claims.GrantID != nil {
		grantID := *claims.GrantID
		copy.GrantID = &grantID
	}
	return &copy
}

func evictVerifiedAPIKeyEntry(entries map[string]APIKeyClaims) {
	if len(entries) < localAdmissionEntriesPerShard {
		return
	}
	for key := range entries {
		delete(entries, key)
		return
	}
}
