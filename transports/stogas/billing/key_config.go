package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

const (
	keyConfigCacheTTL     = 30 * time.Second
	keyConfigCacheEntries = 2048
	keyConfigFetchTimeout = 1500 * time.Millisecond
)

const keyConfigArguments = `
  $1::text,
  $2::text,
  $3::text,
  $4::text
`

type KeyConfigSnapshot struct {
	Config          *policy.Config
	Digest          string
	Generation      int
	RedactionPolicy *redaction.Policy
}

type keyConfigRow struct {
	Result          string
	KeyID           *string
	Generation      *int
	Digest          *string
	CompilerVersion *int
	CompiledConfig  json.RawMessage
}

type keyConfigCacheEntry struct {
	expiresAt time.Time
	snapshot  *KeyConfigSnapshot
}

// keyConfigCache is deliberately small and local. PostgreSQL validates the
// generation in the hold transaction, so this cache can only avoid a read; it
// cannot authorize stale policy.
type keyConfigCache struct {
	mu      sync.Mutex
	entries map[string]keyConfigCacheEntry
}

func (c *keyConfigCache) get(key string, now time.Time) (*KeyConfigSnapshot, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !now.Before(entry.expiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	return entry.snapshot, true
}

func (c *keyConfigCache) put(key string, snapshot *KeyConfigSnapshot, now time.Time) {
	if c == nil || key == "" || snapshot == nil || snapshot.Config == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]keyConfigCacheEntry)
	}
	if current, exists := c.entries[key]; exists && current.snapshot != nil && current.snapshot.Generation > snapshot.Generation {
		return
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= keyConfigCacheEntries {
		for candidate, entry := range c.entries {
			if !now.Before(entry.expiresAt) {
				delete(c.entries, candidate)
			}
		}
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= keyConfigCacheEntries {
		for candidate := range c.entries {
			delete(c.entries, candidate)
			break
		}
	}
	c.entries[key] = keyConfigCacheEntry{expiresAt: now.Add(keyConfigCacheTTL), snapshot: snapshot}
}

func (c *keyConfigCache) remove(key string) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

func (s *Service) ConfigForAPIKey(
	ctx context.Context,
	rawAPIKey string,
	claims *APIKeyClaims,
) (*KeyConfigSnapshot, error) {
	if s == nil || claims == nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	apiKeyHash := hashAPIKey(rawAPIKey, s.apiKeyPepper)
	cacheKey := "api:" + apiKeyHash
	return s.cachedOrFetchKeyConfig(ctx, cacheKey, cacheKey, &apiKeyHash, nil, claims.KeyID)
}

func (s *Service) ConfigForDashboard(
	ctx context.Context,
	credential *DashboardCredential,
) (*KeyConfigSnapshot, error) {
	if s == nil || credential == nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	cacheKey := dashboardConfigCacheKey(credential)
	return s.cachedOrFetchKeyConfig(
		ctx,
		cacheKey,
		dashboardAdmissionKey(credential),
		nil,
		credential,
		credential.KeyID,
	)
}

func (s *Service) cachedOrFetchKeyConfig(
	ctx context.Context,
	cacheKey string,
	rejectionCacheKey string,
	hashedKey *string,
	dashboard *DashboardCredential,
	expectedKeyID string,
) (*KeyConfigSnapshot, error) {
	if snapshot, ok := s.keyConfigs.get(cacheKey, time.Now()); ok {
		return snapshot, nil
	}
	value, err, _ := s.keyConfigFlights.Do(cacheKey, func() (any, error) {
		if snapshot, ok := s.keyConfigs.get(cacheKey, time.Now()); ok {
			return snapshot, nil
		}
		return s.fetchKeyConfig(
			ctx,
			cacheKey,
			rejectionCacheKey,
			hashedKey,
			dashboard,
			expectedKeyID,
		)
	})
	if err != nil {
		return nil, err
	}
	snapshot, ok := value.(*KeyConfigSnapshot)
	if !ok || snapshot == nil {
		return nil, &billingError{err: ErrGatewayUnavailable, statusCode: 503}
	}
	return snapshot, nil
}

func (s *Service) InvalidateAPIKeyConfig(rawAPIKey string) {
	if s == nil || rawAPIKey == "" {
		return
	}
	cacheKey := "api:" + hashAPIKey(rawAPIKey, s.apiKeyPepper)
	s.keyConfigs.remove(cacheKey)
	s.keyConfigFlights.Forget(cacheKey)
}

func (s *Service) InvalidateDashboardConfig(credential *DashboardCredential) {
	if s == nil {
		return
	}
	cacheKey := dashboardConfigCacheKey(credential)
	s.keyConfigs.remove(cacheKey)
	s.keyConfigFlights.Forget(cacheKey)
}

func (s *Service) fetchKeyConfig(
	ctx context.Context,
	cacheKey string,
	rejectionCacheKey string,
	hashedKey *string,
	dashboard *DashboardCredential,
	expectedKeyID string,
) (*KeyConfigSnapshot, error) {
	if s.db == nil || s.keyConfigQuery == "" {
		return nil, &billingError{err: ErrGatewayUnavailable, statusCode: 503}
	}
	queryCtx, cancel := context.WithTimeout(ctx, keyConfigFetchTimeout)
	defer cancel()
	var dashboardKeyID, dashboardActorUserID, dashboardSessionID *string
	if dashboard != nil {
		dashboardKeyID = &dashboard.KeyID
		dashboardActorUserID = &dashboard.ActorUserID
		dashboardSessionID = &dashboard.SessionID
	}
	row := keyConfigRow{}
	err := s.db.pool.QueryRow(
		queryCtx,
		s.keyConfigQuery,
		hashedKey,
		dashboardKeyID,
		dashboardActorUserID,
		dashboardSessionID,
	).Scan(
		&row.Result,
		&row.KeyID,
		&row.Generation,
		&row.Digest,
		&row.CompilerVersion,
		&row.CompiledConfig,
	)
	if err != nil {
		return nil, &billingError{err: fmt.Errorf("%w: %v", ErrGatewayUnavailable, err), statusCode: 503}
	}
	if resultErr := authorizationResultError(row.Result); resultErr != nil {
		s.rejections.record(rejectionCacheKey, row.Result, time.Now())
		return nil, resultErr
	}
	if row.Result != "ok" || row.KeyID == nil || *row.KeyID != expectedKeyID || row.Generation == nil || *row.Generation < 1 || row.Digest == nil || !validConfigDigest(*row.Digest) || row.CompilerVersion == nil || *row.CompilerVersion != policy.CompilerVersion {
		return nil, &billingError{err: ErrGatewayUnavailable, statusCode: 503}
	}
	compiled, err := policy.Parse(row.CompiledConfig)
	if err != nil {
		return nil, &billingError{err: fmt.Errorf("%w: %v", ErrGatewayUnavailable, err), statusCode: 503}
	}
	redactionPolicy, err := compileKeyRedactionPolicy(compiled)
	if err != nil {
		return nil, &billingError{err: fmt.Errorf("%w: %v", ErrGatewayUnavailable, err), statusCode: 503}
	}
	snapshot := &KeyConfigSnapshot{
		Config:          compiled,
		Digest:          *row.Digest,
		Generation:      *row.Generation,
		RedactionPolicy: redactionPolicy,
	}
	s.keyConfigs.put(cacheKey, snapshot, time.Now())
	return snapshot, nil
}

func validConfigDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func compileKeyRedactionPolicy(config *policy.Config) (*redaction.Policy, error) {
	patterns := []redaction.Pattern{
		redaction.PatternEmailAddress,
		redaction.PatternPhoneNumber,
		redaction.PatternSocialSecurityNumber,
		redaction.PatternCreditCardNumber,
		redaction.PatternCredentials,
		redaction.PatternPrivateKeys,
		redaction.PatternJSONWebTokens,
		redaction.PatternDatabaseURLs,
		redaction.PatternVendorTokens,
		redaction.PatternBankIdentifiers,
		redaction.PatternNationalIdentifiers,
		redaction.PatternHealthIdentifiers,
	}
	var custom []redaction.CustomPattern
	if config != nil && config.Plugins != nil && config.Plugins.StogasPIIRedaction != nil {
		for _, configured := range config.Plugins.StogasPIIRedaction.Patterns {
			switch configured {
			case "ip_address":
				patterns = append(patterns, redaction.PatternIPAddress)
			default:
				return nil, policy.ErrInvalidConfig
			}
		}
		for _, expression := range config.Plugins.StogasPIIRedaction.CustomPatterns {
			custom = append(custom, redaction.CustomPattern{Expression: expression})
		}
	}
	return redaction.CompilePolicy(redaction.Options{Patterns: patterns, CustomPatterns: custom})
}

func dashboardConfigCacheKey(credential *DashboardCredential) string {
	if credential == nil {
		return ""
	}
	return "dashboard-config:" + credential.ActorUserID + ":" + credential.SessionID + ":" + credential.KeyID
}
