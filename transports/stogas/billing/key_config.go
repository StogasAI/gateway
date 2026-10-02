package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

const (
	keyConfigCacheTTL     = 3 * time.Minute
	keyConfigCacheBytes   = 96 << 20
	keyConfigFetchTimeout = 1500 * time.Millisecond
)

const keyConfigArguments = `
  $1::text,
  $2::text,
  $3::text,
  $4::text,
  $5::jsonb
`

type PolicyVersion struct {
	Scope    policy.Scope `json:"scope"`
	ID       string       `json:"id"`
	Revision int          `json:"revision"`
}

type PolicyVersions []PolicyVersion

func (v PolicyVersion) identity() string { return string(v.Scope) + ":" + v.ID }

type policySourceRecord struct {
	PolicyVersion
	// Omission means the caller pinned this exact revision. Null means empty.
	Source json.RawMessage `json:"source"`
}

// PolicySnapshot contains one immutable combination of applicable sources.
// A selected credential adds its own source without changing other candidates.
type PolicySnapshot struct {
	Versions   *PolicyVersions
	Config     *policy.Config
	Digest     string
	cacheBytes int64
	shared     *sharedKeyPolicy
	matchers   []*sharedRedactionPlan
	sourceRefs []*sharedPolicySource
}

// Versions identify the saved snapshot; they do not commit to policy content.
type KeyConfigSnapshot struct {
	PolicySnapshot
	Claims                *APIKeyClaims
	Generation            int
	CredentialsGeneration int
	Credentials           map[string][]CredentialSelection
	credentialRefs        []*sharedCredential
	conditionalSources    map[string]*sharedPolicySource
	credentialPolicies    map[string]*PolicySnapshot
	owner                 *keyConfigCache
	retained              bool
}

type keyConfigRow struct {
	Claims                *APIKeyClaims
	Result                string
	KeyID                 *string
	Generation            *int
	Sources               []policySourceRecord
	CredentialsGeneration *int
	Credentials           map[string][]CredentialSelection
	CredentialSources     []json.RawMessage
}

func (s *Service) ConfigForAPIKey(
	ctx context.Context,
	rawAPIKey string,
	claims *APIKeyClaims,
	encryptionKeys customerkey.Keys,
) (*KeyConfigSnapshot, error) {
	if s == nil || claims == nil {
		return nil, ErrInvalidAPIKey
	}
	apiKeyHash := hashAPIKey(rawAPIKey, s.apiKeyPepper)
	cacheKey := "api:" + apiKeyHash
	return s.cachedOrFetchKeyConfig(ctx, cacheKey, &apiKeyHash, nil, claims.KeyID, encryptionKeys, claims)
}

func (s *Service) ConfigForDashboard(
	ctx context.Context,
	credential *DashboardCredential,
	encryptionKeys customerkey.Keys,
) (*KeyConfigSnapshot, error) {
	if s == nil || credential == nil {
		return nil, ErrInvalidAPIKey
	}
	cacheKey := dashboardConfigCacheKey(credential)
	snapshot, err := s.cachedOrFetchKeyConfig(
		ctx,
		cacheKey,
		nil,
		credential,
		credential.KeyID,
		encryptionKeys,
		nil,
	)
	if err != nil {
		return nil, err
	}
	credential.Claims = snapshot.Claims
	if err := s.callerBackoff(snapshot.Claims, credential, time.Now()); err != nil {
		return snapshot, err
	}
	// Dashboard tokens sign the actor/session, not the caller-selected key ID.
	// Charge the shared organization only after resolving that key's authority.
	if retryAfter := s.localRequests.allow("org:"+snapshot.Claims.OrganizationID, time.Now()); retryAfter > 0 {
		return snapshot, &retryAfterError{delay: retryAfter}
	}
	return snapshot, nil
}

func (s *Service) cachedOrFetchKeyConfig(
	ctx context.Context,
	cacheKey string,
	hashedKey *string,
	dashboard *DashboardCredential,
	expectedKeyID string,
	encryptionKeys customerkey.Keys,
	claims *APIKeyClaims,
) (*KeyConfigSnapshot, error) {
	if snapshot, ok := s.keyConfigs.get(cacheKey, time.Now()); ok && snapshot.Config != nil {
		return snapshot, snapshot.checkEncryptionKeys(encryptionKeys)
	}
	value, err, _ := s.keyConfigFlights.Do(cacheKey, func() (any, error) {
		if snapshot, ok := s.keyConfigs.get(cacheKey, time.Now()); ok && snapshot.Config != nil {
			return snapshot, nil
		}
		return s.fetchKeyConfig(
			ctx,
			cacheKey,
			hashedKey,
			dashboard,
			expectedKeyID,
			encryptionKeys,
			claims,
		)
	})
	if err != nil {
		snapshot, _ := value.(*KeyConfigSnapshot)
		return snapshot, err
	}
	snapshot, ok := value.(*KeyConfigSnapshot)
	if !ok || snapshot == nil {
		return nil, ErrGatewayUnavailable
	}
	return snapshot, snapshot.checkEncryptionKeys(encryptionKeys)
}

func (s *PolicySnapshot) checkEncryptionKeys(key customerkey.Keys) error {
	if s != nil && s.Config != nil {
		if err := key.Validate(s.Config.EncryptionKeys); err != nil {
			return err
		}
		for _, id := range s.Config.RequiredEncryptionKeys {
			if !key.Matches(id) {
				return customerkey.ErrKey
			}
		}
	}
	return nil
}

func (s *Service) fetchKeyConfig(
	ctx context.Context,
	cacheKey string,
	hashedKey *string,
	dashboard *DashboardCredential,
	expectedKeyID string,
	encryptionKeys customerkey.Keys,
	claims *APIKeyClaims,
) (*KeyConfigSnapshot, error) {
	if s.db == nil || s.keyConfigQuery == "" {
		return nil, ErrGatewayUnavailable
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
	previous := s.keyConfigs.pinForRefresh(cacheKey)
	if previous != nil {
		defer s.keyConfigs.releaseSources(previous.sourceRefs)
		if claims == nil {
			claims = previous.Claims
		}
	}
	pins := s.keyConfigs.pinSourcesForClaims(claims, previous)
	defer s.keyConfigs.releaseSources(pins.sources)
	checkedAt := time.Now()
	err := s.db.pool.QueryRow(
		queryCtx,
		s.keyConfigQuery,
		hashedKey,
		dashboardKeyID,
		dashboardActorUserID,
		dashboardSessionID,
		pins.known,
	).Scan(
		&row.Result,
		&row.KeyID,
		&row.Generation,
		&row.Sources,
		&row.Claims,
		&row.CredentialsGeneration,
		&row.Credentials,
		&row.CredentialSources,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	if resultErr := authorizationResultError(row.Result); resultErr != nil {
		if row.Claims != nil && row.Claims.KeyID == expectedKeyID {
			snapshot := &KeyConfigSnapshot{Claims: row.Claims}
			s.keyConfigs.put(cacheKey, snapshot, time.Now())
			return snapshot, resultErr
		}
		return nil, resultErr
	}
	if row.Result != "ok" || row.KeyID == nil || *row.KeyID != expectedKeyID || row.Generation == nil || *row.Generation < 1 || row.Claims == nil {
		return nil, ErrGatewayUnavailable
	}
	if claims != nil && (row.Claims == nil || row.Claims.KeyID != claims.KeyID || row.Claims.OrganizationID != claims.OrganizationID || row.Claims.ResponsibleID != claims.ResponsibleID || derefString(row.Claims.GrantID) != derefString(claims.GrantID)) {
		return nil, ErrInvalidAPIKey
	}
	if len(row.Sources) < 2 || len(row.Sources) > 36 {
		return nil, ErrGatewayUnavailable
	}
	first, last := row.Sources[0], row.Sources[len(row.Sources)-1]
	if first.Scope != policy.OrganizationScope || first.ID != row.Claims.OrganizationID ||
		last.Scope != policy.KeyScope || last.ID != row.Claims.KeyID || last.Revision != *row.Generation {
		return nil, ErrGatewayUnavailable
	}
	sources, err := s.keyConfigs.acquireSourceDelta(row.Sources, row.Claims.OrganizationID, pins, encryptionKeys)
	if err != nil {
		if errors.Is(err, customerkey.ErrKey) || errors.Is(err, customerkey.ErrEnvelope) || errors.Is(err, policy.ErrSourceBudget) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	defer s.keyConfigs.releaseSources(sources)
	versions := make(PolicyVersions, len(sources))
	values := make([]policy.ScopedSource, len(sources))
	for i, source := range sources {
		versions[i] = row.Sources[i].PolicyVersion
		values[i] = policy.ScopedSource{Scope: versions[i].Scope, Value: source.value}
	}
	digest := policy.ChainDigest(values)
	compiled, err := s.keyConfigs.composeSources(values, digest)
	if err != nil {
		if errors.Is(err, policy.ErrSourceBudget) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	if err := restoreCredentialPolicySources(row.Credentials, pins, row.CredentialSources); err != nil {
		return nil, err
	}
	if row.CredentialsGeneration == nil || *row.CredentialsGeneration < 1 || validateCredentials(row.Claims, row.Credentials) != nil {
		return nil, ErrGatewayUnavailable
	}
	snapshot := &KeyConfigSnapshot{
		Claims: row.Claims,
		PolicySnapshot: PolicySnapshot{
			Versions: &versions, Config: compiled, Digest: digest,
			cacheBytes: compiled.CompositionBytes(),
			sourceRefs: sources,
		},
		Generation:            *row.Generation,
		CredentialsGeneration: *row.CredentialsGeneration,
		Credentials:           row.Credentials,
	}
	return s.keyConfigs.put(cacheKey, snapshot, checkedAt), nil
}

// A hold renews only the snapshot it actually checked, measured from before the
// database call. A delayed response cannot extend or evict a newer snapshot.
func (s *Service) confirmKeyConfig(apiKeyHash string, dashboard *DashboardCredential, snapshot *KeyConfigSnapshot, current bool, checkedAt time.Time) {
	key := "api:" + apiKeyHash
	var hash *string = &apiKeyHash
	expectedKeyID := snapshot.Claims.KeyID
	if dashboard != nil {
		copy := *dashboard
		dashboard = &copy
		key, hash = dashboardConfigCacheKey(dashboard), nil
	}
	if !s.keyConfigs.confirm(key, snapshot, current, checkedAt, time.Now()) {
		return
	}
	// Invalidation wins once and retains reusable compilation. Concurrent misses share this fetch, whose
	// existing timeout bounds its lifetime independently of the inference.
	s.keyConfigFlights.DoChan(key, func() (any, error) {
		if existing, ok := s.keyConfigs.get(key, time.Now()); ok && existing.Config != nil {
			return existing, nil
		}
		return s.fetchKeyConfig(context.Background(), key, hash, dashboard, expectedKeyID, nil, snapshot.Claims)
	})
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

func dashboardConfigCacheKey(credential *DashboardCredential) string {
	if credential == nil {
		return ""
	}
	return "dashboard-config:" + credential.ActorUserID + ":" + credential.SessionID + ":" + credential.KeyID
}
