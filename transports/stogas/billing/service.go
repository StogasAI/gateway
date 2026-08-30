package billing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
)

const (
	authorizeTimeout           = 1500 * time.Millisecond
	settleTimeout              = 2 * time.Second
	settleRetryWindow          = 90 * time.Second
	settleRetryInitialDelay    = 250 * time.Millisecond
	settleRetryMaxDelay        = 5 * time.Second
	settleRetryWorkerCount     = 64
	settleRetryQueueCapacity   = 8192
	holdSettlementExpiryBuffer = 10 * time.Minute

	// GatewayRequestLifetime bounds direct inference so reconciliation never races a live request.
	GatewayRequestLifetime = 60 * time.Minute
	ManagedUpstreamByok    = "stogas"
)

var (
	ErrAPIKeyDisabled      = errors.New("API key is disabled")
	ErrAPIKeyExpired       = errors.New("API key is expired")
	ErrGrantDisabled       = errors.New("grant is disabled")
	ErrInvalidAPIKey       = errors.New("invalid API key")
	ErrRequestAlreadyUsed  = errors.New("request already finalized; generate a new requestId")
	ErrAuthorizationClosed = errors.New("authorization already completed; generate a new requestId")
	ErrParamsMismatch      = errors.New("authorization already exists with different parameters")
	ErrInsufficientBalance = errors.New("insufficient balance")
	ErrAPIKeySpendLimit    = errors.New("API key spend limit exceeded")
	ErrAPIKeyRateLimit     = errors.New("API key rate limit exceeded")
	ErrAPIKeyConfigStale   = errors.New("API key configuration changed")
	ErrAPIKeyLimit         = errors.New("API key limit reached or disabled/expired")
	ErrByok                = errors.New("BYOK key is unavailable")
	ErrByokRequired        = errors.New("a BYOK key is required for this provider")
	ErrByokTarget          = errors.New("the assigned BYOK credential does not provide this deployment")
	ErrDashboardKeyDenied  = errors.New("API key is not available to this dashboard session")
	ErrGatewayUnavailable  = errors.New("gateway billing database unavailable")
	ErrAuthorizationAbsent = errors.New("Authorization not found")
	ErrLocalAdmissionLimit = errors.New("too many concurrent requests for this API key")
)

const authorizeHoldArguments = `
  $1::text,
  $2::text,
  $3::text,
  $4::text,
  $5::uuid,
  $6::uuid,
  $7::text,
  $8::text,
  $9::numeric,
  $10::timestamptz,
  $11::text,
  $12::jsonb,
  $13::text,
  $14::integer,
  $15::boolean
`

const settleHoldArguments = `
  $1::uuid,
  $2::text,
  $3::text,
  $4::text,
  $5::text,
  $6::numeric,
  $7::json
`

type authorizeRow struct {
	Result                       string
	HoldID                       *string
	UserID                       *string
	KeyID                        *string
	GrantID                      *string
	OrganizationID               *string
	WorkspaceID                  *string
	AuthorizedBilledCostUSDAtoms *string
	CreatedAt                    *time.Time
	ExpiresAt                    *time.Time
	AvailableBalanceUSDAtoms     *string
	UpstreamByok                 *string
	UpstreamByokCiphertext       *string
}

type settleRow struct {
	Result                    string
	BilledCostUSDAtoms        *string
	BalanceAdjustmentUSDAtoms *string
	AvailableBalanceUSDAtoms  *string
}

type Authorization struct {
	AuthorizedBilledCostUSDAtoms *big.Int
	AvailableBalanceUSDAtoms     *big.Int
	CreatedAt                    time.Time
	GrantID                      *string
	KeyID                        string
	OrganizationID               string
	ProductKey                   string
	ProviderKey                  string
	RequestID                    string
	UserID                       string
	WorkspaceID                  string
	UpstreamByok                 string
	UpstreamByokSecret           string
	AzureBinding                 *AzureBinding
	UpstreamTargetJSON           string
}

type UpstreamTarget struct {
	DeploymentType     string `json:"deploymentType"`
	Hosting            string `json:"hosting"`
	Model              string `json:"model"`
	ModelFormat        string `json:"modelFormat"`
	ModelVersion       string `json:"modelVersion"`
	ProcessingLocation string `json:"processingLocation"`
	StorageLocation    string `json:"storageLocation"`
}

type AzureBinding struct {
	AccountLocation    string `json:"accountLocation"`
	DeploymentName     string `json:"deploymentName"`
	DeploymentType     string `json:"deploymentType"`
	Endpoint           string `json:"endpoint"`
	Hosting            string `json:"hosting"`
	ModelFormat        string `json:"modelFormat"`
	ModelName          string `json:"modelName"`
	ModelVersion       string `json:"modelVersion"`
	ProcessingLocation string `json:"processingLocation"`
	StorageLocation    string `json:"storageLocation"`
	TokenScope         string `json:"tokenScope"`
}

type azureBoundCiphertext struct {
	Binding              AzureBinding `json:"binding"`
	CredentialCiphertext string       `json:"credentialCiphertext"`
	Schema               string       `json:"schema"`
}

func parseAzureBoundCiphertext(raw string) (azureBoundCiphertext, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	value := azureBoundCiphertext{}
	if err := decoder.Decode(&value); err != nil {
		return azureBoundCiphertext{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return azureBoundCiphertext{}, errors.New("invalid Azure binding: trailing JSON")
	}
	if value.Schema != "stogas.azure-bound.v2" ||
		value.CredentialCiphertext == "" ||
		value.Binding.AccountLocation == "" ||
		value.Binding.DeploymentName == "" ||
		value.Binding.DeploymentType == "" ||
		value.Binding.Endpoint == "" ||
		value.Binding.Hosting == "" ||
		value.Binding.ModelFormat == "" ||
		value.Binding.ModelName == "" ||
		value.Binding.ModelVersion == "" ||
		value.Binding.ProcessingLocation == "" ||
		value.Binding.StorageLocation == "" ||
		value.Binding.TokenScope == "" {
		return azureBoundCiphertext{}, errors.New("invalid Azure binding")
	}
	return value, nil
}

type passthroughCredential struct {
	Hash   string
	Secret string
}

type Service struct {
	db                        *GatewayDB
	authorizeHoldQuery        string
	keyConfigQuery            string
	keyConfigs                keyConfigCache
	keyConfigFlights          singleflight.Group
	localAuthorizations       *localAuthorizationLimiter
	localRequests             localRequestLimiter
	apiKeys                   verifiedAPIKeyCache
	rejections                authorizationRejectionCache
	retryInitialDelay         time.Duration
	retryMaxDelay             time.Duration
	retryWindow               time.Duration
	retryActive               atomic.Int64
	retryDeferred             atomic.Int64
	retryLastDeferredAt       atomic.Int64
	retryMu                   sync.Mutex
	retryQueue                chan settlementRetryTask
	retryWorkerCount          int
	retryWorkersStarted       bool
	retryWorkersWG            sync.WaitGroup
	retryClosed               bool
	settleFunc                settleHoldFunc
	tinybird                  *TinybirdClient
	settleHoldQuery           string
	settleHoldWithOutboxQuery string
	apiKeyPepper              string
	inferenceTokenPublicKey   ed25519.PublicKey
	byok                      *byokDecryptor
}

type settlementRetryTask struct {
	authorization        Authorization
	holdParamsHash       string
	upstreamCostUSDAtoms string
	requestEventPayload  string
	writeOutbox          bool
	deadline             time.Time
}

type settleHoldFunc func(
	ctx context.Context,
	authorization *Authorization,
	holdParamsHash string,
	upstreamCostUSDAtoms string,
	requestEventPayload string,
	writeOutbox bool,
) error

type DiagnosticsSnapshot struct {
	Database                      *DatabaseDiagnostics      `json:"database,omitempty"`
	LocalAdmission                LocalAdmissionDiagnostics `json:"localAdmission"`
	SettlementRetries             int64                     `json:"settlementRetries"`
	SettlementRetryDeferrals      int64                     `json:"settlementRetryDeferrals"`
	SettlementRetryLastDeferredAt *time.Time                `json:"settlementRetryLastDeferredAt,omitempty"`
	SettlementRetryQueueCapacity  int                       `json:"settlementRetryQueueCapacity"`
	SettlementRetryQueueDepth     int                       `json:"settlementRetryQueueDepth"`
	Tinybird                      *TinybirdDiagnostics      `json:"tinybird,omitempty"`
}

type billingError struct {
	err        error
	statusCode int
}

func (e *billingError) Error() string { return e.err.Error() }
func (e *billingError) Unwrap() error { return e.err }
func (e *billingError) StatusCode() int {
	return e.statusCode
}

type settleResultError struct {
	err        error
	result     string
	statusCode int
}

func (e *settleResultError) Error() string { return e.err.Error() }
func (e *settleResultError) Unwrap() error { return e.err }
func (e *settleResultError) StatusCode() int {
	return e.statusCode
}

func NewService(
	ctx context.Context,
	databaseURL string,
	databaseSchema string,
	apiKeyPepper string,
	byokEncryptionSecret string,
	inferenceTokenPublicKey string,
	databasePool DatabasePoolConfig,
	tinybird *TinybirdClient,
) (*Service, error) {
	publicKey, err := parseInferenceTokenPublicKey(inferenceTokenPublicKey)
	if err != nil {
		return nil, err
	}
	byok, err := newByokDecryptor(byokEncryptionSecret)
	if err != nil {
		return nil, err
	}
	db, err := NewGatewayDB(ctx, databaseURL, databaseSchema, databasePool)
	if err != nil {
		return nil, err
	}

	return &Service{
		db:                        db,
		authorizeHoldQuery:        db.functionQuery("authorize_gateway_hold", authorizeHoldArguments),
		keyConfigQuery:            db.functionQuery("gateway_api_key_config", keyConfigArguments),
		inferenceTokenPublicKey:   publicKey,
		localAuthorizations:       newLocalAuthorizationLimiter(databasePool.MaxConns),
		tinybird:                  tinybird,
		settleHoldQuery:           db.functionQuery("settle_gateway_hold", settleHoldArguments),
		settleHoldWithOutboxQuery: db.functionQuery("settle_gateway_hold_with_outbox", settleHoldArguments),
		apiKeyPepper:              apiKeyPepper,
		byok:                      byok,
	}, nil
}

func (s *Service) Close() {
	s.retryMu.Lock()
	if !s.retryClosed {
		s.retryClosed = true
		if s.retryQueue != nil {
			close(s.retryQueue)
		}
	}
	s.retryMu.Unlock()
	s.retryWorkersWG.Wait()
	if s.tinybird != nil {
		s.tinybird.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}

func (s *Service) ProbeDatabase(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("gateway database is unavailable")
	}
	return s.db.Ping(ctx)
}

func (s *Service) Diagnostics() DiagnosticsSnapshot {
	if s == nil {
		return DiagnosticsSnapshot{}
	}
	retryQueueDepth, retryQueueCapacity := s.retryQueueDiagnostics()
	var retryLastDeferredAt *time.Time
	if unixMilliseconds := s.retryLastDeferredAt.Load(); unixMilliseconds > 0 {
		value := time.UnixMilli(unixMilliseconds).UTC()
		retryLastDeferredAt = &value
	}
	return DiagnosticsSnapshot{
		Database:                      s.db.Diagnostics(),
		LocalAdmission:                localAdmissionDiagnostics(&s.localRequests, s.localAuthorizations, &s.rejections, &s.apiKeys),
		SettlementRetries:             s.retryActive.Load(),
		SettlementRetryDeferrals:      s.retryDeferred.Load(),
		SettlementRetryLastDeferredAt: retryLastDeferredAt,
		SettlementRetryQueueCapacity:  retryQueueCapacity,
		SettlementRetryQueueDepth:     retryQueueDepth,
		Tinybird:                      s.tinybird.Diagnostics(),
	}
}

func (s *Service) retryQueueDiagnostics() (int, int) {
	s.retryMu.Lock()
	defer s.retryMu.Unlock()
	if s.retryQueue == nil {
		return 0, settleRetryQueueCapacity
	}
	return len(s.retryQueue), cap(s.retryQueue)
}

func (s *Service) parseVerifiedAPIKey(rawAPIKey string) (*APIKeyClaims, string, string, error) {
	if s == nil || !hasSignedAPIKeyShape(rawAPIKey) {
		return nil, "", "", errInvalidAPIKeyShape
	}
	apiKeyHash := hashAPIKey(rawAPIKey, s.apiKeyPepper)
	cacheKey := "api:" + apiKeyHash
	if claims, ok := s.apiKeys.get(cacheKey); ok {
		return claims, apiKeyHash, cacheKey, nil
	}
	claims, err := parseSignedAPIKey(rawAPIKey, s.apiKeyPepper)
	if err != nil {
		return nil, "", cacheKey, err
	}
	s.apiKeys.put(cacheKey, claims)
	return claims, apiKeyHash, cacheKey, nil
}

func (s *Service) ParseAPIKey(rawAPIKey string) (*APIKeyClaims, error) {
	if s == nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	claims, _, cacheKey, err := s.parseVerifiedAPIKey(rawAPIKey)
	if err != nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	if retryAfter := s.localRequests.allow(cacheKey, time.Now()); retryAfter > 0 {
		return nil, &billingError{err: ErrAPIKeyRateLimit, statusCode: 429}
	}
	if result, _, ok := s.rejections.get(cacheKey, time.Now()); ok {
		return nil, authorizationResultError(result)
	}
	return claims, nil
}

func (s *Service) ParseDashboardCredential(raw string) (*DashboardCredential, error) {
	if s == nil || len(s.inferenceTokenPublicKey) != ed25519.PublicKeySize {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	credential, err := parseDashboardCredential(raw, s.inferenceTokenPublicKey, time.Now())
	if err != nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	cacheKey := dashboardAdmissionKey(credential)
	if retryAfter := s.localRequests.allow(cacheKey, time.Now()); retryAfter > 0 {
		return nil, &billingError{err: ErrAPIKeyRateLimit, statusCode: 429}
	}
	if result, _, ok := s.rejections.get(cacheKey, time.Now()); ok {
		return nil, authorizationResultError(result)
	}
	return credential, nil
}

func (s *Service) AuthorizeRequestWithPassthrough(
	ctx context.Context,
	rawAPIKey string,
	requestID string,
	providerKey string,
	productKey string,
	estimatedUpstreamCostUSDAtoms string,
	configGeneration int,
	passthroughSecret string,
	upstreamTarget *UpstreamTarget,
	requestLifetime time.Duration,
	singleUse bool,
) (*Authorization, error) {
	return s.authorizeRequestWithDuration(ctx, rawAPIKey, requestID, providerKey, productKey, estimatedUpstreamCostUSDAtoms, configGeneration, passthroughSecret, upstreamTarget, requestLifetime, singleUse)
}

func (s *Service) authorizeRequestWithDuration(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, estimatedUpstreamCostUSDAtoms string, configGeneration int, passthroughSecret string, upstreamTarget *UpstreamTarget, requestLifetime time.Duration, singleUse bool) (*Authorization, error) {
	claims, apiKeyHash, cacheKey, err := s.parseVerifiedAPIKey(rawAPIKey)
	if err != nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	if result, _, ok := s.rejections.get(cacheKey, time.Now()); ok {
		return nil, authorizationResultError(result)
	}
	var passthrough *passthroughCredential
	if passthroughSecret != "" {
		credentialHash, hashErr := s.byok.credentialHash(
			passthroughSecret,
			claims.OrganizationID,
			claims.WorkspaceID,
			providerKey,
		)
		if hashErr != nil {
			return nil, &billingError{err: ErrByok, statusCode: 503}
		}
		passthrough = &passthroughCredential{Hash: credentialHash, Secret: passthroughSecret}
	}

	return s.authorizeResolvedRequest(
		ctx,
		apiKeyHash,
		cacheKey,
		nil,
		claims,
		requestID,
		providerKey,
		productKey,
		estimatedUpstreamCostUSDAtoms,
		configGeneration,
		passthrough,
		upstreamTarget,
		requestLifetime,
		singleUse,
	)
}

func (s *Service) AuthorizeDashboardRequestWithDuration(
	ctx context.Context,
	credential *DashboardCredential,
	requestID string,
	providerKey string,
	productKey string,
	estimatedUpstreamCostUSDAtoms string,
	configGeneration int,
	upstreamTarget *UpstreamTarget,
	requestLifetime time.Duration,
) (*Authorization, error) {
	if credential == nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	return s.authorizeResolvedRequest(
		ctx,
		"",
		dashboardAdmissionKey(credential),
		credential,
		nil,
		requestID,
		providerKey,
		productKey,
		estimatedUpstreamCostUSDAtoms,
		configGeneration,
		nil,
		upstreamTarget,
		requestLifetime,
		true,
	)
}

func (s *Service) authorizeResolvedRequest(
	ctx context.Context,
	apiKeyHash string,
	rejectionCacheKey string,
	dashboard *DashboardCredential,
	claims *APIKeyClaims,
	requestID string,
	providerKey string,
	productKey string,
	estimatedUpstreamCostUSDAtoms string,
	configGeneration int,
	passthrough *passthroughCredential,
	upstreamTarget *UpstreamTarget,
	requestLifetime time.Duration,
	singleUse bool,
) (*Authorization, error) {
	expiresAt := requestHoldExpiresAt(time.Now().UTC(), requestLifetime)
	holdID, err := newUUIDV7String()
	if err != nil {
		return nil, fmt.Errorf("generate hold id: %w", err)
	}
	passthroughHash := ""
	if passthrough != nil {
		passthroughHash = passthrough.Hash
	}
	upstreamTargetJSON := ""
	if upstreamTarget != nil {
		encoded, marshalErr := json.Marshal(upstreamTarget)
		if marshalErr != nil {
			return nil, &billingError{err: ErrByokTarget, statusCode: 400}
		}
		upstreamTargetJSON = string(encoded)
	}
	holdParamsHash := createHoldParamsHash(providerKey, productKey, upstreamTargetJSON)
	releaseAuthorization, acquired := s.localAuthorizations.acquire(rejectionCacheKey)
	if !acquired {
		return nil, &billingError{err: ErrLocalAdmissionLimit, statusCode: 429}
	}
	defer releaseAuthorization()

	row := authorizeRow{}
	queryCtx, cancel := context.WithTimeout(ctx, authorizeTimeout)
	defer cancel()
	var dashboardKeyID, dashboardActorUserID, dashboardSessionID *string
	if dashboard != nil {
		dashboardKeyID = &dashboard.KeyID
		dashboardActorUserID = &dashboard.ActorUserID
		dashboardSessionID = &dashboard.SessionID
	}
	var apiKeyHashValue *string
	if apiKeyHash != "" {
		apiKeyHashValue = &apiKeyHash
	}
	err = s.db.pool.QueryRow(
		queryCtx,
		s.authorizeHoldQuery,
		apiKeyHashValue,
		dashboardKeyID,
		dashboardActorUserID,
		dashboardSessionID,
		requestID,
		holdID,
		providerKey,
		productKey,
		estimatedUpstreamCostUSDAtoms,
		expiresAt,
		holdParamsHash,
		nullableString(upstreamTargetJSON),
		nullableString(passthroughHash),
		configGeneration,
		singleUse,
	).Scan(
		&row.Result, &row.HoldID, &row.UserID, &row.KeyID, &row.GrantID, &row.OrganizationID, &row.WorkspaceID, &row.AuthorizedBilledCostUSDAtoms, &row.CreatedAt, &row.ExpiresAt, &row.AvailableBalanceUSDAtoms, &row.UpstreamByok, &row.UpstreamByokCiphertext,
	)
	if err != nil {
		return nil, &billingError{err: fmt.Errorf("%w: %v", ErrGatewayUnavailable, err), statusCode: 503}
	}

	if resultErr := authorizationResultError(row.Result); resultErr != nil {
		s.rejections.record(rejectionCacheKey, row.Result, time.Now())
		return nil, resultErr
	}

	switch row.Result {
	case "ok":
		keyID := derefString(row.KeyID)
		organizationID := derefString(row.OrganizationID)
		userID := derefString(row.UserID)
		workspaceID := derefString(row.WorkspaceID)
		grantID := row.GrantID
		if dashboard != nil {
			if keyID != dashboard.KeyID || userID != dashboard.ActorUserID {
				s.rejections.record(rejectionCacheKey, "invalid_key", time.Now())
				return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
			}
		} else {
			if claims == nil ||
				keyID != claims.KeyID ||
				organizationID != claims.OrganizationID ||
				userID != claims.ResponsibleID ||
				workspaceID != claims.WorkspaceID ||
				!equalOptionalString(grantID, claims.GrantID) {
				s.rejections.record(rejectionCacheKey, "invalid_key", time.Now())
				return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
			}
		}
		upstreamByok := derefString(row.UpstreamByok)
		authorizedBilledCostUSDAtoms, amountErr := parseDatabaseMoney(row.AuthorizedBilledCostUSDAtoms, "authorized billed cost")
		if amountErr != nil {
			return nil, &billingError{err: fmt.Errorf("%w: %v", ErrGatewayUnavailable, amountErr), statusCode: 503}
		}
		availableBalanceUSDAtoms, amountErr := parseDatabaseMoney(row.AvailableBalanceUSDAtoms, "available balance")
		if amountErr != nil {
			return nil, &billingError{err: fmt.Errorf("%w: %v", ErrGatewayUnavailable, amountErr), statusCode: 503}
		}
		authorization := &Authorization{AuthorizedBilledCostUSDAtoms: authorizedBilledCostUSDAtoms, AvailableBalanceUSDAtoms: availableBalanceUSDAtoms, CreatedAt: derefTime(row.CreatedAt), GrantID: grantID, KeyID: keyID, OrganizationID: organizationID, ProductKey: productKey, ProviderKey: providerKey, RequestID: requestID, UpstreamByok: upstreamByok, UpstreamTargetJSON: upstreamTargetJSON, UserID: userID, WorkspaceID: workspaceID}
		if upstreamByok == "" {
			return authorization, &billingError{err: ErrByok, statusCode: 503}
		}
		ciphertext := derefString(row.UpstreamByokCiphertext)
		if ciphertext != "" {
			if upstreamByok == ManagedUpstreamByok || validCredentialHash(upstreamByok) {
				return authorization, &billingError{err: ErrByok, statusCode: 503}
			}
			if providerKey == "azure" {
				bound, parseErr := parseAzureBoundCiphertext(ciphertext)
				if parseErr != nil {
					return authorization, &billingError{err: ErrByok, statusCode: 503}
				}
				ciphertext = bound.CredentialCiphertext
				authorization.AzureBinding = &bound.Binding
			}
			authorization.UpstreamByokSecret, err = s.byok.decrypt(
				ciphertext,
				upstreamByok,
				organizationID,
				workspaceID,
				providerKey,
			)
			if err != nil {
				return authorization, &billingError{err: ErrByok, statusCode: 503}
			}
		} else if validCredentialHash(upstreamByok) {
			if passthrough == nil || !hmac.Equal([]byte(upstreamByok), []byte(passthrough.Hash)) {
				return authorization, &billingError{err: ErrByok, statusCode: 503}
			}
			authorization.UpstreamByokSecret = passthrough.Secret
		} else if upstreamByok != ManagedUpstreamByok {
			return authorization, &billingError{err: ErrByok, statusCode: 503}
		}
		s.rejections.clear(rejectionCacheKey)
		return authorization, nil
	default:
		return nil, fmt.Errorf("unknown hold authorization result: %s", row.Result)
	}
}

func authorizationResultError(result string) error {
	switch result {
	case "invalid_key", "hold_missing":
		return &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	case "usage_exists":
		return &billingError{err: ErrRequestAlreadyUsed, statusCode: 409}
	case "params_mismatch":
		return &billingError{err: ErrParamsMismatch, statusCode: 409}
	case "authorization_closed":
		return &billingError{err: ErrAuthorizationClosed, statusCode: 409}
	case "expired":
		return &billingError{err: ErrRequestAlreadyUsed, statusCode: 409}
	case "insufficient_balance":
		return &billingError{err: ErrInsufficientBalance, statusCode: 402}
	case "key_disabled":
		return &billingError{err: ErrAPIKeyDisabled, statusCode: 403}
	case "grant_disabled":
		return &billingError{err: ErrGrantDisabled, statusCode: 403}
	case "byok_disabled":
		return &billingError{err: ErrByok, statusCode: 503}
	case "byok_required":
		return &billingError{err: ErrByokRequired, statusCode: 400}
	case "byok_target_unavailable":
		return &billingError{err: ErrByokTarget, statusCode: 400}
	case "byok_not_allowed":
		return &billingError{err: errors.New("pass-through BYOK is not allowed by this API key"), statusCode: 400}
	case "key_expired":
		return &billingError{err: ErrAPIKeyExpired, statusCode: 403}
	case "dashboard_forbidden":
		return &billingError{err: ErrDashboardKeyDenied, statusCode: 403}
	case "key_spend_limit":
		return &billingError{err: ErrAPIKeySpendLimit, statusCode: 402}
	case "key_rate_limited":
		return &billingError{err: ErrAPIKeyRateLimit, statusCode: 429}
	case "config_stale":
		return &billingError{err: ErrAPIKeyConfigStale, statusCode: 503}
	case "api_key_limit":
		return &billingError{err: ErrAPIKeyLimit, statusCode: 402}
	case "invalid_amount":
		return &billingError{err: errors.New("invalid estimated upstream cost"), statusCode: 400}
	default:
		return nil
	}
}

func apiKeyRejectionCacheKey(rawAPIKey string, apiKeyPepper string) string {
	return "api:" + hashAPIKey(rawAPIKey, apiKeyPepper)
}

func dashboardAdmissionKey(credential *DashboardCredential) string {
	if credential == nil {
		return ""
	}
	// KeyID is an unsigned database selector and cannot scope local admission.
	return "dashboard:" + credential.ActorUserID + ":" + credential.SessionID
}

func (s *Service) FinalizeRequest(ctx context.Context, authorization *Authorization, event RequestEvent) error {
	if authorization == nil {
		return nil
	}

	holdParamsHash := createHoldParamsHash(authorization.ProviderKey, authorization.ProductKey, authorization.UpstreamTargetJSON)
	event.holdParamsHash = holdParamsHash
	upstreamCostRaw := event.UpstreamCostUSDAtoms
	if upstreamCostRaw == "" {
		upstreamCostRaw = ZeroChargeUSDAtoms
	}
	upstreamCostUSDAtoms, err := ParseUSDAtoms(upstreamCostRaw)
	if err != nil {
		return fmt.Errorf("invalid upstream cost: %w", err)
	}
	event.UpstreamCostUSDAtoms = upstreamCostUSDAtoms.String()
	billedCostUSDAtoms := calculateBilledCostUSDAtoms(authorization, upstreamCostUSDAtoms)
	event.BilledCostUSDAtoms = billedCostUSDAtoms.String()
	event.StogasBillingStatus = calculateSettlementStatus(authorization.AuthorizedBilledCostUSDAtoms, authorization.AvailableBalanceUSDAtoms, billedCostUSDAtoms)
	requestEventPayload, err := encodeGatewayRequestEvent(event)
	if err != nil {
		return err
	}

	writeOutbox := true
	if s.tinybird != nil {
		writeOutbox = s.tinybird.AppendGatewayRequest(ctx, event) != nil
	}

	if err := s.settleOnce(ctx, authorization, holdParamsHash, upstreamCostUSDAtoms.String(), requestEventPayload, writeOutbox); err != nil {
		if isPermanentSettleError(err) {
			return nil
		}
		if !s.startSettleRetry(authorization, holdParamsHash, upstreamCostUSDAtoms.String(), requestEventPayload, writeOutbox) && writeOutbox {
			s.publishUncommittedFallback(authorization, event)
		}
		return nil
	}

	return nil
}

func (s *Service) startSettleRetry(
	authorization *Authorization,
	holdParamsHash string,
	upstreamCostUSDAtoms string,
	requestEventPayload string,
	writeOutbox bool,
) bool {
	if authorization == nil {
		return false
	}
	task := settlementRetryTask{
		authorization: Authorization{
			KeyID:       authorization.KeyID,
			ProductKey:  authorization.ProductKey,
			ProviderKey: authorization.ProviderKey,
			RequestID:   authorization.RequestID,
		},
		holdParamsHash:       holdParamsHash,
		upstreamCostUSDAtoms: upstreamCostUSDAtoms,
		requestEventPayload:  requestEventPayload,
		writeOutbox:          writeOutbox,
		deadline:             time.Now().Add(durationOrDefault(s.retryWindow, settleRetryWindow)),
	}

	s.retryMu.Lock()
	defer s.retryMu.Unlock()
	if s.retryClosed {
		s.recordSettleRetryDeferral()
		return false
	}
	if s.retryQueue == nil {
		s.retryQueue = make(chan settlementRetryTask, settleRetryQueueCapacity)
	}
	s.startRetryWorkersLocked()
	select {
	case s.retryQueue <- task:
		return true
	default:
		s.recordSettleRetryDeferral()
		return false
	}
}

func (s *Service) recordSettleRetryDeferral() {
	s.retryDeferred.Add(1)
	s.retryLastDeferredAt.Store(time.Now().UTC().UnixMilli())
}

func (s *Service) startRetryWorkersLocked() {
	if s.retryWorkersStarted {
		return
	}
	s.retryWorkersStarted = true
	workers := s.retryWorkerCount
	if workers <= 0 {
		workers = settleRetryWorkerCount
	}
	queue := s.retryQueue
	s.retryWorkersWG.Add(workers)
	for range workers {
		go func() {
			defer s.retryWorkersWG.Done()
			for task := range queue {
				s.retryActive.Add(1)
				s.retrySettleTask(task)
				s.retryActive.Add(-1)
			}
		}()
	}
}

// settleOnce sends the upstream cost basis. PostgreSQL derives billed cost from
// the hold's frozen credential source and verifies the request-event payload.
func (s *Service) settleOnce(ctx context.Context, authorization *Authorization, holdParamsHash string, upstreamCostUSDAtoms string, requestEventPayload string, writeOutbox bool) error {
	if s.settleFunc != nil {
		return s.settleFunc(ctx, authorization, holdParamsHash, upstreamCostUSDAtoms, requestEventPayload, writeOutbox)
	}

	queryCtx, cancel := context.WithTimeout(ctx, settleTimeout)
	defer cancel()

	row := settleRow{}
	query := s.settleHoldQuery
	if writeOutbox {
		query = s.settleHoldWithOutboxQuery
	}
	err := s.db.pool.QueryRow(
		queryCtx,
		query,
		authorization.RequestID,
		authorization.KeyID,
		authorization.ProviderKey,
		authorization.ProductKey,
		holdParamsHash,
		upstreamCostUSDAtoms,
		requestEventPayload,
	).Scan(&row.Result, &row.BilledCostUSDAtoms, &row.BalanceAdjustmentUSDAtoms, &row.AvailableBalanceUSDAtoms)
	if err != nil {
		return fmt.Errorf("settle gateway hold: %w", err)
	}

	switch row.Result {
	case "complete", "under_reserved", "negative_balance", "already_settled":
		return nil
	case "hold_not_found":
		return &settleResultError{err: ErrAuthorizationAbsent, result: row.Result, statusCode: 404}
	case "params_mismatch":
		return &settleResultError{err: ErrAuthorizationClosed, result: row.Result, statusCode: 409}
	case "invalid_amount", "invalid_payload", "payload_mismatch":
		return &settleResultError{err: errors.New("invalid settlement payload"), result: row.Result, statusCode: 400}
	default:
		return fmt.Errorf("unknown settlement result: %s", row.Result)
	}
}

func (s *Service) retrySettle(authorization *Authorization, holdParamsHash string, upstreamCostUSDAtoms string, requestEventPayload string, writeOutbox bool) {
	if authorization == nil {
		return
	}
	s.retrySettleTask(settlementRetryTask{
		authorization:        *authorization,
		holdParamsHash:       holdParamsHash,
		upstreamCostUSDAtoms: upstreamCostUSDAtoms,
		requestEventPayload:  requestEventPayload,
		writeOutbox:          writeOutbox,
		deadline:             time.Now().Add(durationOrDefault(s.retryWindow, settleRetryWindow)),
	})
}

func (s *Service) retrySettleTask(task settlementRetryTask) {
	delay := durationOrDefault(s.retryInitialDelay, settleRetryInitialDelay)
	maxDelay := durationOrDefault(s.retryMaxDelay, settleRetryMaxDelay)
	retryCtx, cancel := context.WithDeadline(context.Background(), task.deadline)
	defer cancel()
	for retryCtx.Err() == nil {
		wait := jitteredSettleRetryDelay(delay)
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-retryCtx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			break
		}
		if retryCtx.Err() != nil {
			break
		}
		err := s.settleOnce(retryCtx, &task.authorization, task.holdParamsHash, task.upstreamCostUSDAtoms, task.requestEventPayload, task.writeOutbox)
		if err == nil {
			return
		}
		if isPermanentSettleError(err) {
			return
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}

	if task.writeOutbox {
		event, err := decodeGatewayRequestEvent(task.requestEventPayload)
		if err == nil {
			s.publishUncommittedFallbackAfterRetry(&task.authorization, task.holdParamsHash, event)
		}
	}
}

func jitteredSettleRetryDelay(delay time.Duration) time.Duration {
	if delay <= time.Nanosecond {
		return delay
	}
	half := delay / 2
	return half + time.Duration(rand.Int64N(int64(delay-half)+1))
}

func isPermanentSettleError(err error) bool {
	var typed *settleResultError
	return errors.As(err, &typed)
}

func durationOrDefault(value time.Duration, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func requestHoldExpiresAt(now time.Time, requestLifetime time.Duration) time.Time {
	return now.Add(durationOrDefault(requestLifetime, GatewayRequestLifetime) + holdSettlementExpiryBuffer)
}

func encodeGatewayRequestEvent(event RequestEvent) (string, error) {
	if event.Pricing == nil {
		event.Pricing = EventPricing{}
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("marshal gateway request log payload: %w", err)
	}
	if len(encoded)+1 > tinybirdMaxEventBytes {
		return "", fmt.Errorf("gateway request log payload is %d bytes, limit is %d", len(encoded), tinybirdMaxEventBytes-1)
	}
	return string(encoded), nil
}

func decodeGatewayRequestEvent(payload string) (RequestEvent, error) {
	event := RequestEvent{}
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		return RequestEvent{}, fmt.Errorf("unmarshal gateway request log payload: %w", err)
	}
	pricing, analyticsQuantities, err := validateEventPricing(event.Pricing)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("validate gateway request log payload: %w", err)
	}
	event.Pricing = pricing
	event.analyticsQuantities = analyticsQuantities
	event.CacheReadSavingsUSDAtoms, err = requestOptionalUSDAtoms(
		event.CacheReadSavingsUSDAtoms,
		"cache read savings",
	)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("validate gateway request log payload: %w", err)
	}
	event.CacheWriteOverheadUSDAtoms, err = requestOptionalUSDAtoms(
		event.CacheWriteOverheadUSDAtoms,
		"cache write overhead",
	)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("validate gateway request log payload: %w", err)
	}
	return event, nil
}

func (s *Service) publishUncommittedFallback(authorization *Authorization, event RequestEvent) {
	s.publishUncommittedFallbackWithMode(authorization, event, false)
}

func (s *Service) publishUncommittedFallbackAfterRetry(authorization *Authorization, holdParamsHash string, event RequestEvent) {
	event.holdParamsHash = holdParamsHash
	s.publishUncommittedFallbackWithMode(authorization, event, true)
}

func (s *Service) publishUncommittedFallbackWithMode(authorization *Authorization, event RequestEvent, joinProbe bool) {
	if authorization == nil {
		return
	}
	if s.tinybird == nil {
		return
	}
	appendCtx, cancel := context.WithTimeout(context.Background(), tinybirdAppendTimeout)
	defer cancel()
	if joinProbe {
		_ = s.tinybird.appendGatewayRequestAfterRetry(appendCtx, event)
		return
	}
	_ = s.tinybird.AppendGatewayRequest(appendCtx, event)
}

func ErrorStatus(err error) int {
	var statusError interface{ StatusCode() int }
	if errors.As(err, &statusError) {
		return statusError.StatusCode()
	}
	var typed *billingError
	if errors.As(err, &typed) {
		return typed.statusCode
	}
	var settleErr *settleResultError
	if errors.As(err, &settleErr) {
		return settleErr.statusCode
	}
	return 500
}

func newUUIDV7String() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func validCredentialHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for index := range len(value) {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

func equalOptionalString(left *string, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func parseDatabaseMoney(value *string, field string) (*big.Int, error) {
	if value == nil {
		return nil, fmt.Errorf("database returned no %s", field)
	}
	parsed, err := ParseUSDAtoms(*value)
	if err != nil {
		return nil, fmt.Errorf("database returned an invalid %s: %w", field, err)
	}
	return parsed, nil
}

func derefTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}
