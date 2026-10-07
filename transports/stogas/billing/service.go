package billing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/money"
	"github.com/maximhq/bifrost/transports/stogas/policy"
	"io"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
)

const (
	authorizeTimeout           = 1500 * time.Millisecond
	holdSettlementExpiryBuffer = 20 * time.Minute

	// GatewayRequestLifetime bounds direct inference so reconciliation never races a live request.
	GatewayRequestLifetime = 60 * time.Minute
	ManagedUpstreamByok    = "stogas"
)

var ErrAuthorizationAbsent = errors.New("Authorization not found")

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
  $15::boolean,
  $16::numeric,
  $17::timestamptz,
  $18::integer,
  $19::jsonb,
  $20::jsonb,
  $21::jsonb,
  $22::numeric
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
	Result                  string
	HoldID                  *string
	UserID                  *string
	KeyID                   *string
	GrantID                 *string
	OrganizationID          *string
	AuthorizedBilledCostUSD *string
	CreatedAt               *time.Time
	ExpiresAt               *time.Time
	AvailableBalanceUSD     *string
	UpstreamByok            *string
	UpstreamByokBinding     *string
	ConfigCurrent           bool
}

type settleRow struct {
	Result               string
	BilledCostUSD        *string
	BalanceAdjustmentUSD *string
	AvailableBalanceUSD  *string
}

type Authorization struct {
	releaseFinalization        func()
	admissionStartedAt         time.Time
	dashboardAdmissionIdentity string
	AuthorizedBilledCostUSD    *money.USD
	AvailableBalanceUSD        *money.USD
	CreatedAt                  time.Time
	GrantID                    *string
	KeyID                      string
	OrganizationID             string
	ProductKey                 string
	ProviderKey                string
	RequestID                  string
	UserID                     string
	UpstreamByok               string
	UpstreamByokSecret         string
	AzureBinding               *AzureBinding
	UpstreamTargetJSON         string
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

type azureBoundBinding struct {
	Binding AzureBinding `json:"binding"`
	Schema  string       `json:"schema"`
}

func parseAzureBoundBinding(raw string) (azureBoundBinding, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	value := azureBoundBinding{}
	if err := decoder.Decode(&value); err != nil {
		return azureBoundBinding{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return azureBoundBinding{}, errors.New("invalid Azure binding: trailing JSON")
	}
	if value.Schema != "stogas.azure-binding.v1" ||
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
		return azureBoundBinding{}, errors.New("invalid Azure binding")
	}
	return value, nil
}

type Service struct {
	db                         *GatewayDB
	authorizeHoldQuery         string
	keyConfigQuery             string
	keyConfigs                 keyConfigCache
	keyConfigFlights           singleflight.Group
	authorizations             authorizationActivity
	localRequests              localRequestLimiter
	apiKeys                    verifiedAPIKeyCache
	callerFailures             callerFailureCache
	rejectionLogs              rejectionLogBuffer
	finalizations              finalizationState
	underReservedSettlements   atomic.Uint64
	negativeBalanceSettlements atomic.Uint64
	requestLogs                *RequestLogClient
	settleHoldQuery            string
	apiKeyPepper               string
	inferenceTokenPublicKey    ed25519.PublicKey
	byok                       *byokDecryptor
}

type DiagnosticsSnapshot struct {
	KeyConfigCache                 PolicyCacheDiagnostics    `json:"keyConfigCache"`
	RedactionCache                 PolicyCacheDiagnostics    `json:"redactionCache"`
	RejectionLogs                  RejectionLogDiagnostics   `json:"rejectionLogs"`
	Database                       *DatabaseDiagnostics      `json:"database,omitempty"`
	LocalAdmission                 LocalAdmissionDiagnostics `json:"localAdmission"`
	FinalizationRetries            int64                     `json:"finalizationRetries"`
	UnderReservedSettlements       uint64                    `json:"underReservedSettlements"`
	NegativeBalanceSettlements     uint64                    `json:"negativeBalanceSettlements"`
	FinalizationAbandoned          int64                     `json:"finalizationAbandoned"`
	FinalizationEncodingFailed     bool                      `json:"finalizationEncodingFailed"`
	FinalizationRetryQueueCapacity int                       `json:"finalizationRetryQueueCapacity"`
	FinalizationRetryQueueDepth    int                       `json:"finalizationRetryQueueDepth"`
	RequestLogs                    *RequestLogDiagnostics    `json:"requestLogs,omitempty"`
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
	requestLogs *RequestLogClient,
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

	service := &Service{
		db:                      db,
		authorizeHoldQuery:      db.functionQuery("authorize_gateway_hold", authorizeHoldArguments),
		keyConfigQuery:          db.functionQuery("gateway_api_key_config", keyConfigArguments),
		inferenceTokenPublicKey: publicKey,
		requestLogs:             requestLogs,
		settleHoldQuery:         db.functionQuery("settle_gateway_hold", settleHoldArguments),
		apiKeyPepper:            apiKeyPepper,
		byok:                    byok,
	}
	return service, nil
}

func (s *Service) Close() {
	s.keyConfigs.close()
	s.closeRejectionLogs()
	s.closeFinalizations()
	if s.requestLogs != nil {
		s.requestLogs.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}

func (s *Service) Diagnostics() DiagnosticsSnapshot {
	if s == nil {
		return DiagnosticsSnapshot{}
	}
	retryQueueDepth := s.finalizationQueueDepth()
	return DiagnosticsSnapshot{
		KeyConfigCache:                 s.keyConfigs.diagnostics(),
		RedactionCache:                 s.keyConfigs.redactionDiagnostics(),
		RejectionLogs:                  s.rejectionLogs.snapshot(),
		Database:                       s.db.Diagnostics(),
		LocalAdmission:                 localAdmissionDiagnostics(&s.localRequests, &s.authorizations, &s.callerFailures, &s.apiKeys),
		FinalizationRetries:            s.finalizations.pending.Load(),
		UnderReservedSettlements:       s.underReservedSettlements.Load(),
		NegativeBalanceSettlements:     s.negativeBalanceSettlements.Load(),
		FinalizationAbandoned:          s.finalizations.abandoned.Load(),
		FinalizationEncodingFailed:     s.finalizations.encodingFailed.Load(),
		FinalizationRetryQueueCapacity: finalizationCapacity,
		FinalizationRetryQueueDepth:    retryQueueDepth,
		RequestLogs:                    s.requestLogs.Diagnostics(),
	}
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
		return nil, ErrInvalidAPIKey
	}
	claims, _, _, err := s.parseVerifiedAPIKey(rawAPIKey)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	if err := s.callerBackoff(claims, nil, time.Now()); err != nil {
		return claims, err
	}
	if retryAfter := s.localRequests.allow("org:"+claims.OrganizationID, time.Now()); retryAfter > 0 {
		return claims, &retryAfterError{delay: retryAfter}
	}
	return claims, nil
}

func (s *Service) ParseDashboardCredential(raw string) (*DashboardCredential, error) {
	if s == nil || len(s.inferenceTokenPublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidAPIKey
	}
	credential, err := parseDashboardCredential(raw, s.inferenceTokenPublicKey, time.Now())
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	cacheKey := dashboardAdmissionKey(credential)
	if snapshot, ok := s.keyConfigs.get(dashboardConfigCacheKey(credential), time.Now()); ok {
		credential.Claims = snapshot.Claims
	}
	if err := s.callerBackoff(credential.Claims, credential, time.Now()); err != nil {
		return credential, err
	}
	if retryAfter := s.localRequests.allow(cacheKey, time.Now()); retryAfter > 0 {
		return credential, &retryAfterError{delay: retryAfter}
	}
	return credential, nil
}

// UsageReservation records quantities once before authorization. Text remains
// in exact UTF-8 bytes; STT presentation divides it by four.
type UsageReservation struct {
	Tokens         int64
	InputTextBytes int64
}

func (s *Service) AuthorizeRequestWithEncryptionKeys(
	ctx context.Context,
	rawAPIKey string,
	requestID string,
	providerKey string,
	productKey string,
	estimatedUpstreamCostUSD string, usage UsageReservation,
	snapshot *KeyConfigSnapshot,
	prepared *PreparedCredential,
	activeRules []policy.RuleMatch,
	encryptionKeys customerkey.Keys,
	upstreamTarget *UpstreamTarget,
	requestLifetime time.Duration,
	singleUse bool,
) (*Authorization, error) {
	return s.authorizeRequestWithDuration(ctx, rawAPIKey, requestID, providerKey, productKey, estimatedUpstreamCostUSD, usage, snapshot, prepared, activeRules, encryptionKeys, upstreamTarget, requestLifetime, singleUse)
}

func (s *Service) authorizeRequestWithDuration(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, estimatedUpstreamCostUSD string, usage UsageReservation, snapshot *KeyConfigSnapshot, prepared *PreparedCredential, activeRules []policy.RuleMatch, encryptionKeys customerkey.Keys, upstreamTarget *UpstreamTarget, requestLifetime time.Duration, singleUse bool) (*Authorization, error) {
	claims, apiKeyHash, _, err := s.parseVerifiedAPIKey(rawAPIKey)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	if err := s.callerBackoff(claims, nil, time.Now()); err != nil {
		return nil, err
	}

	return s.authorizeResolvedRequest(
		ctx,
		apiKeyHash,
		nil,
		claims,
		requestID,
		providerKey,
		productKey,
		estimatedUpstreamCostUSD,
		usage,
		snapshot,
		prepared,
		activeRules,
		encryptionKeys,
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
	estimatedUpstreamCostUSD string, usage UsageReservation,
	snapshot *KeyConfigSnapshot,
	prepared *PreparedCredential,
	activeRules []policy.RuleMatch,
	encryptionKeys customerkey.Keys,
	upstreamTarget *UpstreamTarget,
	requestLifetime time.Duration,
) (*Authorization, error) {
	if credential == nil {
		return nil, ErrInvalidAPIKey
	}
	if err := s.callerBackoff(credential.Claims, credential, time.Now()); err != nil {
		return nil, err
	}
	return s.authorizeResolvedRequest(
		ctx,
		"",
		credential,
		nil,
		requestID,
		providerKey,
		productKey,
		estimatedUpstreamCostUSD,
		usage,
		snapshot,
		prepared,
		activeRules,
		encryptionKeys,
		upstreamTarget,
		requestLifetime,
		true,
	)
}

func (s *Service) authorizeResolvedRequest(
	ctx context.Context,
	apiKeyHash string,
	dashboard *DashboardCredential,
	claims *APIKeyClaims,
	requestID string,
	providerKey string,
	productKey string,
	estimatedUpstreamCostUSD string, usage UsageReservation,
	snapshot *KeyConfigSnapshot,
	prepared *PreparedCredential,
	activeRules []policy.RuleMatch,
	encryptionKeys customerkey.Keys,
	upstreamTarget *UpstreamTarget,
	requestLifetime time.Duration,
	singleUse bool,
) (*Authorization, error) {
	releaseFinalization, err := s.reserveFinalization()
	if err != nil {
		return nil, err
	}
	defer func() {
		if releaseFinalization != nil {
			releaseFinalization()
		}
	}()
	if snapshot == nil || snapshot.Config == nil || snapshot.Claims == nil || snapshot.Generation < 1 || snapshot.CredentialsGeneration < 1 || snapshot.Versions == nil {
		return nil, ErrGatewayUnavailable
	}
	if prepared == nil || prepared.snapshot != snapshot || prepared.provider != providerKey {
		return nil, ErrByok
	}
	selection := prepared.selection
	// Plugin roots are covered by the checked source revisions. SQL needs only
	// the root identifier for the selected encrypted provider credential.
	credentialKeyID := ""
	if selection.Mode == "encrypted" && selection.Credential != nil {
		credentialKeyID = selection.Credential.EncryptionKeyID
	}
	selectedPolicy, err := snapshot.PolicyForCredential(providerKey, prepared.index, encryptionKeys, time.Now(), nil)
	if err != nil {
		return nil, err
	}
	matchedRules := make([]struct {
		Scope policy.Scope `json:"scope"`
		ID    string       `json:"id"`
		Rule  string       `json:"rule"`
	}, len(activeRules))
	for i, match := range activeRules {
		if match.Source < 0 || match.Source >= len(*selectedPolicy.Versions) {
			return nil, ErrGatewayUnavailable
		}
		version := (*selectedPolicy.Versions)[match.Source]
		matchedRules[i].Scope, matchedRules[i].ID, matchedRules[i].Rule = version.Scope, version.ID, match.Name
	}
	selectionJSON, err := json.Marshal(struct {
		Mode string  `json:"mode"`
		ID   *string `json:"byokId"`
	}{selection.Mode, nullableString(selection.ID)})
	if err != nil {
		return nil, ErrGatewayUnavailable
	}
	started := time.Now()
	expiresAt := requestHoldExpiresAt(started.UTC(), requestLifetime)
	holdID, err := newUUIDV7String()
	if err != nil {
		return nil, fmt.Errorf("generate hold id: %w", err)
	}
	upstreamTargetJSON := ""
	if upstreamTarget != nil {
		encoded, marshalErr := json.Marshal(upstreamTarget)
		if marshalErr != nil {
			return nil, ErrByokTarget
		}
		upstreamTargetJSON = string(encoded)
	}
	holdParamsHash := createHoldParamsHash(providerKey, productKey, upstreamTargetJSON)
	releaseAuthorization := s.authorizations.start()
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
		estimatedUpstreamCostUSD,
		expiresAt,
		holdParamsHash,
		nullableString(upstreamTargetJSON),
		nullableString(credentialKeyID),
		snapshot.Generation,
		singleUse,
		usage.Tokens,
		expiresAt.Add(-holdSettlementExpiryBuffer+time.Minute),
		snapshot.CredentialsGeneration,
		string(selectionJSON),
		selectedPolicy.Versions,
		matchedRules,
		usage.InputTextBytes,
	).Scan(
		&row.Result, &row.HoldID, &row.UserID, &row.KeyID, &row.GrantID, &row.OrganizationID, &row.AuthorizedBilledCostUSD, &row.CreatedAt, &row.ExpiresAt, &row.AvailableBalanceUSD, &row.UpstreamByok, &row.UpstreamByokBinding, &row.ConfigCurrent,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}

	if resultErr := authorizationResultError(row.Result); resultErr != nil {
		if !row.ConfigCurrent && derefString(row.KeyID) == snapshot.Claims.KeyID {
			s.confirmKeyConfig(apiKeyHash, dashboard, snapshot, false, started)
		}
		return nil, resultErr
	}

	switch row.Result {
	case "ok":
		keyID := derefString(row.KeyID)
		organizationID := derefString(row.OrganizationID)
		userID := derefString(row.UserID)
		grantID := row.GrantID
		if dashboard != nil {
			if keyID != dashboard.KeyID || userID != dashboard.ActorUserID {
				return nil, ErrInvalidAPIKey
			}
		} else {
			if claims == nil ||
				keyID != claims.KeyID ||
				organizationID != claims.OrganizationID ||
				userID != claims.ResponsibleID ||
				!equalOptionalString(grantID, claims.GrantID) {
				return nil, ErrInvalidAPIKey
			}
		}
		upstreamByok := derefString(row.UpstreamByok)
		authorizedBilledCostUSD, amountErr := parseDatabaseMoney(row.AuthorizedBilledCostUSD, "authorized billed cost")
		if amountErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, amountErr)
		}
		availableBalanceUSD, amountErr := parseDatabaseMoney(row.AvailableBalanceUSD, "available balance")
		if amountErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, amountErr)
		}
		authorization := &Authorization{releaseFinalization: releaseFinalization, AuthorizedBilledCostUSD: authorizedBilledCostUSD, AvailableBalanceUSD: availableBalanceUSD, CreatedAt: derefTime(row.CreatedAt), GrantID: grantID, KeyID: keyID, OrganizationID: organizationID, ProductKey: productKey, ProviderKey: providerKey, RequestID: requestID, UpstreamByok: upstreamByok, UpstreamTargetJSON: upstreamTargetJSON, UserID: userID}
		releaseFinalization = nil // Ownership follows the accepted request through durable finalization.
		if upstreamByok == "" {
			return authorization, ErrByok
		}
		s.confirmKeyConfig(apiKeyHash, dashboard, snapshot, row.ConfigCurrent, started)
		if selection.Mode == "stored" {
			credential := selection.Credential
			if credential == nil || credential.ID != upstreamByok || credential.OrganizationID != organizationID ||
				credential.Provider != providerKey {
				return authorization, ErrByok
			}
			if providerKey == "azure" {
				bound, parseErr := parseAzureBoundBinding(derefString(row.UpstreamByokBinding))
				if parseErr != nil {
					return authorization, ErrByok
				}
				authorization.AzureBinding = &bound.Binding
			} else if row.UpstreamByokBinding != nil {
				return authorization, ErrByok
			}
			authorization.UpstreamByokSecret = prepared.Secret
		} else if selection.Mode == "encrypted" {
			credential := selection.Credential
			if credential == nil || credential.ID != upstreamByok || row.UpstreamByokBinding != nil || !encryptionKeys.Matches(credential.EncryptionKeyID) {
				return authorization, customerkey.ErrKey
			}
			authorization.UpstreamByokSecret = prepared.Secret

		} else if upstreamByok != ManagedUpstreamByok || row.UpstreamByokBinding != nil {
			return authorization, ErrByok
		}
		authorization.admissionStartedAt = started
		if dashboard != nil {
			authorization.dashboardAdmissionIdentity = dashboardAdmissionKey(dashboard)
		}
		return authorization, nil
	default:
		return nil, fmt.Errorf("unknown hold authorization result: %s", row.Result)
	}
}

func authorizationResultError(result string) error {
	if err := policyResultErrors[result]; err != nil {
		return err
	}
	switch result {
	case "invalid_key", "hold_missing":
		return ErrInvalidAPIKey
	case "params_mismatch":
		return ErrParamsMismatch
	case "authorization_closed":
		return ErrAuthorizationClosed
	case "expired":
		return ErrRequestAlreadyUsed
	case "insufficient_balance":
		return ErrInsufficientBalance
	case "byok_disabled":
		return ErrByok
	case "encryption_key_required":
		return customerkey.ErrKey
	case "byok_required":
		return ErrByokRequired
	case "byok_target_unavailable":
		return ErrByokTarget
	case "byok_not_allowed":
		return errByokNotAllowed
	case "dashboard_forbidden":
		return ErrDashboardKeyDenied
	case "config_stale":
		return ErrAPIKeyConfigStale
	case "key_configuration_too_large":
		return ErrAPIKeyConfigSize
	case "api_key_limit":
		return ErrAPIKeyLimit
	case "invalid_amount":
		return errors.New("invalid estimated upstream cost")
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

func durationOrDefault(value time.Duration, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func requestHoldExpiresAt(now time.Time, requestLifetime time.Duration) time.Time {
	return now.Add(durationOrDefault(requestLifetime, GatewayRequestLifetime) + holdSettlementExpiryBuffer)
}

func ErrorStatus(err error) int {
	var statusError interface{ StatusCode() int }
	if errors.As(err, &statusError) {
		return statusError.StatusCode()
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

func equalOptionalString(left *string, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func parseDatabaseMoney(value *string, field string) (*money.USD, error) {
	if value == nil {
		return nil, fmt.Errorf("database returned no %s", field)
	}
	parsed, err := ParseUSD(*value)
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
