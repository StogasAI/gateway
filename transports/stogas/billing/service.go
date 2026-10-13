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
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/sync/singleflight"
)

const (
	authorizeTimeout = 1500 * time.Millisecond
	// Waiting for an organization slot and a connection ends this long before
	// the authorization deadline, so a statement that starts can finish. One
	// cut off loses its connection and needs a close, which under overload
	// costs the pool more than the requests it fails.
	authorizeStatementReserve  = 250 * time.Millisecond
	holdSettlementExpiryBuffer = 20 * time.Minute

	// GatewayRequestLifetime bounds direct inference, so a hold that outlives it
	// by holdSettlementExpiryBuffer failed to settle and raises an alert.
	GatewayRequestLifetime = time.Hour
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
  $14::timestamptz,
  $15::numeric,
  $16::timestamptz,
  $17::bigint,
  $18::jsonb,
  $19::jsonb,
  $20::jsonb,
  $21::numeric,
  $22::text
`

const authorizeHoldColumns = "result, hold_id, user_id, key_id, grant_id, organization_id, authorized_billed_cost_usd, created_at, expires_at, available_balance_usd, upstream_byok, upstream_byok_binding, config_current"

const closeRequestArguments = `
  $1::uuid,
  $2::text,
  $3::timestamptz
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
	closeRequestQuery          string
	keyConfigQuery             string
	keyConfigs                 keyConfigCache
	keyConfigFlights           singleflight.Group
	authorizations             authorizationActivity
	organizationSlots          organizationSlots
	localRequests              localRequestLimiter
	apiKeys                    verifiedAPIKeyCache
	callerFailures             callerFailureCache
	rejectionLogs              rejectionLogBuffer
	finalizations              finalizationState
	underReservedSettlements   atomic.Uint64
	negativeBalanceSettlements atomic.Uint64
	settleQuery                string
	sanctionedSourceQuery      string
	sanctionedNetworksQuery    string
	// Each hold records the boot that owns it, so Control can release the
	// holds of a boot that stopped.
	nodeID                  string
	apiKeyPepper            string
	inferenceTokenPublicKey ed25519.PublicKey
	byok                    *byokDecryptor
}

type DiagnosticsSnapshot struct {
	KeyConfigCache PolicyCacheDiagnostics    `json:"keyConfigCache"`
	RedactionCache PolicyCacheDiagnostics    `json:"redactionCache"`
	RejectionLogs  RejectionLogDiagnostics   `json:"rejectionLogs"`
	Database       *DatabaseDiagnostics      `json:"database,omitempty"`
	LocalAdmission LocalAdmissionDiagnostics `json:"localAdmission"`
	Settlement     SettlementDiagnostics     `json:"settlement"`
}

func NewService(
	ctx context.Context,
	databaseURL string,
	databaseSchema string,
	apiKeyPepper string,
	byokEncryptionSecret string,
	inferenceTokenPublicKey string,
	nodeID string,
) (*Service, error) {
	publicKey, err := parseInferenceTokenPublicKey(inferenceTokenPublicKey)
	if err != nil {
		return nil, err
	}
	byok, err := newByokDecryptor(byokEncryptionSecret)
	if err != nil {
		return nil, err
	}
	db, err := NewGatewayDB(ctx, databaseURL, databaseSchema)
	if err != nil {
		return nil, err
	}

	service := &Service{
		db:                      db,
		authorizeHoldQuery:      db.functionQuery("authorize_gateway_hold", authorizeHoldColumns, authorizeHoldArguments),
		closeRequestQuery:       db.functionQuery("close_gateway_request", "*", closeRequestArguments),
		keyConfigQuery:          db.functionQuery("gateway_api_key_config", keyConfigColumns, keyConfigArguments),
		settleQuery:             db.functionQuery("settle_gateway_request_logs", "request_id, result", "$1::json, $2::json"),
		sanctionedSourceQuery:   db.functionQuery("gateway_sanctioned_networks_source", "*", ""),
		sanctionedNetworksQuery: db.functionQuery("gateway_sanctioned_networks", "first_address, last_address", ""),
		inferenceTokenPublicKey: publicKey,
		nodeID:                  nodeID,
		apiKeyPepper:            apiKeyPepper,
		byok:                    byok,
	}
	if err := db.checkQueries(
		ctx,
		service.authorizeHoldQuery,
		service.closeRequestQuery,
		service.keyConfigQuery,
		service.settleQuery,
		service.sanctionedSourceQuery,
		service.sanctionedNetworksQuery,
	); err != nil {
		db.Close()
		return nil, err
	}
	return service, nil
}

func (s *Service) Close() {
	s.keyConfigs.close()
	s.closeFinalizations()
	if done := s.stopRejectionLogs(); done != nil {
		<-done
	}
	if s.db != nil {
		s.db.Close()
	}
}

func (s *Service) Diagnostics() DiagnosticsSnapshot {
	if s == nil {
		return DiagnosticsSnapshot{}
	}
	return DiagnosticsSnapshot{
		KeyConfigCache: s.keyConfigs.diagnostics(),
		RedactionCache: s.keyConfigs.redactionDiagnostics(),
		RejectionLogs:  s.rejectionLogs.snapshot(),
		Database:       s.db.Diagnostics(),
		LocalAdmission: localAdmissionDiagnostics(&s.localRequests, &s.authorizations, &s.organizationSlots, &s.callerFailures, &s.apiKeys),
		Settlement:     s.settlementDiagnostics(),
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
) (*Authorization, error) {
	return s.authorizeRequestWithDuration(ctx, rawAPIKey, requestID, providerKey, productKey, estimatedUpstreamCostUSD, usage, snapshot, prepared, activeRules, encryptionKeys, upstreamTarget, requestLifetime)
}

func (s *Service) authorizeRequestWithDuration(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, estimatedUpstreamCostUSD string, usage UsageReservation, snapshot *KeyConfigSnapshot, prepared *PreparedCredential, activeRules []policy.RuleMatch, encryptionKeys customerkey.Keys, upstreamTarget *UpstreamTarget, requestLifetime time.Duration) (*Authorization, error) {
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
	if snapshot == nil || snapshot.Config == nil || snapshot.Claims == nil || snapshot.CredentialsGeneration < 1 || snapshot.Versions == nil {
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
	// PostgreSQL creates no hold after this time by its own clock, so a close
	// that finds this time passed cannot miss one.
	authorizeBefore := time.Now().Add(authorizeTimeout)
	queryCtx, cancel := context.WithDeadline(ctx, authorizeBefore)
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
	waitCtx, cancelWait := context.WithDeadline(queryCtx, authorizeBefore.Add(-authorizeStatementReserve))
	defer cancelWait()
	releaseSlot, err := s.organizationSlots.take(waitCtx, snapshot.Claims.OrganizationID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	defer releaseSlot()
	// A statement that never left the gateway cannot have created a hold, so it
	// needs no close. An exhausted pool or an unreachable database then gets
	// no extra calls from the requests it already failed.
	conn, err := s.db.pool.Acquire(waitCtx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	err = conn.QueryRow(
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
		authorizeBefore,
		usage.Tokens,
		expiresAt.Add(-holdSettlementExpiryBuffer+time.Minute),
		snapshot.CredentialsGeneration,
		string(selectionJSON),
		selectedPolicy.Versions,
		matchedRules,
		usage.InputTextBytes,
		nullableString(s.nodeID),
	).Scan(
		&row.Result, &row.HoldID, &row.UserID, &row.KeyID, &row.GrantID, &row.OrganizationID, &row.AuthorizedBilledCostUSD, &row.CreatedAt, &row.ExpiresAt, &row.AvailableBalanceUSD, &row.UpstreamByok, &row.UpstreamByokBinding, &row.ConfigCurrent,
	)
	conn.Release()
	releaseSlot()
	if err != nil {
		if !pgconn.SafeToRetry(err) {
			s.closeUnconfirmedAuthorization(requestID, snapshot.Claims.KeyID, authorizeBefore, releaseFinalization)
			releaseFinalization = nil
		}
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
		releaseFinalization = nil // Ownership follows the accepted request through settlement.
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
	case "params_mismatch", "authorization_closed", "expired":
		// The gateway's own parameters or clock failed these checks, not the caller.
		return fmt.Errorf("%w: authorization %s", ErrGatewayUnavailable, result)
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
