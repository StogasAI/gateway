package billing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	authorizeTimeout           = 1500 * time.Millisecond
	settleTimeout              = 2 * time.Second
	settleRetryWindow          = 90 * time.Second
	settleRetryInitialDelay    = 250 * time.Millisecond
	settleRetryMaxDelay        = 5 * time.Second
	holdSettlementExpiryBuffer = 10 * time.Minute

	// GatewayRequestLifetime bounds direct inference streams so reconciliation never races a live request.
	GatewayRequestLifetime = 60 * time.Minute
)

var (
	ErrAPIKeyDisabled      = errors.New("API key is disabled")
	ErrAPIKeyExpired       = errors.New("API key is expired")
	ErrInvalidAPIKey       = errors.New("Invalid API key")
	ErrRequestAlreadyUsed  = errors.New("Request already finalized; generate a new requestId")
	ErrAuthorizationClosed = errors.New("Authorization already completed; generate a new requestId")
	ErrParamsMismatch      = errors.New("Authorization already exists with different parameters")
	ErrInsufficientBalance = errors.New("Insufficient balance")
	ErrAPIKeySpendLimit    = errors.New("API key spend limit exceeded")
	ErrAPIKeyRateLimit     = errors.New("API key rate limit exceeded")
	ErrAPIKeyLimit         = errors.New("API key limit reached or disabled/expired")
	ErrByok                = errors.New("BYOK key is unavailable")
	ErrDashboardKeyDenied  = errors.New("API key is not available to this dashboard session")
	ErrGatewayUnavailable  = errors.New("Gateway billing database unavailable")
	ErrAuthorizationAbsent = errors.New("Authorization not found")
	ErrLocalAdmissionLimit = errors.New("Too many concurrent requests for this API key")
)

const authorizeHoldQuery = `
select *
from authorize_gateway_hold(
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
  $12::boolean
);
`

const settleHoldQuery = `
select *
from settle_gateway_hold(
  $1::uuid,
  $2::text,
  $3::text,
  $4::text,
  $5::text,
  $6::numeric,
  $7::json
);
`

const settleHoldWithOutboxQuery = `
select *
from settle_gateway_hold_with_outbox(
  $1::uuid,
  $2::text,
  $3::text,
  $4::text,
  $5::text,
  $6::numeric,
  $7::json
);
`

type authorizeRow struct {
	Result                 string
	HoldID                 *string
	UserID                 *string
	KeyID                  *string
	ProvisioningKeyID      *string
	OrganizationID         *string
	WorkspaceID            *string
	AuthorizedAmount       *string
	CreatedAt              *time.Time
	ExpiresAt              *time.Time
	AvailableAfter         *string
	UpstreamByok           *string
	UpstreamByokCiphertext *string
}

type settleRow struct {
	Result         string
	FinalCost      *string
	RefundAmount   *string
	AvailableAfter *string
}

type Authorization struct {
	AuthorizedAmount   *big.Int
	AvailableAfter     *big.Int
	CreatedAt          time.Time
	ExpiresAt          time.Time
	HoldID             string
	KeyID              string
	OrganizationID     string
	ProvisioningKeyID  *string
	ProductKey         string
	ProviderKey        string
	RequestID          string
	UserID             string
	WorkspaceID        string
	UpstreamByok       string
	UpstreamByokSecret string
}

type Service struct {
	db                      *GatewayDB
	localAuthorizations     localAuthorizationLimiter
	localRequests           localRequestLimiter
	rejections              authorizationRejectionCache
	retryInitialDelay       time.Duration
	retryMaxDelay           time.Duration
	retryWindow             time.Duration
	retryWG                 sync.WaitGroup
	settleFunc              func(context.Context, *Authorization, string, string, string, bool) error
	tinybird                *TinybirdClient
	apiKeyPepper            string
	inferenceTokenPublicKey ed25519.PublicKey
	byok                    *byokDecryptor
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
		db:                      db,
		inferenceTokenPublicKey: publicKey,
		tinybird:                tinybird,
		apiKeyPepper:            apiKeyPepper,
		byok:                    byok,
	}, nil
}

func (s *Service) Close() {
	s.retryWG.Wait()
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

func (s *Service) ValidateAPIKeyFormat(rawAPIKey string) error {
	if s == nil {
		return &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	_, err := parseSignedAPIKey(rawAPIKey, s.apiKeyPepper)
	if err != nil {
		return &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	return nil
}

func (s *Service) ParseAPIKey(rawAPIKey string) (*APIKeyClaims, error) {
	if s == nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	claims, err := parseSignedAPIKey(rawAPIKey, s.apiKeyPepper)
	if err != nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	cacheKey := apiKeyRejectionCacheKey(rawAPIKey, s.apiKeyPepper)
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
	cacheKey := dashboardRejectionCacheKey(credential)
	if retryAfter := s.localRequests.allow(cacheKey, time.Now()); retryAfter > 0 {
		return nil, &billingError{err: ErrAPIKeyRateLimit, statusCode: 429}
	}
	if result, _, ok := s.rejections.get(cacheKey, time.Now()); ok {
		return nil, authorizationResultError(result)
	}
	return credential, nil
}

func (s *Service) AuthorizeRequest(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string) (*Authorization, error) {
	return s.AuthorizeRequestWithDuration(ctx, rawAPIKey, requestID, providerKey, productKey, amountUSDAtoms, GatewayRequestLifetime)
}

func (s *Service) AuthorizeRequestWithDuration(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string, requestLifetime time.Duration) (*Authorization, error) {
	return s.authorizeRequestWithDuration(ctx, rawAPIKey, requestID, providerKey, productKey, amountUSDAtoms, requestLifetime, false)
}

func (s *Service) AuthorizeSingleUseRequestWithDuration(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string, requestLifetime time.Duration) (*Authorization, error) {
	return s.authorizeRequestWithDuration(ctx, rawAPIKey, requestID, providerKey, productKey, amountUSDAtoms, requestLifetime, true)
}

func (s *Service) authorizeRequestWithDuration(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string, requestLifetime time.Duration, singleUse bool) (*Authorization, error) {
	claims, err := parseSignedAPIKey(rawAPIKey, s.apiKeyPepper)
	if err != nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	cacheKey := apiKeyRejectionCacheKey(rawAPIKey, s.apiKeyPepper)
	if result, _, ok := s.rejections.get(cacheKey, time.Now()); ok {
		return nil, authorizationResultError(result)
	}

	return s.authorizeResolvedRequest(
		ctx,
		hashAPIKey(rawAPIKey, s.apiKeyPepper),
		cacheKey,
		nil,
		claims,
		requestID,
		providerKey,
		productKey,
		amountUSDAtoms,
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
	amountUSDAtoms string,
	requestLifetime time.Duration,
) (*Authorization, error) {
	if credential == nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}
	return s.authorizeResolvedRequest(
		ctx,
		"",
		dashboardRejectionCacheKey(credential),
		credential,
		nil,
		requestID,
		providerKey,
		productKey,
		amountUSDAtoms,
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
	amountUSDAtoms string,
	requestLifetime time.Duration,
	singleUse bool,
) (*Authorization, error) {
	if requestLifetime <= 0 {
		requestLifetime = GatewayRequestLifetime
	}
	releaseAuthorization, acquired := s.localAuthorizations.acquire(rejectionCacheKey)
	if !acquired {
		return nil, &billingError{err: ErrLocalAdmissionLimit, statusCode: 429}
	}
	defer releaseAuthorization()

	expiresAt := time.Now().UTC().Add(requestLifetime + holdSettlementExpiryBuffer)
	holdID, err := newUUIDV7String()
	if err != nil {
		return nil, fmt.Errorf("generate hold id: %w", err)
	}
	paramsHash := createHoldParamsHash(providerKey, productKey)

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
		authorizeHoldQuery,
		apiKeyHashValue,
		dashboardKeyID,
		dashboardActorUserID,
		dashboardSessionID,
		requestID,
		holdID,
		providerKey,
		productKey,
		amountUSDAtoms,
		expiresAt,
		paramsHash,
		singleUse,
	).Scan(
		&row.Result, &row.HoldID, &row.UserID, &row.KeyID, &row.ProvisioningKeyID, &row.OrganizationID, &row.WorkspaceID, &row.AuthorizedAmount, &row.CreatedAt, &row.ExpiresAt, &row.AvailableAfter, &row.UpstreamByok, &row.UpstreamByokCiphertext,
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
		provisioningKeyID := row.ProvisioningKeyID
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
				!equalOptionalString(provisioningKeyID, claims.ProvisioningID) {
				s.rejections.record(rejectionCacheKey, "invalid_key", time.Now())
				return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
			}
		}
		upstreamByok := derefString(row.UpstreamByok)
		authorization := &Authorization{AuthorizedAmount: parseMoneyOrZero(row.AuthorizedAmount), AvailableAfter: parseMoneyOrZero(row.AvailableAfter), CreatedAt: derefTime(row.CreatedAt), ExpiresAt: derefTime(row.ExpiresAt), HoldID: derefString(row.HoldID), KeyID: keyID, OrganizationID: organizationID, ProvisioningKeyID: provisioningKeyID, ProductKey: productKey, ProviderKey: providerKey, RequestID: requestID, UpstreamByok: upstreamByok, UserID: userID, WorkspaceID: workspaceID}
		if upstreamByok == "" {
			return authorization, &billingError{err: ErrByok, statusCode: 503}
		}
		if upstreamByok != "stogas" {
			authorization.UpstreamByokSecret, err = s.byok.decrypt(
				derefString(row.UpstreamByokCiphertext),
				upstreamByok,
				organizationID,
				workspaceID,
				providerKey,
			)
			if err != nil {
				return authorization, &billingError{err: ErrByok, statusCode: 503}
			}
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
	case "byok_disabled":
		return &billingError{err: ErrByok, statusCode: 503}
	case "key_expired":
		return &billingError{err: ErrAPIKeyExpired, statusCode: 403}
	case "dashboard_forbidden":
		return &billingError{err: ErrDashboardKeyDenied, statusCode: 403}
	case "key_spend_limit":
		return &billingError{err: ErrAPIKeySpendLimit, statusCode: 402}
	case "key_rate_limited":
		return &billingError{err: ErrAPIKeyRateLimit, statusCode: 429}
	case "api_key_limit":
		return &billingError{err: ErrAPIKeyLimit, statusCode: 402}
	case "invalid_amount":
		return &billingError{err: errors.New("Invalid authorization amount"), statusCode: 400}
	default:
		return nil
	}
}

func apiKeyRejectionCacheKey(rawAPIKey string, apiKeyPepper string) string {
	return "api:" + hashAPIKey(rawAPIKey, apiKeyPepper)
}

func dashboardRejectionCacheKey(credential *DashboardCredential) string {
	if credential == nil {
		return ""
	}
	return "dashboard:" + credential.SessionID + ":" + credential.KeyID
}

func (s *Service) FinalizeRequest(ctx context.Context, authorization *Authorization, event RequestEvent) error {
	if authorization == nil {
		return nil
	}

	paramsHash := createHoldParamsHash(authorization.ProviderKey, authorization.ProductKey)
	actualCost := event.UpstreamCostUSDAtoms
	if actualCost == "" {
		actualCost = ZeroChargeUSDAtoms
		event.UpstreamCostUSDAtoms = actualCost
	}
	event.BilledCostUSDAtoms = billedRequestCost(authorization, actualCost)
	payload, err := encodeGatewayRequestEvent(event)
	if err != nil {
		return err
	}

	writeOutbox := true
	if s.tinybird != nil {
		writeOutbox = s.tinybird.AppendGatewayRequest(ctx, event) != nil
	}

	if err := s.settleOnce(ctx, authorization, paramsHash, actualCost, payload, writeOutbox); err != nil {
		s.retryWG.Add(1)
		go func() {
			defer s.retryWG.Done()
			s.retrySettle(authorization, paramsHash, actualCost, payload, event, writeOutbox)
		}()
		return nil
	}

	return nil
}

func (s *Service) settleOnce(ctx context.Context, authorization *Authorization, paramsHash string, actualCost string, payload string, writeOutbox bool) error {
	if s.settleFunc != nil {
		return s.settleFunc(ctx, authorization, paramsHash, actualCost, payload, writeOutbox)
	}

	queryCtx, cancel := context.WithTimeout(ctx, settleTimeout)
	defer cancel()

	row := settleRow{}
	query := settleHoldQuery
	if writeOutbox {
		query = settleHoldWithOutboxQuery
	}
	err := s.db.pool.QueryRow(
		queryCtx,
		query,
		authorization.RequestID,
		authorization.KeyID,
		authorization.ProviderKey,
		authorization.ProductKey,
		paramsHash,
		actualCost,
		payload,
	).Scan(&row.Result, &row.FinalCost, &row.RefundAmount, &row.AvailableAfter)
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
		return &settleResultError{err: errors.New("Invalid settlement payload"), result: row.Result, statusCode: 400}
	default:
		return fmt.Errorf("unknown settlement result: %s", row.Result)
	}
}

func (s *Service) retrySettle(authorization *Authorization, paramsHash string, actualCost string, payload string, event RequestEvent, writeOutbox bool) {
	deadline := time.Now().Add(durationOrDefault(s.retryWindow, settleRetryWindow))
	delay := durationOrDefault(s.retryInitialDelay, settleRetryInitialDelay)
	maxDelay := durationOrDefault(s.retryMaxDelay, settleRetryMaxDelay)
	for time.Now().Before(deadline) {
		time.Sleep(delay)
		err := s.settleOnce(context.Background(), authorization, paramsHash, actualCost, payload, writeOutbox)
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

	if writeOutbox {
		s.publishUncommittedFallback(authorization, event)
	}
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

func encodeGatewayRequestEvent(event RequestEvent) (string, error) {
	if event.Pricing == nil {
		event.Pricing = map[string]any{}
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("marshal gateway request log payload: %w", err)
	}
	return string(encoded), nil
}

func (s *Service) publishUncommittedFallback(authorization *Authorization, event RequestEvent) {
	if authorization == nil {
		return
	}
	if s.tinybird == nil {
		return
	}
	appendCtx, cancel := context.WithTimeout(context.Background(), tinybirdAppendTimeout)
	defer cancel()
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

func equalOptionalString(left *string, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func parseMoneyOrZero(value *string) *big.Int {
	return parseMoneyOrZeroString(derefString(value))
}

func derefTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}
