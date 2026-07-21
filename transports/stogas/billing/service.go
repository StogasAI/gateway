package billing

import (
	"context"
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
	ErrGatewayUnavailable  = errors.New("Gateway billing database unavailable")
	ErrAuthorizationAbsent = errors.New("Authorization not found")
)

const authorizeHoldQuery = `
select *
from authorize_gateway_hold(
  $1::text,
  $2::uuid,
  $3::uuid,
  $4::text,
  $5::text,
  $6::numeric,
  $7::timestamptz,
  $8::text
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
  $7::jsonb,
  $8::json
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
  $7::jsonb,
  $8::json
);
`

type authorizeRow struct {
	Result           string
	HoldID           *string
	UserID           *string
	KeyID            *string
	OrganizationID   *string
	WorkspaceID      *string
	AuthorizedAmount *string
	CreatedAt        *time.Time
	ExpiresAt        *time.Time
	AvailableAfter   *string
}

type settleRow struct {
	Result         string
	FinalCost      *string
	RefundAmount   *string
	AvailableAfter *string
}

type Authorization struct {
	AuthorizedAmount *big.Int
	AvailableAfter   *big.Int
	CreatedAt        time.Time
	ExpiresAt        time.Time
	HoldID           string
	KeyID            string
	OrganizationID   string
	ProductKey       string
	ProviderKey      string
	RequestID        string
	UserID           string
	WorkspaceID      string
}

type Service struct {
	db                *GatewayDB
	retryInitialDelay time.Duration
	retryMaxDelay     time.Duration
	retryWindow       time.Duration
	retryWG           sync.WaitGroup
	settleFunc        func(context.Context, *Authorization, string, string, string, string, bool) error
	tinybird          *TinybirdClient
	tokenPepper       string
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

func NewService(ctx context.Context, databaseURL string, databaseSchema string, authSecret string, databasePool DatabasePoolConfig, tinybird *TinybirdClient) (*Service, error) {
	tokenPepper, err := deriveTokenPepper(authSecret)
	if err != nil {
		return nil, err
	}
	db, err := NewGatewayDB(ctx, databaseURL, databaseSchema, databasePool)
	if err != nil {
		return nil, err
	}

	return &Service{db: db, tinybird: tinybird, tokenPepper: tokenPepper}, nil
}

func (s *Service) Close() {
	s.retryWG.Wait()
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
	if _, err := s.ParseAPIKey(rawAPIKey); err != nil {
		return err
	}
	return nil
}

func (s *Service) ParseAPIKey(rawAPIKey string) (*APIKeyClaims, error) {
	if s == nil {
		return nil, ErrInvalidAPIKey
	}
	claims, err := parseSignedAPIKey(rawAPIKey, s.tokenPepper)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	return claims, nil
}

func (s *Service) AuthorizeRequest(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string) (*Authorization, error) {
	return s.AuthorizeRequestWithDuration(ctx, rawAPIKey, requestID, providerKey, productKey, amountUSDAtoms, GatewayRequestLifetime)
}

func (s *Service) AuthorizeRequestWithDuration(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string, requestLifetime time.Duration) (*Authorization, error) {
	if err := s.ValidateAPIKeyFormat(rawAPIKey); err != nil {
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	}

	apiKeyHash := hashAPIKey(rawAPIKey, s.tokenPepper)
	if requestLifetime <= 0 {
		requestLifetime = GatewayRequestLifetime
	}
	expiresAt := time.Now().UTC().Add(requestLifetime + holdSettlementExpiryBuffer)
	holdID, err := newUUIDV7String()
	if err != nil {
		return nil, fmt.Errorf("generate hold id: %w", err)
	}
	paramsHash := createHoldParamsHash(providerKey, productKey)

	row := authorizeRow{}
	queryCtx, cancel := context.WithTimeout(ctx, authorizeTimeout)
	defer cancel()
	err = s.db.pool.QueryRow(queryCtx, authorizeHoldQuery, apiKeyHash, requestID, holdID, providerKey, productKey, amountUSDAtoms, expiresAt, paramsHash).Scan(
		&row.Result, &row.HoldID, &row.UserID, &row.KeyID, &row.OrganizationID, &row.WorkspaceID, &row.AuthorizedAmount, &row.CreatedAt, &row.ExpiresAt, &row.AvailableAfter,
	)
	if err != nil {
		return nil, &billingError{err: fmt.Errorf("%w: %v", ErrGatewayUnavailable, err), statusCode: 503}
	}

	switch row.Result {
	case "invalid_key", "hold_missing":
		return nil, &billingError{err: ErrInvalidAPIKey, statusCode: 401}
	case "usage_exists":
		return nil, &billingError{err: ErrRequestAlreadyUsed, statusCode: 409}
	case "params_mismatch":
		return nil, &billingError{err: ErrParamsMismatch, statusCode: 409}
	case "expired":
		return nil, &billingError{err: ErrRequestAlreadyUsed, statusCode: 409}
	case "insufficient_balance":
		return nil, &billingError{err: ErrInsufficientBalance, statusCode: 402}
	case "key_disabled":
		return nil, &billingError{err: ErrAPIKeyDisabled, statusCode: 403}
	case "key_expired":
		return nil, &billingError{err: ErrAPIKeyExpired, statusCode: 403}
	case "key_spend_limit":
		return nil, &billingError{err: ErrAPIKeySpendLimit, statusCode: 402}
	case "key_rate_limited":
		return nil, &billingError{err: ErrAPIKeyRateLimit, statusCode: 429}
	case "api_key_limit":
		return nil, &billingError{err: ErrAPIKeyLimit, statusCode: 402}
	case "ok":
		return &Authorization{AuthorizedAmount: parseMoneyOrZero(row.AuthorizedAmount), AvailableAfter: parseMoneyOrZero(row.AvailableAfter), CreatedAt: derefTime(row.CreatedAt), ExpiresAt: derefTime(row.ExpiresAt), HoldID: derefString(row.HoldID), KeyID: derefString(row.KeyID), OrganizationID: derefString(row.OrganizationID), ProductKey: productKey, ProviderKey: providerKey, RequestID: requestID, UserID: derefString(row.UserID), WorkspaceID: derefString(row.WorkspaceID)}, nil
	case "invalid_amount":
		return nil, &billingError{err: errors.New("Invalid authorization amount"), statusCode: 400}
	default:
		return nil, fmt.Errorf("unknown hold authorization result: %s", row.Result)
	}
}

func (s *Service) FinalizeRequest(ctx context.Context, authorization *Authorization, event RequestEvent) error {
	if authorization == nil {
		return nil
	}

	paramsHash := createHoldParamsHash(authorization.ProviderKey, authorization.ProductKey)
	actualCost := event.TotalCostUSDAtoms
	if actualCost == "" {
		actualCost = ZeroChargeUSDAtoms
		event.TotalCostUSDAtoms = actualCost
	}
	event.Pricing = canonicalPricing(event.Pricing)
	pricingJSON := pricingJSONString(event.Pricing)
	payload, err := encodeGatewayRequestEvent(event)
	if err != nil {
		return err
	}

	writeOutbox := true
	if s.tinybird != nil {
		writeOutbox = s.tinybird.AppendGatewayRequest(ctx, event) != nil
	}

	if err := s.settleOnce(ctx, authorization, paramsHash, actualCost, string(pricingJSON), payload, writeOutbox); err != nil {
		s.retryWG.Add(1)
		go func() {
			defer s.retryWG.Done()
			s.retrySettle(authorization, paramsHash, actualCost, string(pricingJSON), payload, event, writeOutbox)
		}()
		return nil
	}

	return nil
}

func (s *Service) settleOnce(ctx context.Context, authorization *Authorization, paramsHash string, actualCost string, pricingJSON string, payload string, writeOutbox bool) error {
	if s.settleFunc != nil {
		return s.settleFunc(ctx, authorization, paramsHash, actualCost, pricingJSON, payload, writeOutbox)
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
		pricingJSON,
		payload,
	).Scan(&row.Result, &row.FinalCost, &row.RefundAmount, &row.AvailableAfter)
	if err != nil {
		return fmt.Errorf("settle gateway hold: %w", err)
	}

	switch row.Result {
	case "complete", "over_reserved", "under_reserved", "negative_balance", "already_settled":
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

func (s *Service) retrySettle(authorization *Authorization, paramsHash string, actualCost string, pricingJSON string, payload string, event RequestEvent, writeOutbox bool) {
	deadline := time.Now().Add(durationOrDefault(s.retryWindow, settleRetryWindow))
	delay := durationOrDefault(s.retryInitialDelay, settleRetryInitialDelay)
	maxDelay := durationOrDefault(s.retryMaxDelay, settleRetryMaxDelay)
	for time.Now().Before(deadline) {
		time.Sleep(delay)
		err := s.settleOnce(context.Background(), authorization, paramsHash, actualCost, pricingJSON, payload, writeOutbox)
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
	event.Pricing = canonicalPricing(event.Pricing)
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

func pricingJSONString(pricing map[string]any) string {
	encoded, err := json.Marshal(canonicalPricing(pricing))
	if err != nil {
		return "{}"
	}
	return string(encoded)
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

func parseMoneyOrZero(value *string) *big.Int {
	return parseMoneyOrZeroString(derefString(value))
}

func derefTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}
