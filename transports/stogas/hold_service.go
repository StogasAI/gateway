package stogas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/hkdf"
)

const (
	tokenPepperInfo           = "stogas:token:pepper"
	signedAPIKeyPrefix        = "sk_stogas_v1_"
	signedAPIKeyPayloadBytes  = 85
	signedAPIKeyMACBytes      = 24
	signedAPIKeyBodyBytes     = signedAPIKeyPayloadBytes + signedAPIKeyMACBytes
	signedAPIKeyPersonal      = byte(1)
	signedAPIKeyExternal      = byte(2)
	signedAPIKeyProvisioned   = byte(3)
	placeholderChargeUsdAtoms = "4000000000" // 4 nanoUSD at 18-decimal USD atom precision.

	poolHealthCheckPeriod      = 30 * time.Second
	poolMaxConnIdleTime        = 5 * time.Minute
	poolMaxConnLifetime        = 30 * time.Minute
	poolMaxConnLifetimeJitter  = 5 * time.Minute
	poolWarmupTimeout          = 5 * time.Second
	poolWarmupPerConnTimeout   = 2 * time.Second
	authorizeTimeout           = 1500 * time.Millisecond
	settleTimeout              = 2 * time.Second
	settleRetryWindow          = 90 * time.Second
	settleRetryInitialDelay    = 250 * time.Millisecond
	settleRetryMaxDelay        = 5 * time.Second
	holdSettlementExpiryBuffer = 10 * time.Minute

	// GatewayRequestLifetime bounds direct inference streams so reconciliation never races a live request.
	GatewayRequestLifetime = 60 * time.Minute
	defaultHoldDuration    = GatewayRequestLifetime + holdSettlementExpiryBuffer
)

var (
	ErrAPIKeyDisabled      = errors.New("API key is disabled")
	ErrAPIKeyExpired       = errors.New("API key is expired")
	ErrInvalidAPIKey       = errors.New("Invalid API key")
	ErrRequestAlreadyUsed  = errors.New("Request already finalized; generate a new requestId")
	ErrHoldCompleted       = errors.New("Hold already completed; generate a new requestId")
	ErrHoldParamsMismatch  = errors.New("Hold already exists with different parameters")
	ErrInsufficientBalance = errors.New("Insufficient balance")
	ErrAPIKeySpendLimit    = errors.New("API key spend limit exceeded")
	ErrAPIKeyRateLimit     = errors.New("API key rate limit exceeded")
	ErrAPIKeyLimit         = errors.New("API key limit reached or disabled/expired")
	ErrGatewayUnavailable  = errors.New("Gateway billing database unavailable")
	ErrHoldNotFound        = errors.New("Hold not found")
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

const releaseHoldQuery = `
select *
from release_gateway_hold(
  $1::uuid,
  $2::text
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

type releaseRow struct {
	Result         string
	ReleasedAmount *string
	AvailableAfter *string
}

type HoldAuthorization struct {
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

type HoldService struct {
	pool              *pgxpool.Pool
	retryInitialDelay time.Duration
	retryMaxDelay     time.Duration
	retryWindow       time.Duration
	settleFunc        func(context.Context, *HoldAuthorization, string, string, string, string, bool) error
	tinybird          *TinybirdClient
	tokenPepper       string
}

type holdError struct {
	err        error
	statusCode int
}

func (e *holdError) Error() string { return e.err.Error() }
func (e *holdError) Unwrap() error { return e.err }

type settleResultError struct {
	err        error
	result     string
	statusCode int
}

func (e *settleResultError) Error() string { return e.err.Error() }
func (e *settleResultError) Unwrap() error { return e.err }

func NewHoldService(ctx context.Context, databaseURL string, databaseSchema string, authSecret string, databasePool DatabasePoolConfig, tinybird *TinybirdClient) (*HoldService, error) {
	if err := databasePool.Validate(); err != nil {
		return nil, err
	}
	searchPath, err := pgrollSearchPath(databaseSchema)
	if err != nil {
		return nil, err
	}
	tokenPepper, err := deriveTokenPepper(authSecret)
	if err != nil {
		return nil, err
	}

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse postgres config: %w", err)
	}
	poolConfig.MaxConns = databasePool.MaxConns
	poolConfig.MinConns = databasePool.MinConns
	poolConfig.MinIdleConns = databasePool.MinIdleConns
	poolConfig.HealthCheckPeriod = poolHealthCheckPeriod
	poolConfig.MaxConnIdleTime = poolMaxConnIdleTime
	poolConfig.MaxConnLifetime = poolMaxConnLifetime
	poolConfig.MaxConnLifetimeJitter = poolMaxConnLifetimeJitter
	poolConfig.ConnConfig.DefaultQueryExecMode = queryExecMode(databasePool.QueryExecMode)
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = map[string]string{}
	}
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "stogas-gateway"
	poolConfig.ConnConfig.RuntimeParams["search_path"] = searchPath
	poolConfig.ConnConfig.RuntimeParams["TimeZone"] = "UTC"

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if err := warmPool(ctx, pool, int(poolConfig.MinConns)); err != nil {
		pool.Close()
		return nil, err
	}

	return &HoldService{pool: pool, tinybird: tinybird, tokenPepper: tokenPepper}, nil
}

func queryExecMode(mode string) pgx.QueryExecMode {
	switch mode {
	case "cache_describe":
		return pgx.QueryExecModeCacheDescribe
	case "describe_exec":
		return pgx.QueryExecModeDescribeExec
	case "exec":
		return pgx.QueryExecModeExec
	case "simple_protocol":
		return pgx.QueryExecModeSimpleProtocol
	default:
		return pgx.QueryExecModeCacheStatement
	}
}

func (s *HoldService) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func (s *HoldService) ValidateAPIKeyFormat(rawAPIKey string) error {
	if s == nil {
		return ErrInvalidAPIKey
	}
	if _, err := parseSignedAPIKey(rawAPIKey, s.tokenPepper); err != nil {
		return ErrInvalidAPIKey
	}
	return nil
}

func (s *HoldService) AuthorizePlaceholderHold(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string) (*HoldAuthorization, error) {
	if err := s.ValidateAPIKeyFormat(rawAPIKey); err != nil {
		return nil, &holdError{err: ErrInvalidAPIKey, statusCode: 401}
	}

	apiKeyHash := createTokenHash(rawAPIKey, s.tokenPepper)
	expiresAt := time.Now().UTC().Add(defaultHoldDuration)
	holdID, err := newUUIDV7String()
	if err != nil {
		return nil, fmt.Errorf("generate hold id: %w", err)
	}
	paramsHash := createHoldParamsHash(providerKey, productKey)

	row := authorizeRow{}
	queryCtx, cancel := context.WithTimeout(ctx, authorizeTimeout)
	defer cancel()
	err = s.pool.QueryRow(queryCtx, authorizeHoldQuery, apiKeyHash, requestID, holdID, providerKey, productKey, placeholderChargeUsdAtoms, expiresAt, paramsHash).Scan(
		&row.Result, &row.HoldID, &row.UserID, &row.KeyID, &row.OrganizationID, &row.WorkspaceID, &row.AuthorizedAmount, &row.CreatedAt, &row.ExpiresAt, &row.AvailableAfter,
	)
	if err != nil {
		return nil, &holdError{err: fmt.Errorf("%w: %v", ErrGatewayUnavailable, err), statusCode: 503}
	}

	switch row.Result {
	case "invalid_key", "hold_missing":
		return nil, &holdError{err: ErrInvalidAPIKey, statusCode: 401}
	case "usage_exists":
		return nil, &holdError{err: ErrRequestAlreadyUsed, statusCode: 409}
	case "params_mismatch":
		return nil, &holdError{err: ErrHoldParamsMismatch, statusCode: 409}
	case "expired":
		return nil, &holdError{err: ErrRequestAlreadyUsed, statusCode: 409}
	case "insufficient_balance":
		return nil, &holdError{err: ErrInsufficientBalance, statusCode: 402}
	case "key_disabled":
		return nil, &holdError{err: ErrAPIKeyDisabled, statusCode: 403}
	case "key_expired":
		return nil, &holdError{err: ErrAPIKeyExpired, statusCode: 403}
	case "key_spend_limit":
		return nil, &holdError{err: ErrAPIKeySpendLimit, statusCode: 402}
	case "key_rate_limited":
		return nil, &holdError{err: ErrAPIKeyRateLimit, statusCode: 429}
	case "api_key_limit":
		return nil, &holdError{err: ErrAPIKeyLimit, statusCode: 402}
	case "ok":
		return &HoldAuthorization{AuthorizedAmount: parseMoneyOrZero(row.AuthorizedAmount), AvailableAfter: parseMoneyOrZero(row.AvailableAfter), CreatedAt: derefTime(row.CreatedAt), ExpiresAt: derefTime(row.ExpiresAt), HoldID: derefString(row.HoldID), KeyID: derefString(row.KeyID), OrganizationID: derefString(row.OrganizationID), ProductKey: productKey, ProviderKey: providerKey, RequestID: requestID, UserID: derefString(row.UserID), WorkspaceID: derefString(row.WorkspaceID)}, nil
	case "invalid_amount":
		return nil, &holdError{err: errors.New("Invalid authorization amount"), statusCode: 400}
	default:
		return nil, fmt.Errorf("unknown hold authorization result: %s", row.Result)
	}
}

func (s *HoldService) FinalizePlaceholderHold(ctx context.Context, authorization *HoldAuthorization, event GatewayRequestEvent) error {
	if authorization == nil {
		return nil
	}

	metricsJSON := metricsJSONString(event.Metrics)
	paramsHash := createHoldParamsHash(authorization.ProviderKey, authorization.ProductKey)
	actualCost := event.TotalCostUSDAtoms
	if actualCost == "" {
		actualCost = placeholderChargeUsdAtoms
		event.TotalCostUSDAtoms = actualCost
	}
	payload, err := encodeGatewayRequestEvent(event)
	if err != nil {
		return err
	}

	writeOutbox := true
	if s.tinybird != nil {
		writeOutbox = s.tinybird.AppendGatewayRequest(ctx, event) != nil
	}

	if err := s.settleOnce(ctx, authorization, paramsHash, actualCost, string(metricsJSON), payload, writeOutbox); err != nil {
		go s.retrySettle(authorization, paramsHash, actualCost, string(metricsJSON), payload, event, writeOutbox)
		return nil
	}

	return nil
}

func (s *HoldService) ReleaseHold(ctx context.Context, authorization *HoldAuthorization) error {
	if authorization == nil {
		return nil
	}

	return s.releaseOnce(ctx, authorization, "provider_error")
}

func (s *HoldService) settleOnce(ctx context.Context, authorization *HoldAuthorization, paramsHash string, actualCost string, metricsJSON string, payload string, writeOutbox bool) error {
	if s.settleFunc != nil {
		return s.settleFunc(ctx, authorization, paramsHash, actualCost, metricsJSON, payload, writeOutbox)
	}

	queryCtx, cancel := context.WithTimeout(ctx, settleTimeout)
	defer cancel()

	row := settleRow{}
	query := settleHoldQuery
	if writeOutbox {
		query = settleHoldWithOutboxQuery
	}
	err := s.pool.QueryRow(
		queryCtx,
		query,
		authorization.RequestID,
		authorization.KeyID,
		authorization.ProviderKey,
		authorization.ProductKey,
		paramsHash,
		actualCost,
		metricsJSON,
		payload,
	).Scan(&row.Result, &row.FinalCost, &row.RefundAmount, &row.AvailableAfter)
	if err != nil {
		return fmt.Errorf("settle gateway hold: %w", err)
	}

	switch row.Result {
	case "complete", "over_reserved", "under_reserved", "negative_balance", "already_settled":
		return nil
	case "hold_not_found":
		return &settleResultError{err: ErrHoldNotFound, result: row.Result, statusCode: 404}
	case "params_mismatch":
		return &settleResultError{err: ErrHoldCompleted, result: row.Result, statusCode: 409}
	case "invalid_amount", "invalid_payload", "payload_mismatch":
		return &settleResultError{err: errors.New("Invalid settlement payload"), result: row.Result, statusCode: 400}
	default:
		return fmt.Errorf("unknown settlement result: %s", row.Result)
	}
}

func (s *HoldService) retrySettle(authorization *HoldAuthorization, paramsHash string, actualCost string, metricsJSON string, payload string, event GatewayRequestEvent, writeOutbox bool) {
	deadline := time.Now().Add(durationOrDefault(s.retryWindow, settleRetryWindow))
	delay := durationOrDefault(s.retryInitialDelay, settleRetryInitialDelay)
	maxDelay := durationOrDefault(s.retryMaxDelay, settleRetryMaxDelay)
	var lastErr error
	for time.Now().Before(deadline) {
		time.Sleep(delay)
		if err := s.settleOnce(context.Background(), authorization, paramsHash, actualCost, metricsJSON, payload, writeOutbox); err == nil {
			return
		} else {
			if isPermanentSettleError(err) {
				return
			}
			lastErr = err
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}

	if lastErr == nil {
		lastErr = errors.New("postgres settlement did not commit after retry window")
	}
	if writeOutbox {
		s.publishUncommittedFallback(authorization, event, lastErr)
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

func (s *HoldService) releaseOnce(ctx context.Context, authorization *HoldAuthorization, reason string) error {
	queryCtx, cancel := context.WithTimeout(ctx, settleTimeout)
	defer cancel()

	row := releaseRow{}
	err := s.pool.QueryRow(queryCtx, releaseHoldQuery, authorization.RequestID, reason).Scan(
		&row.Result, &row.ReleasedAmount, &row.AvailableAfter,
	)
	if err != nil {
		return fmt.Errorf("release gateway hold: %w", err)
	}

	switch row.Result {
	case "provider_error", "expired", "released", "already_released":
		return nil
	case "hold_not_found":
		return &holdError{err: ErrHoldNotFound, statusCode: 404}
	default:
		return fmt.Errorf("unknown release result: %s", row.Result)
	}
}

func settlementStatus(authorization *HoldAuthorization, actualCost string) string {
	actual := parseMoneyOrZero(&actualCost)
	refund := new(big.Int).Sub(new(big.Int).Set(authorization.AuthorizedAmount), actual)
	switch {
	case refund.Sign() == 0:
		return "complete"
	case refund.Sign() > 0:
		return "over_reserved"
	default:
		availableAfter := new(big.Int).Add(new(big.Int).Set(authorization.AvailableAfter), refund)
		if availableAfter.Sign() < 0 {
			return "negative_balance"
		}
		return "under_reserved"
	}
}

func encodeGatewayRequestEvent(event GatewayRequestEvent) (string, error) {
	if event.Metrics == nil {
		event.Metrics = map[string]any{}
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("marshal gateway request log payload: %w", err)
	}
	return string(encoded), nil
}

func (s *HoldService) publishUncommittedFallback(authorization *HoldAuthorization, event GatewayRequestEvent, _ error) {
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

func metricsJSONString(metrics map[string]any) string {
	if len(metrics) == 0 {
		return "{}"
	}
	encoded, err := json.Marshal(metrics)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func ErrorStatus(err error) int {
	var typed *holdError
	if errors.As(err, &typed) {
		return typed.statusCode
	}
	var settleErr *settleResultError
	if errors.As(err, &settleErr) {
		return settleErr.statusCode
	}
	return 500
}

func deriveTokenPepper(authSecret string) (string, error) {
	reader := hkdf.New(sha256.New, []byte(authSecret), nil, []byte(tokenPepperInfo))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(reader, derived); err != nil {
		return "", fmt.Errorf("derive token pepper: %w", err)
	}
	return hex.EncodeToString(derived), nil
}

type signedAPIKeyClaims struct {
	KeyID          string
	KeyType        byte
	KeyVersion     uint32
	OrganizationID string
	ProvisioningID *string
	ResponsibleID  string
	WorkspaceID    string
}

func parseSignedAPIKey(rawKey string, tokenPepper string) (*signedAPIKeyClaims, error) {
	if !strings.HasPrefix(rawKey, signedAPIKeyPrefix) {
		return nil, ErrInvalidAPIKey
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rawKey, signedAPIKeyPrefix))
	if err != nil || len(body) != signedAPIKeyBodyBytes {
		return nil, ErrInvalidAPIKey
	}

	payload := body[:signedAPIKeyPayloadBytes]
	actualMAC := body[signedAPIKeyPayloadBytes:]
	hasher := hmac.New(sha256.New, []byte(tokenPepper))
	_, _ = hasher.Write(payload)
	expectedMAC := hasher.Sum(nil)[:signedAPIKeyMACBytes]
	if !hmac.Equal(actualMAC, expectedMAC) {
		return nil, ErrInvalidAPIKey
	}

	keyID, err := uuid.FromBytes(payload[4:20])
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	organizationID, err := uuid.FromBytes(payload[20:36])
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	workspaceID, err := uuid.FromBytes(payload[36:52])
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	responsibleID, err := uuid.FromBytes(payload[52:68])
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	keyType := payload[68]
	provisioningID, err := uuid.FromBytes(payload[69:85])
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	var provisioningIDString *string
	switch keyType {
	case signedAPIKeyPersonal, signedAPIKeyExternal:
		if provisioningID != uuid.Nil {
			return nil, ErrInvalidAPIKey
		}
	case signedAPIKeyProvisioned:
		if provisioningID == uuid.Nil {
			return nil, ErrInvalidAPIKey
		}
		value := provisioningID.String()
		provisioningIDString = &value
	default:
		return nil, ErrInvalidAPIKey
	}

	return &signedAPIKeyClaims{
		KeyID:          keyID.String(),
		KeyType:        keyType,
		KeyVersion:     binary.BigEndian.Uint32(payload[0:4]),
		OrganizationID: organizationID.String(),
		ProvisioningID: provisioningIDString,
		ResponsibleID:  responsibleID.String(),
		WorkspaceID:    workspaceID.String(),
	}, nil
}

func createTokenHash(token string, tokenPepper string) string {
	hasher := hmac.New(sha512.New, []byte(tokenPepper))
	_, _ = hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}

func createHoldParamsHash(providerKey string, productKey string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(providerKey))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(productKey))
	return hex.EncodeToString(hasher.Sum(nil))
}

func newUUIDV7String() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func warmPool(parent context.Context, pool *pgxpool.Pool, target int) error {
	if target <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, poolWarmupTimeout)
	defer cancel()
	conns := make([]*pgxpool.Conn, 0, target)
	for i := 0; i < target; i++ {
		acquireCtx, acquireCancel := context.WithTimeout(ctx, poolWarmupPerConnTimeout)
		conn, err := pool.Acquire(acquireCtx)
		acquireCancel()
		if err != nil {
			for _, acquired := range conns {
				acquired.Release()
			}
			return fmt.Errorf("warm postgres pool: %w", err)
		}
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		conn.Release()
	}
	return nil
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func parseMoneyOrZero(value *string) *big.Int {
	if value == nil || *value == "" {
		return big.NewInt(0)
	}
	parsed, ok := new(big.Int).SetString(*value, 10)
	if !ok {
		return big.NewInt(0)
	}
	return parsed
}

func derefTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}
