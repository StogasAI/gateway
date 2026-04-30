package stogas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/hkdf"
)

const (
	tokenPepperInfo                 = "stogas:token:pepper"
	placeholderChargeUsdAtoms       = "4000000000" // 4 nanoUSD at 18-decimal USD atom precision.
	poolMaxConns              int32 = 32
	poolMinConns              int32 = 4
	poolMinIdleConns          int32 = 4
	poolHealthCheckPeriod           = 30 * time.Second
	poolMaxConnIdleTime             = 5 * time.Minute
	poolMaxConnLifetime             = 30 * time.Minute
	poolMaxConnLifetimeJitter       = 5 * time.Minute
	poolWarmupTimeout               = 5 * time.Second
	poolWarmupPerConnTimeout        = 2 * time.Second
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
	ErrAPIKeyLimit         = errors.New("API key limit reached or disabled/expired")
	ErrHoldNotFound        = errors.New("Hold not found")
)

const authorizeHoldQuery = `
with input_values as (
  select
    $1::text as hashed_key,
    $2::uuid as request_id,
    $3::uuid as hold_id,
    $4::text as provider_key,
    $5::text as product_key,
    $6::numeric as authorized_amount,
    $7::timestamptz as expires_at,
    $8::text as params_hash,
    $9::jsonb as estimated_metrics,
    $10::timestamptz as now_ts
),
key_row as (
  select * from api_key where key = (select hashed_key from input_values) limit 1 for update
),
usage_exists as (
  select 1 from usage_record where request_id = (select request_id from input_values) limit 1
),
attempt_insert as (
  insert into holds (
	    id, "userId", "keyId", request_id, status, authorized_amount_usd_atoms,
    "providerKey", "productKey", "estimatedMetrics", "expiresAt", meta
  )
  select
    iv.hold_id, k."userId", k.id, iv.request_id, 'active', iv.authorized_amount,
    iv.provider_key, iv.product_key, iv.estimated_metrics, iv.expires_at,
    jsonb_build_object('paramsHash', iv.params_hash, 'gateway', 'stogas')
  from input_values iv
  join key_row k on true
  where not exists (select 1 from usage_exists)
  on conflict (request_id) do nothing
  returning *, true as is_new
),
existing_hold as (
  select h.*, false as is_new
  from holds h
  where h.request_id = (select request_id from input_values)
  for update
),
target_hold as (
  select * from attempt_insert
  union all
  select * from existing_hold
  limit 1
),
expired_balance_release as (
  update balance_account b
  set
    available_usd_atoms = b.available_usd_atoms + th.authorized_amount_usd_atoms,
    on_hold_usd_atoms = b.on_hold_usd_atoms - th.authorized_amount_usd_atoms,
    "updatedAt" = (select now_ts from input_values)
  from target_hold th
  where th.status = 'active'
    and th."expiresAt" <= (select now_ts from input_values)
    and b."userId" = th."userId"
    and b.on_hold_usd_atoms >= th.authorized_amount_usd_atoms
  returning th.id
),
expired_key_release as (
  update api_key k
  set
    on_hold_usd_atoms = k.on_hold_usd_atoms - th.authorized_amount_usd_atoms,
    "updatedAt" = (select now_ts from input_values)
  from target_hold th
  where th.status = 'active'
    and th."expiresAt" <= (select now_ts from input_values)
    and th."keyId" = k.id
    and k.on_hold_usd_atoms >= th.authorized_amount_usd_atoms
  returning th.id
),
mark_expired as (
  update holds h
  set status = 'expired', "updatedAt" = (select now_ts from input_values)
  where h.id in (select id from target_hold where status = 'active' and "expiresAt" <= (select now_ts from input_values))
  returning id
),
validation as (
  select
    th.*,
    kr.enabled as key_enabled,
    kr."expiresAt" as key_expires_at,
    kr.spend_limit_usd_atoms as key_spend_limit,
    kr.total_spent_usd_atoms as key_total_spent,
    kr.on_hold_usd_atoms as key_on_hold,
    case
      when not exists (select 1 from key_row) then 'invalid_key'
      when exists (select 1 from usage_exists) then 'usage_exists'
      when th.id is null then 'hold_missing'
      when (th.meta ->> 'paramsHash') is distinct from (select params_hash from input_values) then 'params_mismatch'
      when th.status <> 'active' then 'inactive'
      when th."expiresAt" <= (select now_ts from input_values) then 'expired'
      when kr.enabled = false then 'key_disabled'
      when kr."expiresAt" is not null and kr."expiresAt" <= (select now_ts from input_values) then 'key_expired'
      when kr.spend_limit_usd_atoms is not null
        and kr.total_spent_usd_atoms + kr.on_hold_usd_atoms + th.authorized_amount_usd_atoms > kr.spend_limit_usd_atoms then 'key_spend_limit'
      else 'ok'
    end as validation_result
  from target_hold th
  left join key_row kr on true
),
balance_apply as (
  update balance_account b
  set
    available_usd_atoms = b.available_usd_atoms - v.authorized_amount_usd_atoms,
    on_hold_usd_atoms = b.on_hold_usd_atoms + v.authorized_amount_usd_atoms,
    "updatedAt" = (select now_ts from input_values)
  from validation v
  where v.validation_result = 'ok'
    and v.is_new = true
    and b."userId" = v."userId"
    and b.available_usd_atoms >= v.authorized_amount_usd_atoms
  returning b.available_usd_atoms
),
key_apply as (
  update api_key k
  set
    on_hold_usd_atoms = k.on_hold_usd_atoms + v.authorized_amount_usd_atoms,
    "updatedAt" = (select now_ts from input_values)
  from validation v
  where v.validation_result = 'ok'
    and v.is_new = true
    and k.id = v."keyId"
    and k."userId" = v."userId"
    and k.enabled = true
    and (k."expiresAt" is null or k."expiresAt" > (select now_ts from input_values))
    and (k.spend_limit_usd_atoms is null or k.total_spent_usd_atoms + k.on_hold_usd_atoms + v.authorized_amount_usd_atoms <= k.spend_limit_usd_atoms)
  returning k.id
),
final_status as (
  select
    case
      when v.validation_result = 'invalid_key' then 'invalid_key'
      when v.validation_result <> 'ok' then v.validation_result
      when v.is_new = true and not exists (select 1 from balance_apply) then 'insufficient_balance'
      when v.is_new = true and not exists (select 1 from key_apply) then 'api_key_limit'
      else 'ok'
    end as result,
    v.id as hold_id,
    v."userId" as user_id,
    v."keyId" as key_id,
    v.authorized_amount_usd_atoms::text as authorized_amount,
    v."expiresAt" as expires_at,
    coalesce(
      (select available_usd_atoms::text from balance_apply limit 1),
      (select available_usd_atoms::text from balance_account where "userId" = v."userId" limit 1)
    ) as available_after
  from validation v
)
select * from final_status limit 1;
`

type authorizeRow struct {
	Result           string
	HoldID           *string
	UserID           *string
	KeyID            *string
	AuthorizedAmount *string
	ExpiresAt        *time.Time
	AvailableAfter   *string
}

type HoldAuthorization struct {
	AuthorizedAmount *big.Int
	AvailableAfter   *big.Int
	ExpiresAt        time.Time
	HoldID           string
	KeyID            string
	ProductKey       string
	ProviderKey      string
	RequestID        string
	UserID           string
}

type HoldService struct {
	pool        *pgxpool.Pool
	tokenPepper string
}

type holdError struct {
	err        error
	statusCode int
}

func (e *holdError) Error() string { return e.err.Error() }
func (e *holdError) Unwrap() error { return e.err }

func NewHoldService(ctx context.Context, databaseURL string, authSecret string) (*HoldService, error) {
	tokenPepper, err := deriveTokenPepper(authSecret)
	if err != nil {
		return nil, err
	}

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse postgres config: %w", err)
	}
	poolConfig.MaxConns = poolMaxConns
	poolConfig.MinConns = poolMinConns
	poolConfig.MinIdleConns = poolMinIdleConns
	poolConfig.HealthCheckPeriod = poolHealthCheckPeriod
	poolConfig.MaxConnIdleTime = poolMaxConnIdleTime
	poolConfig.MaxConnLifetime = poolMaxConnLifetime
	poolConfig.MaxConnLifetimeJitter = poolMaxConnLifetimeJitter
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = map[string]string{}
	}
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "stogas-gateway"
	poolConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "set timezone = 'UTC'")
		return err
	}

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

	return &HoldService{pool: pool, tokenPepper: tokenPepper}, nil
}

func (s *HoldService) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func (s *HoldService) AuthorizePlaceholderHold(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string) (*HoldAuthorization, error) {
	apiKeyHash := createTokenHash(rawAPIKey, s.tokenPepper)
	expiresAt := time.Now().UTC().Add(15 * time.Minute)
	holdID := uuid.NewString()
	paramsHash := createHoldParamsHash(providerKey, productKey)
	now := time.Now().UTC()

	row := authorizeRow{}
	err := s.pool.QueryRow(ctx, authorizeHoldQuery, apiKeyHash, requestID, holdID, providerKey, productKey, placeholderChargeUsdAtoms, expiresAt, paramsHash, "{}", now).Scan(
		&row.Result, &row.HoldID, &row.UserID, &row.KeyID, &row.AuthorizedAmount, &row.ExpiresAt, &row.AvailableAfter,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &holdError{err: ErrInvalidAPIKey, statusCode: 401}
		}
		return nil, fmt.Errorf("authorize placeholder hold: %w", err)
	}

	switch row.Result {
	case "invalid_key", "hold_missing":
		return nil, &holdError{err: ErrInvalidAPIKey, statusCode: 401}
	case "usage_exists":
		return nil, &holdError{err: ErrRequestAlreadyUsed, statusCode: 409}
	case "params_mismatch":
		return nil, &holdError{err: ErrHoldParamsMismatch, statusCode: 409}
	case "inactive":
		return nil, &holdError{err: ErrHoldCompleted, statusCode: 409}
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
	case "api_key_limit":
		return nil, &holdError{err: ErrAPIKeyLimit, statusCode: 402}
	case "ok":
		return &HoldAuthorization{AuthorizedAmount: parseMoneyOrZero(row.AuthorizedAmount), AvailableAfter: parseMoneyOrZero(row.AvailableAfter), ExpiresAt: derefTime(row.ExpiresAt), HoldID: derefString(row.HoldID), KeyID: derefString(row.KeyID), ProductKey: productKey, ProviderKey: providerKey, RequestID: requestID, UserID: derefString(row.UserID)}, nil
	default:
		return nil, fmt.Errorf("unknown hold authorization result: %s", row.Result)
	}
}

func (s *HoldService) FinalizePlaceholderHold(ctx context.Context, authorization *HoldAuthorization, metrics map[string]any) error {
	if authorization == nil {
		return nil
	}

	metricsJSON, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("marshal usage metrics: %w", err)
	}
	paramsHash := createHoldParamsHash(authorization.ProviderKey, authorization.ProductKey)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin finalize hold: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	hold, err := lockGatewayHold(ctx, tx, authorization.RequestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if err := validateGatewayHold(authorization, hold); err != nil {
		return err
	}

	actualCost := placeholderChargeUsdAtoms
	_, err = tx.Exec(ctx, `
insert into usage_record (request_id, "userId", "providerKey", "productKey", metrics, meta)
values ($1::uuid, $2, $3, $4, $5::jsonb, jsonb_build_object('paramsHash', $6::text, 'authorizedAmountUsdAtoms', $7::text, 'keyId', $8::text, 'gateway', 'stogas'))
on conflict (request_id) do nothing
`, hold.RequestID, hold.UserID, hold.ProviderKey, hold.ProductKey, string(metricsJSON), paramsHash, hold.AuthorizedAmount, hold.KeyID)
	if err != nil {
		return fmt.Errorf("insert usage record: %w", err)
	}

	var finalCost string
	err = tx.QueryRow(ctx, `select coalesce(final_cost_usd_atoms::text, '') from usage_record where request_id = $1::uuid limit 1`, hold.RequestID).Scan(&finalCost)
	if err != nil {
		return fmt.Errorf("load usage record: %w", err)
	}
	if finalCost != "" {
		return tx.Commit(ctx)
	}

	_, err = tx.Exec(ctx, `
insert into ledger_event (id, "userId", type, amount_usd_atoms, request_id, "usageId", meta)
values ($1::uuid, $2, 'capture', -($3::numeric), $4::uuid, $4::uuid, '{}'::jsonb)
`, uuid.NewString(), hold.UserID, actualCost, hold.RequestID)
	if err != nil && !isUniqueViolation(err) {
		return fmt.Errorf("insert capture ledger event: %w", err)
	}

	_, err = tx.Exec(ctx, `update usage_record set final_cost_usd_atoms = $2::numeric where request_id = $1::uuid`, hold.RequestID, actualCost)
	if err != nil {
		return fmt.Errorf("set final usage cost: %w", err)
	}

	commandTag, err := tx.Exec(ctx, `
update balance_account
set
  on_hold_usd_atoms = on_hold_usd_atoms - $2::numeric,
  available_usd_atoms = available_usd_atoms + ($2::numeric - $3::numeric),
  "updatedAt" = $4::timestamptz
where "userId" = $1 and on_hold_usd_atoms >= $2::numeric
`, hold.UserID, hold.AuthorizedAmount, actualCost, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("update balance during finalize: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return fmt.Errorf("update balance during finalize: no rows affected")
	}

	if hold.KeyID != "" {
		commandTag, err = tx.Exec(ctx, `
update api_key
set
  on_hold_usd_atoms = on_hold_usd_atoms - $2::numeric,
  total_spent_usd_atoms = total_spent_usd_atoms + $3::numeric,
  "updatedAt" = $4::timestamptz
where id = $1 and on_hold_usd_atoms >= $2::numeric
`, hold.KeyID, hold.AuthorizedAmount, actualCost, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("update api key during finalize: %w", err)
		}
		if commandTag.RowsAffected() == 0 {
			return fmt.Errorf("update api key during finalize: no rows affected")
		}
	}

	_, err = tx.Exec(ctx, `delete from holds where id = $1::uuid`, hold.ID)
	if err != nil {
		return fmt.Errorf("delete finalized hold: %w", err)
	}

	return tx.Commit(ctx)
}

func (s *HoldService) ReleaseHold(ctx context.Context, authorization *HoldAuthorization) error {
	if authorization == nil {
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin release hold: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	hold, err := lockGatewayHold(ctx, tx, authorization.RequestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &holdError{err: ErrHoldNotFound, statusCode: 404}
		}
		return err
	}
	if err := validateGatewayHold(authorization, hold); err != nil {
		return err
	}

	now := time.Now().UTC()
	commandTag, err := tx.Exec(ctx, `
update balance_account
set
  available_usd_atoms = available_usd_atoms + $2::numeric,
  on_hold_usd_atoms = on_hold_usd_atoms - $2::numeric,
  "updatedAt" = $3::timestamptz
where "userId" = $1 and on_hold_usd_atoms >= $2::numeric
`, hold.UserID, hold.AuthorizedAmount, now)
	if err != nil {
		return fmt.Errorf("release balance: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return fmt.Errorf("release balance: no rows affected")
	}

	if hold.KeyID != "" {
		commandTag, err = tx.Exec(ctx, `
update api_key
set on_hold_usd_atoms = on_hold_usd_atoms - $2::numeric, "updatedAt" = $3::timestamptz
where id = $1 and on_hold_usd_atoms >= $2::numeric
`, hold.KeyID, hold.AuthorizedAmount, now)
		if err != nil {
			return fmt.Errorf("release api key hold: %w", err)
		}
		if commandTag.RowsAffected() == 0 {
			return fmt.Errorf("release api key hold: no rows affected")
		}
	}

	_, err = tx.Exec(ctx, `delete from holds where id = $1::uuid`, hold.ID)
	if err != nil {
		return fmt.Errorf("delete released hold: %w", err)
	}

	return tx.Commit(ctx)
}

type gatewayHold struct {
	AuthorizedAmount string
	ID               string
	KeyID            string
	ProductKey       string
	ProviderKey      string
	RequestID        string
	Status           string
	UserID           string
	ExpiresAt        time.Time
}

func lockGatewayHold(ctx context.Context, tx pgx.Tx, requestID string) (*gatewayHold, error) {
	row := &gatewayHold{}
	err := tx.QueryRow(ctx, `
select id::text, "userId", coalesce("keyId", ''), request_id::text, status, authorized_amount_usd_atoms::text, "providerKey", "productKey", "expiresAt"
from holds
where request_id = $1::uuid
for update
limit 1
`, requestID).Scan(&row.ID, &row.UserID, &row.KeyID, &row.RequestID, &row.Status, &row.AuthorizedAmount, &row.ProviderKey, &row.ProductKey, &row.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

func validateGatewayHold(authorization *HoldAuthorization, hold *gatewayHold) error {
	if hold.UserID != authorization.UserID {
		return &holdError{err: errors.New("Hold does not belong to user"), statusCode: 403}
	}
	if hold.KeyID != authorization.KeyID {
		return &holdError{err: errors.New("Hold already linked to a different API key"), statusCode: 409}
	}
	if hold.ProviderKey != authorization.ProviderKey || hold.ProductKey != authorization.ProductKey {
		return &holdError{err: errors.New("Provider/product key mismatch with hold"), statusCode: 422}
	}
	if hold.Status != "active" {
		return &holdError{err: fmt.Errorf("Hold already %s", hold.Status), statusCode: 409}
	}
	return nil
}

func ErrorStatus(err error) int {
	var typed *holdError
	if errors.As(err, &typed) {
		return typed.statusCode
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

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
func derefTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}
