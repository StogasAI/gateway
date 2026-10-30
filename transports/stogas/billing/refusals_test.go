package billing

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQL refuses every request here. A client slower than the hold-back
// reaches PostgreSQL every time and sees its real refusal; a runaway client
// reaches it once per hold-back, however long it keeps going.
func TestRefusalHoldBackUnderContinuousTraffic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rate    int
		reached int
	}{
		{"script slower than the hold-back", 20, 200},
		{"client at the hold-back", 40, 400},
		{"runaway client", 10000, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var refusals refusalCache
			start := time.Unix(1_700_000_000, 0)
			reached := 0
			for i := range tc.rate * 10 {
				now := start.Add(time.Duration(i) * time.Second / time.Duration(tc.rate))
				if err := refusals.get("api:secret", now); err != nil {
					var retry *retryAfterError
					if !errors.As(err, &retry) || !errors.Is(err, ErrRateLimit) || retry.RetryAfter() <= 0 || retry.RetryAfter() > refusalHoldBack {
						t.Fatalf("hold-back = %v", err)
					}
					continue
				}
				reached++
				refusals.record("api:secret", nil, refusalHoldBack, now)
			}
			if reached != tc.reached {
				t.Fatalf("PostgreSQL saw %d requests, want %d", reached, tc.reached)
			}
		})
	}
}

func TestOnlyDatabaseRefusalsHoldBack(t *testing.T) {
	claims := &APIKeyClaims{admissionKey: "api:secret"}
	for _, code := range []string{
		"invalid_request", "request_too_large", "model_unavailable", "encryption_key_required",
		"ip_rate_limit_exceeded", "rate_limit_exceeded", "gateway_capacity_exceeded", "gateway_unavailable",
		"key_configuration_changed", "provider_unavailable", "upstream_rate_limit_error", "request_timeout", "internal_error",
	} {
		s := &Service{}
		s.RecordRefusal(claims, nil, code)
		if err := s.refusals.get(claims.admissionKey, time.Now()); err != nil {
			t.Errorf("%s held the secret back: %v", code, err)
		}
	}
	for _, code := range []string{
		"insufficient_balance", "key_rate_limited", "organization_spend_limit", "member_token_limit",
		"key_concurrency_limit", "key_disabled", "byok_unavailable", "dashboard_key_denied",
	} {
		s := &Service{}
		s.RecordRefusal(claims, nil, code)
		if err := s.refusals.get(claims.admissionKey, time.Now()); !errors.Is(err, ErrRateLimit) {
			t.Errorf("%s did not hold the secret back: %v", code, err)
		}
	}
}

// A limit's refusal tells the client when PostgreSQL expects it to end, and
// the request still tries its next pair. A refusal that waiting cannot end
// gives no time. The platform request rate covers every pair.
func TestDatabaseLimitRefusalsTellClientsWhenTheyEnd(t *testing.T) {
	wait := int64(1500)
	err := authorizationResultError("organization_rate_limited", &wait)
	var retry interface{ RetryAfter() time.Duration }
	if !errors.As(err, &retry) || retry.RetryAfter() != 1500*time.Millisecond || !PairRefused(err) || ErrorStatus(err) != 429 {
		t.Fatalf("limit refusal = %v", err)
	}
	if err := authorizationResultError("key_token_limit", nil); errors.As(err, &retry) || !PairRefused(err) || ErrorStatus(err) != 429 {
		t.Fatalf("lasting refusal = %v", err)
	}
	// A limit that resets every 1,000 years can wait longer than a Duration holds.
	millennium := int64(1000 * 366 * 24 * 3_600_000)
	if err := authorizationResultError("key_rate_limited", &millennium); !errors.As(err, &retry) || retry.RetryAfter() < 292*365*24*time.Hour {
		t.Fatalf("millennium refusal = %v", err)
	}
	if err := authorizationResultError("platform_rate_limited", &wait); !errors.As(err, &retry) || PairRefused(err) || !errors.Is(err, ErrPlatformRateLimit) {
		t.Fatalf("platform refusal = %v", err)
	}
}

// Rotation keeps the key ID, and the replaced secret still passes the MAC
// check. Its refusal must not reach the current secret, sibling keys or
// dashboard sessions, and dashboard refusals must not hold back API secrets.
func TestRefusalsIsolateSecretsAndDashboardSessions(t *testing.T) {
	const secret = "test-api-key-pepper"
	org := "019de516-7df8-71d6-80e4-3c62090d4e94"
	user := "019de516-b10f-786f-97f8-b95c71dfe1b6"
	replaced := testSignedAPIKey(t, secret, "019de515-eabf-7c0e-89bd-400629a79580", org, user, "", apiKeyVersion)
	current := resignTestAPIKey(t, secret, replaced, func(payload []byte) { payload[apiKeyPayloadBytes-1] ^= 0xff })
	sibling := testSignedAPIKey(t, secret, "019de515-eabf-7c0e-89bd-400629a79581", org, user, "", apiKeyVersion)
	service := &Service{apiKeyPepper: secret}
	replacedClaims, err := service.ParseAPIKey(replaced)
	if err != nil {
		t.Fatal(err)
	}
	currentClaims, err := service.ParseAPIKey(current)
	if err != nil || currentClaims.KeyID != replacedClaims.KeyID {
		t.Fatalf("reissued secret: %v", err)
	}
	service.RecordRefusal(replacedClaims, nil, ErrAPIKeyOldSecret.Code)
	if _, err := service.ParseAPIKey(replaced); !errors.Is(err, ErrAPIKeyOldSecret) {
		t.Fatalf("replaced secret was not refused: %v", err)
	}
	for _, raw := range []string{current, sibling} {
		if _, err := service.ParseAPIKey(raw); err != nil {
			t.Fatalf("another secret shared the refusal: %v", err)
		}
	}
	dashboard := &DashboardCredential{ActorUserID: "actor", SessionID: "session", KeyID: currentClaims.KeyID}
	if service.refusals.get(dashboardAdmissionKey(dashboard), time.Now()) != nil {
		t.Fatal("a replaced secret held back a dashboard session")
	}
	// Dashboard requests carry the selected key's claims.
	service.RecordRefusal(currentClaims, dashboard, ErrDashboardKeyDenied.Code)
	if err := service.refusals.get(dashboardAdmissionKey(dashboard), time.Now()); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("dashboard session was not held back: %v", err)
	}
	if _, err := service.ParseAPIKey(current); err != nil {
		t.Fatalf("dashboard refusal held back the API secret: %v", err)
	}
}

// A refusal recorded while a request waited in its organization's queue holds
// that request back before it asks PostgreSQL. A move of an admitted request
// still asks.
func TestRefusalHoldsBackRequestsWaitingInTheirQueue(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go acceptPostgres(listener, nil)
	pool, err := pgxpool.New(context.Background(), "postgres://unused:unused@"+listener.Addr().String()+"/unused?sslmode=disable&connect_timeout=1&pool_max_conns=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var cache keyConfigCache
	snapshot := credentialPolicySnapshot(t, &cache, "org", json.RawMessage(`null`), nil)
	service := &Service{db: &GatewayDB{pool: pool}, authorizeHoldQuery: "select 1", closeRequestQuery: "select 1"}
	defer service.Close()
	claims := *snapshot.Claims
	claims.admissionKey = "api:secret"
	authorize := func(previous *Authorization) error {
		prepared, err := service.PrepareCredential(snapshot, "chutes", 0, nil)
		if err != nil {
			return err
		}
		_, err = service.authorizeResolvedRequest(context.Background(), "hash", &claims, HoldRequest{RequestID: "request", ProviderKey: "chutes", ProductKey: "product", EstimatedUpstreamCostUSD: "0.01", Snapshot: snapshot, Prepared: prepared, RequestLifetime: time.Minute, Previous: previous})
		return err
	}
	// The queue waits for the only connection.
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	go func() { waiting <- authorize(nil) }()
	waitFor(t, func() bool { return service.authorizations.inFlight.Load() == 1 })
	service.refusals.record(claims.admissionKey, nil, time.Hour, time.Now())
	conn.Release()
	if err := <-waiting; !errors.Is(err, ErrRateLimit) {
		t.Fatalf("waiting request got %v", err)
	}
	if err := authorize(&Authorization{holdID: "hold"}); !errors.Is(err, ErrGatewayUnavailable) {
		t.Fatalf("move got %v, want the unanswered statement", err)
	}
}

func TestRefusalsAreBounded(t *testing.T) {
	var refusals refusalCache
	now := time.Unix(1_700_000_000, 0)
	for index := range localAdmissionShards * localAdmissionEntriesPerShard * 2 {
		refusals.record(strconv.Itoa(index), nil, time.Minute, now)
	}
	for index := range refusals.shards {
		if len(refusals.shards[index].entries) > localAdmissionEntriesPerShard {
			t.Fatal("refusals grew without bound")
		}
	}
}
