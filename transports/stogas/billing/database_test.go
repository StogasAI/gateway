package billing

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidateDatabaseSchemaRejectsMalformedSchema(t *testing.T) {
	if err := ValidateDatabaseSchema("public;drop schema public"); err == nil {
		t.Fatal("ValidateDatabaseSchema returned nil error for malformed schema")
	}
}

func TestValidateDatabaseSchemaRequiresSchema(t *testing.T) {
	if err := ValidateDatabaseSchema("  "); err == nil {
		t.Fatal("ValidateDatabaseSchema returned nil error for an empty schema")
	}
}

// Only a statement that left the gateway can have created a hold, so only that
// one starts a close. The server here accepts statements and never answers.
func TestAuthorizationClosesOnlyAfterSendingItsStatement(t *testing.T) {
	for _, sent := range []bool{false, true} {
		t.Run(fmt.Sprintf("sent=%t", sent), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			if sent {
				defer listener.Close()
				go acceptPostgres(listener, nil)
			} else {
				listener.Close()
			}
			pool, err := pgxpool.New(context.Background(), "postgres://unused:unused@"+address+"/unused?sslmode=disable&connect_timeout=1")
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			var cache keyConfigCache
			snapshot := credentialPolicySnapshot(t, &cache, "org", json.RawMessage(`null`), nil)
			service := &Service{db: &GatewayDB{pool: pool}, authorizeHoldQuery: "select 1", closeRequestQuery: "select 1"}
			defer service.Close()
			prepared, err := service.PrepareCredential(snapshot, "chutes", 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			var kept, released atomic.Int32
			keep := func() func() {
				kept.Add(1)
				return func() { released.Add(1) }
			}
			_, err = service.authorizeResolvedRequest(context.Background(), "hash", snapshot.Claims, HoldRequest{RequestID: "request", ProviderKey: "chutes", ProductKey: "product", EstimatedUpstreamCostUSD: "0.01", Snapshot: snapshot, Prepared: prepared, RequestLifetime: time.Minute, KeepMemory: keep})
			if !errors.Is(err, ErrGatewayUnavailable) {
				t.Fatalf("authorization error = %v", err)
			}
			want := 0
			if sent {
				want = 1
			}
			// The close keeps the request's settlement place and memory until it
			// ends, and admission stays open while the database is unreachable.
			got := service.Diagnostics().Settlement
			if got.Closing != int64(want) || got.Reserved != want || kept.Load() != int32(want) || released.Load() != 0 || !service.FinalizationReady() {
				t.Fatalf("closes = %d, places taken = %d and memory kept %d times, want %d", got.Closing, got.Reserved, kept.Load(), want)
			}
			service.closeFinalizations()
			if released.Load() != kept.Load() {
				t.Fatalf("an ended close released memory %d of %d times", released.Load(), kept.Load())
			}
		})
	}
}

// Waiting in the organization's queue or for a connection ends a statement
// reserve before the authorization deadline, so a statement that starts can
// finish.
func TestAuthorizationWaitsEndBeforeTheStatementReserve(t *testing.T) {
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
	service := &Service{db: &GatewayDB{pool: pool}, authorizeHoldQuery: "select 1", closeRequestQuery: "select 1"}
	defer service.Close()
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	// Two requests of "busy" share its queue, and "idle" waits alone.
	organizations := []string{"busy", "busy", "idle"}
	errs := make([]error, len(organizations))
	elapsed := make([]time.Duration, len(organizations))
	var authorizations sync.WaitGroup
	for index, organization := range organizations {
		var cache keyConfigCache
		snapshot := credentialPolicySnapshot(t, &cache, organization, json.RawMessage(`null`), nil)
		prepared, err := service.PrepareCredential(snapshot, "chutes", 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		authorizations.Go(func() {
			started := time.Now()
			_, errs[index] = service.authorizeResolvedRequest(context.Background(), "hash", snapshot.Claims, HoldRequest{RequestID: fmt.Sprint("request-", index), ProviderKey: "chutes", ProductKey: "product", EstimatedUpstreamCostUSD: "0.01", Snapshot: snapshot, Prepared: prepared, RequestLifetime: time.Minute})
			elapsed[index] = time.Since(started)
		})
	}
	authorizations.Wait()
	for index, organization := range organizations {
		if !errors.Is(errs[index], ErrGatewayUnavailable) || elapsed[index] < authorizeTimeout-authorizeStatementReserve || elapsed[index] >= authorizeTimeout {
			t.Fatalf("%s failed with %v after %s", organization, errs[index], elapsed[index])
		}
	}
	if waits, timeouts := service.organizationQueues.waits.Load(), service.organizationQueues.timeouts.Load(); waits != 1 || timeouts != 3 {
		t.Fatalf("organization waits %d and timeouts %d, want 1 and 3", waits, timeouts)
	}
	if closing := service.finalizations.closing.Load(); closing != 0 {
		t.Fatalf("closes = %d, want 0", closing)
	}
}

// Authorizations of one organization that arrive while its statement runs
// share the next statement, in arrival order, and each gets its own result.
// Another organization's statements run meanwhile.
func TestOrganizationAuthorizationsShareStatements(t *testing.T) {
	const waiting = 30
	first, released := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var statements [][]string
	service := scriptedService(t, 4, func(statement fakeStatement) ([]fakeRow, *pgproto3.ErrorResponse) {
		mu.Lock()
		statements = append(statements, statement.products)
		count := len(statements)
		mu.Unlock()
		if count == 1 {
			close(first)
			<-released
		}
		return limitRows(statement), nil
	})
	results := make([]error, waiting+1)
	var authorizations sync.WaitGroup
	authorize := func(organization string, index int) {
		authorizations.Go(func() { results[index] = authorizeProduct(t, service, organization, index) })
	}
	authorize("a", 0)
	<-first
	for index := 1; index <= waiting; index++ {
		authorize("a", index)
		waitFor(t, func() bool { return service.organizationQueues.waits.Load() == uint64(index) })
	}
	if err := authorizeProduct(t, service, "b", 99); !retriesAfter(err, 99) {
		t.Fatalf("another organization waited for this one: %v", err)
	}
	close(released)
	authorizations.Wait()
	for index, err := range results {
		if !retriesAfter(err, index) {
			t.Fatalf("authorization %d got %v", index, err)
		}
	}
	want := []string{"a-0"}
	for index := 1; index <= waiting; index++ {
		want = append(want, fmt.Sprint("a-", index))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(statements) != 3 || !slices.Equal(statements[0], want[:1]) || !slices.Equal(statements[2], want[1:]) {
		t.Fatalf("statements = %v", statements)
	}
	if diagnostics := service.localAdmissionDiagnostics(); diagnostics.OrganizationBatches != 1 || diagnostics.OrganizationBatchedRequests != waiting || diagnostics.OrganizationLargestBatch != waiting {
		t.Fatalf("batch diagnostics = %#v", diagnostics)
	}
}

// A batch that finds its organization busy runs again in its order, and one
// that PostgreSQL rolled back runs again one authorization at a time, so a bad
// request fails alone.
func TestBusyAndRolledBackBatchesRunAgain(t *testing.T) {
	first, released := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var statements [][]string
	service := scriptedService(t, 1, func(statement fakeStatement) ([]fakeRow, *pgproto3.ErrorResponse) {
		mu.Lock()
		statements = append(statements, statement.products)
		count := len(statements)
		mu.Unlock()
		switch {
		case count == 1:
			close(first)
			<-released
		case count == 2:
			rows := make([]fakeRow, len(statement.products))
			for index := range rows {
				rows[index] = fakeRow{result: "organization_busy", waitMS: -1}
			}
			return rows, nil
		case statement.batch, statement.products[0] == "a-2":
			return nil, &pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: "40P01", Message: "deadlock detected"}
		}
		return limitRows(statement), nil
	})
	results := make([]error, 4)
	var authorizations sync.WaitGroup
	authorizations.Go(func() { results[0] = authorizeProduct(t, service, "a", 0) })
	<-first
	for index := 1; index < len(results); index++ {
		authorizations.Go(func() { results[index] = authorizeProduct(t, service, "a", index) })
		waitFor(t, func() bool { return service.organizationQueues.waits.Load() == uint64(index) })
	}
	close(released)
	authorizations.Wait()
	for index, err := range results {
		if index == 2 {
			if !errors.Is(err, ErrGatewayUnavailable) {
				t.Fatalf("the bad request got %v", err)
			}
		} else if !retriesAfter(err, index) {
			t.Fatalf("authorization %d got %v", index, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := [][]string{{"a-0"}, {"a-1", "a-2", "a-3"}, {"a-1", "a-2", "a-3"}, {"a-1"}, {"a-2"}, {"a-3"}}
	if !slices.EqualFunc(statements, want, slices.Equal) {
		t.Fatalf("statements = %v, want %v", statements, want)
	}
	if busy := service.organizationQueues.busy.Load(); busy != 1 {
		t.Fatalf("busy statements = %d", busy)
	}
	// The rolled-back batch ran again, so only the bad request's statement
	// failed, and the statement after it was answered.
	if diagnostics := service.localAdmissionDiagnostics(); diagnostics.AuthorizationFailures != 1 ||
		diagnostics.AuthorizationLastFailedAt == nil || diagnostics.AuthorizationFailingSince != nil {
		t.Fatalf("authorization failures %d, last %v, failing since %v", diagnostics.AuthorizationFailures,
			diagnostics.AuthorizationLastFailedAt, diagnostics.AuthorizationFailingSince)
	}
}

// A caller that leaves while its authorization waits takes it out of the
// queue, and also while a statement that finds the organization busy has it.
// It gets the cancellation, which the gateway answers with nothing, and no
// later statement includes it.
func TestAuthorizationWhoseCallerLeavesLeavesTheQueue(t *testing.T) {
	first, busy, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var statements [][]string
	service := scriptedService(t, 1, func(statement fakeStatement) ([]fakeRow, *pgproto3.ErrorResponse) {
		mu.Lock()
		statements = append(statements, statement.products)
		count := len(statements)
		mu.Unlock()
		switch count {
		case 1:
			close(first)
			<-released
		case 2:
			close(busy)
			<-released
			rows := make([]fakeRow, len(statement.products))
			for index := range rows {
				rows[index] = fakeRow{result: "organization_busy", waitMS: -1}
			}
			return rows, nil
		}
		return limitRows(statement), nil
	})
	results := make([]error, 5)
	answered := make([]chan struct{}, len(results))
	callers := make([]context.CancelFunc, len(results))
	var authorizations sync.WaitGroup
	for index := range results {
		var ctx context.Context
		ctx, callers[index] = context.WithCancel(context.Background())
		defer callers[index]()
		answered[index] = make(chan struct{})
		authorizations.Go(func() {
			defer close(answered[index])
			results[index] = authorizeProductUntil(ctx, t, service, "a", index)
		})
		if index == 0 {
			<-first
		} else {
			waitFor(t, func() bool { return service.organizationQueues.waits.Load() == uint64(index) })
		}
	}
	// a-2's caller leaves while it waits. The first statement then ends, the
	// next takes the others, and a-3's caller leaves while it runs.
	callers[2]()
	<-answered[2]
	released <- struct{}{}
	<-busy
	callers[3]()
	close(released)
	authorizations.Wait()
	for index, err := range results {
		if index == 2 || index == 3 {
			if !errors.Is(err, context.Canceled) || errors.Is(err, ErrGatewayUnavailable) {
				t.Fatalf("authorization %d whose caller left got %v", index, err)
			}
		} else if !retriesAfter(err, index) {
			t.Fatalf("authorization %d got %v", index, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := [][]string{{"a-0"}, {"a-1", "a-3", "a-4"}, {"a-1", "a-4"}}
	if !slices.EqualFunc(statements, want, slices.Equal) {
		t.Fatalf("statements = %v, want %v", statements, want)
	}
	if diagnostics := service.localAdmissionDiagnostics(); diagnostics.OrganizationTimeouts != 0 || diagnostics.AuthorizationFailures != 0 {
		t.Fatalf("callers that left counted as timeouts %d or failures %d", diagnostics.OrganizationTimeouts, diagnostics.AuthorizationFailures)
	}
}

// The monitor reads when authorizations started failing. Failures keep that
// time, and the first statement that PostgreSQL answers clears it.
func TestAuthorizationFailuresLastUntilPostgreSQLAnswers(t *testing.T) {
	var statements atomic.Int64
	service := scriptedService(t, 1, func(statement fakeStatement) ([]fakeRow, *pgproto3.ErrorResponse) {
		if statements.Add(1) <= 2 {
			return nil, &pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: "25006", Message: "cannot execute INSERT in a read-only transaction"}
		}
		return limitRows(statement), nil
	})
	if err := authorizeProduct(t, service, "a", 0); !errors.Is(err, ErrGatewayUnavailable) {
		t.Fatalf("first authorization got %v", err)
	}
	first := service.localAdmissionDiagnostics()
	if first.AuthorizationFailures != 1 || first.AuthorizationFailingSince == nil || first.AuthorizationLastFailedAt == nil ||
		!first.AuthorizationFailingSince.Equal(*first.AuthorizationLastFailedAt) {
		t.Fatalf("after one failure: %+v", first)
	}
	time.Sleep(2 * time.Millisecond)
	if err := authorizeProduct(t, service, "b", 0); !errors.Is(err, ErrGatewayUnavailable) {
		t.Fatalf("second authorization got %v", err)
	}
	second := service.localAdmissionDiagnostics()
	if second.AuthorizationFailures != 2 || !second.AuthorizationFailingSince.Equal(*first.AuthorizationFailingSince) ||
		!second.AuthorizationLastFailedAt.After(*first.AuthorizationLastFailedAt) {
		t.Fatalf("after two failures: %+v", second)
	}
	if err := authorizeProduct(t, service, "c", 0); !retriesAfter(err, 0) {
		t.Fatalf("answered authorization got %v", err)
	}
	answered := service.localAdmissionDiagnostics()
	if answered.AuthorizationFailures != 2 || answered.AuthorizationFailingSince != nil ||
		!answered.AuthorizationLastFailedAt.Equal(*second.AuthorizationLastFailedAt) {
		t.Fatalf("after an answer: %+v", answered)
	}
}

// A batch whose connection fails before PostgreSQL answers may have committed
// any of its holds, as in a failover, so each of its first authorizations
// closes its request.
func TestBatchLostWithItsConnectionClosesEachRequest(t *testing.T) {
	first, released := make(chan struct{}), make(chan struct{})
	var statements atomic.Int32
	service := scriptedService(t, 1, func(statement fakeStatement) ([]fakeRow, *pgproto3.ErrorResponse) {
		if statements.Add(1) == 1 {
			close(first)
			<-released
			return limitRows(statement), nil
		}
		return nil, dropConnection
	})
	results := make([]error, 4)
	var authorizations sync.WaitGroup
	authorizations.Go(func() { results[0] = authorizeProduct(t, service, "a", 0) })
	<-first
	for index := 1; index < len(results); index++ {
		authorizations.Go(func() { results[index] = authorizeProduct(t, service, "a", index) })
		waitFor(t, func() bool { return service.organizationQueues.waits.Load() == uint64(index) })
	}
	close(released)
	authorizations.Wait()
	if !retriesAfter(results[0], 0) {
		t.Fatalf("the answered authorization got %v", results[0])
	}
	for index, err := range results[1:] {
		if !errors.Is(err, ErrGatewayUnavailable) {
			t.Fatalf("authorization %d got %v", index+1, err)
		}
	}
	// Each close waits for its authorization deadline before it runs.
	if closing := service.finalizations.closing.Load(); closing != 3 {
		t.Fatalf("closes = %d, want 3", closing)
	}
	waitFor(t, func() bool { return service.finalizations.closing.Load() == 0 })
}

// Requests keep arriving while the database accepts statements and never
// answers them. Each statement in flight costs one settlement place for its
// close, so the pool bounds the places an outage takes and a short one leaves
// every gateway ready. The places return once the database answers again.
func TestUnansweredAuthorizationsTakeOnePlacePerConnectionUntilClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var recovered atomic.Bool
	go acceptPostgres(listener, &recovered)
	pool, err := pgxpool.New(context.Background(), fmt.Sprintf("postgres://unused:unused@%s/unused?sslmode=disable&connect_timeout=1&pool_max_conns=%d", listener.Addr(), poolConns))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	service := &Service{db: &GatewayDB{pool: pool}, authorizeHoldQuery: "select 1", closeRequestQuery: "select 1"}
	defer service.Close()

	var authorizations sync.WaitGroup
	for index := range 200 {
		var cache keyConfigCache
		snapshot := credentialPolicySnapshot(t, &cache, fmt.Sprint("organization-", index), json.RawMessage(`null`), nil)
		prepared, err := service.PrepareCredential(snapshot, "chutes", 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		authorizations.Go(func() {
			_, err := service.authorizeResolvedRequest(context.Background(), "hash", snapshot.Claims, HoldRequest{RequestID: fmt.Sprint("request-", index), ProviderKey: "chutes", ProductKey: "product", EstimatedUpstreamCostUSD: "0.01", Snapshot: snapshot, Prepared: prepared, RequestLifetime: time.Minute})
			if !errors.Is(err, ErrGatewayUnavailable) {
				t.Errorf("authorization error = %v", err)
			}
		})
	}
	authorizations.Wait()
	closing := service.finalizations.closing.Load()
	if got := service.Diagnostics().Settlement; closing == 0 || closing > poolConns || int64(got.Reserved) != closing || !service.FinalizationReady() {
		t.Fatalf("closes = %d and places taken = %d, want 1 to %d each", closing, got.Reserved, poolConns)
	}
	recovered.Store(true)
	waitFor(t, func() bool {
		return service.finalizations.closing.Load() == 0 && service.Diagnostics().Settlement.Reserved == 0
	})
}

type fakeStatement struct {
	// products lists the authorizations by product key, in order.
	products []string
	batch    bool
}

// dropConnection makes the server close the connection instead of answering.
var dropConnection = &pgproto3.ErrorResponse{}

// fakeRow is an authorization result; a negative waitMS is NULL.
type fakeRow struct {
	result string
	waitMS int64
}

// limitRows refuses each authorization of a statement with a limit whose wait
// in milliseconds is the number its product key ends with.
func limitRows(statement fakeStatement) []fakeRow {
	rows := make([]fakeRow, len(statement.products))
	for index, product := range statement.products {
		wait, _ := strconv.ParseInt(product[strings.LastIndexByte(product, '-')+1:], 10, 64)
		rows[index] = fakeRow{result: "key_rate_limited", waitMS: wait}
	}
	return rows
}

func retriesAfter(err error, milliseconds int) bool {
	var retry interface{ RetryAfter() time.Duration }
	return errors.Is(err, ErrAPIKeyRateLimit) && errors.As(err, &retry) && retry.RetryAfter() == time.Duration(milliseconds)*time.Millisecond
}

// authorizeProduct authorizes a request of organization whose product key
// names it and index.
func authorizeProduct(t *testing.T, service *Service, organization string, index int) error {
	return authorizeProductUntil(context.Background(), t, service, organization, index)
}

// authorizeProductUntil authorizes as authorizeProduct does for a caller that
// leaves when ctx ends.
func authorizeProductUntil(ctx context.Context, t *testing.T, service *Service, organization string, index int) error {
	var cache keyConfigCache
	snapshot := credentialPolicySnapshot(t, &cache, organization, json.RawMessage(`null`), nil)
	prepared, err := service.PrepareCredential(snapshot, "chutes", 0, nil)
	if err != nil {
		return err
	}
	requestID, err := newUUIDV7String()
	if err != nil {
		return err
	}
	_, err = service.authorizeResolvedRequest(ctx, "hash", snapshot.Claims, HoldRequest{RequestID: requestID, ProviderKey: "chutes", ProductKey: fmt.Sprintf("%s-%d", organization, index), EstimatedUpstreamCostUSD: "0.01", Snapshot: snapshot, Prepared: prepared, RequestLifetime: time.Minute})
	return err
}

// scriptedService authorizes through a server whose authorization statements
// answer decides. Other statements find their request closed.
func scriptedService(t *testing.T, connections int, answer func(fakeStatement) ([]fakeRow, *pgproto3.ErrorResponse)) *Service {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go servePostgres(conn, answer)
		}
	}()
	pool, err := pgxpool.New(context.Background(), fmt.Sprintf("postgres://unused:unused@%s/unused?sslmode=disable&connect_timeout=1&pool_max_conns=%d", listener.Addr(), connections))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db := &GatewayDB{pool: pool, schemaName: "public"}
	service := &Service{
		db:                  db,
		authorizeHoldQuery:  db.functionQuery("authorize_gateway_hold", authorizeHoldColumns, authorizeHoldArguments),
		authorizeHoldsQuery: db.functionQuery("authorize_gateway_holds", "ordinal, "+authorizeHoldColumns, "$1::jsonb, $2::uuid[]"),
		closeRequestQuery:   db.functionQuery("close_gateway_request", "result", closeRequestArguments),
	}
	t.Cleanup(service.Close)
	return service
}

var fakeTypes = map[string]uint32{"text": 25, "uuid": 2950, "uuid[]": 2951, "numeric": 1700, "timestamptz": 1184, "jsonb": 3802, "bigint": 20, "int8": 20, "bool": 16}

var fakeColumnTypes = map[string]string{"ordinal": "int8", "hold_id": "uuid", "created_at": "timestamptz", "expires_at": "timestamptz", "config_current": "bool", "wait_ms": "int8"}

func servePostgres(conn net.Conn, answer func(fakeStatement) ([]fakeRow, *pgproto3.ErrorResponse)) {
	defer conn.Close()
	backend := pgproto3.NewBackend(conn, conn)
	if _, err := backend.ReceiveStartupMessage(); err != nil {
		return
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if backend.Flush() != nil {
		return
	}
	queries := map[string]string{}
	var query string
	var statement fakeStatement
	var formats []int16
	failed := false
	for {
		message, err := backend.Receive()
		if _, terminate := message.(*pgproto3.Terminate); err != nil || terminate {
			return
		}
		switch message := message.(type) {
		case *pgproto3.Query: // pgxpool pings idle connections.
			backend.Send(&pgproto3.EmptyQueryResponse{})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Parse:
			queries[message.Name] = message.Query
			backend.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Close: // pgx deallocates a statement that failed.
			delete(queries, message.Name)
			backend.Send(&pgproto3.CloseComplete{})
		case *pgproto3.Describe:
			text := queries[message.Name]
			var parameters []uint32
			for _, match := range regexp.MustCompile(`\$\d+::(\w+(?:\[\])?)`).FindAllStringSubmatch(text, -1) {
				parameters = append(parameters, fakeTypes[match[1]])
			}
			backend.Send(&pgproto3.ParameterDescription{ParameterOIDs: parameters})
			backend.Send(&pgproto3.RowDescription{Fields: fakeFields(text)})
		case *pgproto3.Bind:
			query = queries[message.PreparedStatement]
			formats = slices.Clone(message.ResultFormatCodes)
			statement = fakeStatement{batch: strings.Contains(query, `"authorize_gateway_holds"`)}
			switch {
			case statement.batch:
				var members []struct {
					Product string `json:"product_key"`
				}
				_ = json.Unmarshal(bytes.TrimPrefix(message.Parameters[0], []byte{1}), &members)
				for _, member := range members {
					statement.products = append(statement.products, member.Product)
				}
			case strings.Contains(query, `"authorize_gateway_hold"`):
				statement.products = []string{string(message.Parameters[7])}
			}
			backend.Send(&pgproto3.BindComplete{})
		case *pgproto3.Execute:
			if failed {
				break
			}
			fields := fakeFields(query)
			if statement.products == nil {
				backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("closed")}})
				backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				break
			}
			rows, failure := answer(statement)
			if failure == dropConnection {
				return
			}
			if failure != nil {
				backend.Send(failure)
				failed = true
				break
			}
			for index, row := range rows {
				values := make([][]byte, len(fields))
				for column, field := range fields {
					format := int16(0)
					if len(formats) == 1 {
						format = formats[0]
					} else if len(formats) > column {
						format = formats[column]
					}
					switch name := string(field.Name); {
					case name == "ordinal":
						values[column] = fakeInt8(int64(index+1), format)
					case name == "result":
						values[column] = []byte(row.result)
					case name == "config_current":
						values[column] = []byte("f")
						if format == 1 {
							values[column] = []byte{0}
						}
					case name == "wait_ms" && row.waitMS >= 0:
						values[column] = fakeInt8(row.waitMS, format)
					}
				}
				backend.Send(&pgproto3.DataRow{Values: values})
			}
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte(fmt.Sprintf("SELECT %d", len(rows)))})
		case *pgproto3.Sync:
			failed = false
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		}
		if backend.Flush() != nil {
			return
		}
	}
}

// fakeFields describes the columns that query selects.
func fakeFields(query string) []pgproto3.FieldDescription {
	selected, _, _ := strings.Cut(strings.TrimPrefix(query, "select "), " from ")
	var fields []pgproto3.FieldDescription
	for _, name := range strings.Split(selected, ", ") {
		kind, ok := fakeColumnTypes[name]
		if !ok {
			kind = "text"
		}
		fields = append(fields, pgproto3.FieldDescription{Name: []byte(name), DataTypeOID: fakeTypes[kind], DataTypeSize: -1, TypeModifier: -1})
	}
	return fields
}

func fakeInt8(value int64, format int16) []byte {
	if format == 1 {
		return binary.BigEndian.AppendUint64(nil, uint64(value))
	}
	return []byte(strconv.FormatInt(value, 10))
}

// acceptPostgres completes each connection's startup. A connection opened
// before recovered is set reads messages without answering them until the
// client terminates; a later one answers every statement with "closed", as a
// close finds.
func acceptPostgres(listener net.Listener, recovered *atomic.Bool) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		answering := recovered != nil && recovered.Load()
		go func() {
			defer conn.Close()
			backend := pgproto3.NewBackend(conn, conn)
			if _, err := backend.ReceiveStartupMessage(); err != nil {
				return
			}
			backend.Send(&pgproto3.AuthenticationOk{})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if backend.Flush() != nil {
				return
			}
			for {
				message, err := backend.Receive()
				if _, terminate := message.(*pgproto3.Terminate); err != nil || terminate {
					return
				}
				if !answering {
					continue
				}
				switch message := message.(type) {
				case *pgproto3.Query: // pgxpool pings idle connections.
					backend.Send(&pgproto3.EmptyQueryResponse{})
					backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				case *pgproto3.Parse:
					backend.Send(&pgproto3.ParseComplete{})
				case *pgproto3.Describe:
					if message.ObjectType == 'S' {
						// A close passes the request ID, key ID and authorization deadline.
						backend.Send(&pgproto3.ParameterDescription{ParameterOIDs: []uint32{25, 25, 1184}})
					}
					backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
						{Name: []byte("result"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1},
					}})
				case *pgproto3.Bind:
					backend.Send(&pgproto3.BindComplete{})
				case *pgproto3.Execute:
					backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("closed")}})
					backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				case *pgproto3.Sync:
					backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				}
				if backend.Flush() != nil {
					return
				}
			}
		}()
	}
}
