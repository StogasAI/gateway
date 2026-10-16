package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
			_, err = service.authorizeResolvedRequest(context.Background(), "hash", snapshot.Claims, HoldRequest{RequestID: "request", ProviderKey: "chutes", ProductKey: "product", EstimatedUpstreamCostUSD: "0.01", Snapshot: snapshot, Prepared: prepared, RequestLifetime: time.Minute})
			if !errors.Is(err, ErrGatewayUnavailable) {
				t.Fatalf("authorization error = %v", err)
			}
			want := 0
			if sent {
				want = 1
			}
			// The close keeps the request's settlement place until it ends, and
			// admission stays open while the database is unreachable.
			got := service.Diagnostics().Settlement
			if closing := service.finalizations.closing.Load(); closing != int64(want) || got.Reserved != want || !service.FinalizationReady() {
				t.Fatalf("closes = %d and places taken = %d, want %d", closing, got.Reserved, want)
			}
		})
	}
}

// Waiting for an organization slot or a connection ends a statement reserve
// before the authorization deadline, so a statement that starts can finish.
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
	releaseSlot, err := service.organizationSlots.take(context.Background(), "busy")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSlot()

	// "busy" waits for its organization slot, and "idle" for the connection.
	organizations := []string{"busy", "idle"}
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
			_, errs[index] = service.authorizeResolvedRequest(context.Background(), "hash", snapshot.Claims, HoldRequest{RequestID: "request-" + organization, ProviderKey: "chutes", ProductKey: "product", EstimatedUpstreamCostUSD: "0.01", Snapshot: snapshot, Prepared: prepared, RequestLifetime: time.Minute})
			elapsed[index] = time.Since(started)
		})
	}
	authorizations.Wait()
	for index, organization := range organizations {
		if !errors.Is(errs[index], ErrGatewayUnavailable) || elapsed[index] < authorizeTimeout-authorizeStatementReserve || elapsed[index] >= authorizeTimeout {
			t.Fatalf("%s failed with %v after %s", organization, errs[index], elapsed[index])
		}
	}
	if waits, timeouts := service.organizationSlots.waits.Load(), service.organizationSlots.timeouts.Load(); waits != 1 || timeouts != 1 {
		t.Fatalf("organization waits %d and timeouts %d, want 1 and 1", waits, timeouts)
	}
	if closing := service.finalizations.closing.Load(); closing != 0 {
		t.Fatalf("closes = %d, want 0", closing)
	}
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
