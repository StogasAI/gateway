package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
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
				go acceptSilentPostgres(listener)
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
			_, err = service.authorizeResolvedRequest(context.Background(), "hash", nil, snapshot.Claims, "request", "chutes", "product", "0.01", UsageReservation{}, snapshot, prepared, nil, nil, nil, time.Minute)
			if !errors.Is(err, ErrGatewayUnavailable) {
				t.Fatalf("authorization error = %v", err)
			}
			want := int64(0)
			if sent {
				want = 1
			}
			if closing := service.finalizations.closing.Load(); closing != want {
				t.Fatalf("closes = %d, want %d", closing, want)
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
	go acceptSilentPostgres(listener)
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
			_, errs[index] = service.authorizeResolvedRequest(context.Background(), "hash", nil, snapshot.Claims, "request-"+organization, "chutes", "product", "0.01", UsageReservation{}, snapshot, prepared, nil, nil, nil, time.Minute)
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

// acceptSilentPostgres completes each connection's startup, then reads its
// messages without answering them until the client terminates.
func acceptSilentPostgres(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
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
			}
		}()
	}
}
