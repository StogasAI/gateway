package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// settlementCall is one settle_gateway_request_logs call as the database saw it.
type settlementCall struct {
	at time.Time
	// The two arguments as sent.
	arrays           [2]string
	logs, rejections []json.RawMessage
}

// settlementReply answers a call with rows of request ID ("" for null) and
// result, with an error response, or by closing the connection unanswered.
type settlementReply struct {
	rows [][2]string
	code string
	drop bool
}

// settleAll answers like a database that stores every log and rejection.
func settleAll(call settlementCall) settlementReply {
	reply := settlementReply{}
	for _, id := range requestIDs(call.logs) {
		reply.rows = append(reply.rows, [2]string{id, "complete"})
	}
	return reply
}

func requestIDs(rows []json.RawMessage) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		var event struct {
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(row, &event)
		ids[i] = event.RequestID
	}
	return ids
}

// fakeSettlementDatabase speaks enough of the PostgreSQL protocol for pgx to
// prepare and run the settlement query in the gateway's default mode.
type fakeSettlementDatabase struct {
	service *Service
	answer  func(settlementCall) settlementReply
	mu      sync.Mutex
	calls   []settlementCall
	active  int
	overlap bool
}

func newFakeSettlementDatabase(t *testing.T, answer func(settlementCall) settlementReply) *fakeSettlementDatabase {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	db := &fakeSettlementDatabase{answer: answer}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go db.serve(conn)
		}
	}()
	pool, err := pgxpool.New(context.Background(), "postgres://unused:unused@"+listener.Addr().String()+"/unused?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	db.service = &Service{db: &GatewayDB{pool: pool}, settleQuery: "select request_id, result from settle_gateway_request_logs($1::json, $2::json)"}
	t.Cleanup(func() {
		db.service.Close()
		listener.Close()
	})
	return db
}

func (db *fakeSettlementDatabase) recorded() []settlementCall {
	db.mu.Lock()
	defer db.mu.Unlock()
	return slices.Clone(db.calls)
}

func (db *fakeSettlementDatabase) call(parameters [][]byte) settlementReply {
	if len(parameters) != 2 {
		return settlementReply{code: "08P01"}
	}
	call := settlementCall{at: time.Now(), arrays: [2]string{string(parameters[0]), string(parameters[1])}}
	if json.Unmarshal(parameters[0], &call.logs) != nil || json.Unmarshal(parameters[1], &call.rejections) != nil {
		return settlementReply{code: "22P02"}
	}
	db.mu.Lock()
	db.calls = append(db.calls, call)
	db.active++
	db.overlap = db.overlap || db.active > 1
	db.mu.Unlock()
	defer func() { db.mu.Lock(); db.active--; db.mu.Unlock() }()
	return db.answer(call)
}

func (db *fakeSettlementDatabase) serve(conn net.Conn) {
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
	columns := &pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
		{Name: []byte("request_id"), DataTypeOID: 2950, DataTypeSize: 16, TypeModifier: -1},
		{Name: []byte("result"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1},
	}}
	var parameters [][]byte
	var formats []int16
	failed := false
	for {
		message, err := backend.Receive()
		if err != nil {
			return
		}
		switch message := message.(type) {
		case *pgproto3.Query: // pgxpool pings idle connections.
			backend.Send(&pgproto3.EmptyQueryResponse{})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Parse:
			if !failed {
				backend.Send(&pgproto3.ParseComplete{})
			}
		case *pgproto3.Describe:
			if failed {
				continue
			}
			if message.ObjectType == 'S' {
				backend.Send(&pgproto3.ParameterDescription{ParameterOIDs: []uint32{114, 114}})
			}
			backend.Send(columns)
		case *pgproto3.Bind:
			if failed {
				continue
			}
			parameters = parameters[:0]
			for _, parameter := range message.Parameters {
				parameters = append(parameters, bytes.Clone(parameter))
			}
			formats = slices.Clone(message.ResultFormatCodes)
			backend.Send(&pgproto3.BindComplete{})
		case *pgproto3.Execute:
			if failed {
				continue
			}
			reply := db.call(parameters)
			if reply.drop {
				return
			}
			if reply.code != "" {
				backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: reply.code, Message: "settlement failed"})
				failed = true
				continue
			}
			for _, row := range reply.rows {
				var id []byte
				if row[0] != "" {
					id = []byte(row[0])
					if len(formats) > 0 && formats[0] == 1 {
						binary := uuid.MustParse(row[0])
						id = binary[:]
					}
				}
				backend.Send(&pgproto3.DataRow{Values: [][]byte{id, []byte(row[1])}})
			}
			backend.Send(&pgproto3.CommandComplete{CommandTag: fmt.Appendf(nil, "SELECT %d", len(reply.rows))})
		case *pgproto3.Close: // pgx deallocates a statement after any error.
			if !failed {
				backend.Send(&pgproto3.CloseComplete{})
			}
		case *pgproto3.Sync:
			failed = false
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Terminate:
			return
		}
		if backend.Flush() != nil {
			return
		}
	}
}

// settlementRequest returns an admitted request, as authorization would.
func settlementRequest(t *testing.T, s *Service) (*Authorization, RequestEvent) {
	t.Helper()
	release, err := s.reserveFinalization()
	if err != nil {
		t.Fatal(err)
	}
	authorization := testAuthorization()
	authorization.RequestID = uuid.Must(uuid.NewV7()).String()
	authorization.releaseFinalization = release
	event := testGatewayRequestEvent()
	event.RequestID = authorization.RequestID
	return authorization, event
}

func finalizeAsync(s *Service, authorization *Authorization, event RequestEvent) <-chan error {
	done := make(chan error, 1)
	go func() { done <- s.FinalizeRequest(authorization, event) }()
	return done
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func drainSettlements(t *testing.T, s *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.DrainFinalizations(ctx); err != nil {
		t.Fatal(err)
	}
}

func settlementReason(err error) string {
	var settlementErr *SettlementError
	if !errors.As(err, &settlementErr) {
		return fmt.Sprint(err)
	}
	return settlementErr.Reason
}

func TestSettlementStoresTheLogWithItsHoldBindingAndCost(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	s := db.service
	authorization, event := settlementRequest(t, s)
	event.Usage.UpstreamCostUSD = "0.5"
	if err := s.FinalizeRequest(authorization, event); err != nil {
		t.Fatal(err)
	}
	calls := db.recorded()
	if len(calls) != 1 || len(calls[0].logs) != 1 || len(calls[0].rejections) != 0 {
		t.Fatalf("calls = %+v, want one call with one log", calls)
	}
	var wire struct {
		HoldParamsHash string       `json:"hold_params_hash"`
		Usage          RequestUsage `json:"usage"`
	}
	if err := json.Unmarshal(calls[0].logs[0], &wire); err != nil {
		t.Fatal(err)
	}
	if wire.HoldParamsHash != createHoldParamsHash(authorization.ProviderKey, authorization.ProductKey, authorization.UpstreamTargetJSON) ||
		wire.Usage.UpstreamCostUSD != "0.5" || wire.Usage.BilledCostUSD != "0.5" {
		t.Fatalf("settled log = %s", calls[0].logs[0])
	}
	if got := s.Diagnostics().Settlement; got.Reserved != 0 || got.Queued != 0 || got.Calls != 1 || got.FailedCalls != 0 {
		t.Fatalf("diagnostics = %+v", got)
	}
}

// Requests that finish while a call runs share the next call, up to the
// database's limit, and calls never overlap.
func TestSettlementBatchesRequestsThatFinishDuringACall(t *testing.T) {
	release := make(chan struct{})
	var first sync.Once
	db := newFakeSettlementDatabase(t, func(call settlementCall) settlementReply {
		first.Do(func() { <-release })
		return settleAll(call)
	})
	s := db.service
	const requests = 2*settlementMaxLogs + 50
	pending := map[string]bool{}
	results := make([]<-chan error, 0, requests)
	for range requests {
		authorization, event := settlementRequest(t, s)
		pending[authorization.RequestID] = true
		results = append(results, finalizeAsync(s, authorization, event))
		if len(results) == 1 {
			waitFor(t, func() bool { return len(db.recorded()) == 1 })
		}
	}
	waitFor(t, func() bool { return s.Diagnostics().Settlement.Queued == requests })
	close(release)
	for _, result := range results {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	calls := db.recorded()
	var sizes []int
	for i, call := range calls {
		sizes = append(sizes, len(call.logs))
		for _, id := range requestIDs(call.logs) {
			if !pending[id] {
				t.Fatalf("request %s settled twice", id)
			}
			delete(pending, id)
		}
		if i > 0 && call.at.Sub(calls[i-1].at) < settlementInterval-10*time.Millisecond {
			t.Fatalf("calls started %s apart", call.at.Sub(calls[i-1].at))
		}
	}
	if !slices.Equal(sizes, []int{1, settlementMaxLogs, settlementMaxLogs, 49}) || len(pending) != 0 {
		t.Fatalf("call sizes = %v, unsettled = %d", sizes, len(pending))
	}
	if db.overlap {
		t.Fatal("settlement calls overlapped")
	}
}

// A log whose contents fail the call is found by splitting the batch. Only it
// is abandoned; its hold waits for the boot to stop.
func TestSettlementIsolatesTheLogThatFailsACall(t *testing.T) {
	poisonLog, poisonRejection := uuid.Must(uuid.NewV7()).String(), uuid.Must(uuid.NewV7()).String()
	release := make(chan struct{})
	var first sync.Once
	db := newFakeSettlementDatabase(t, func(call settlementCall) settlementReply {
		first.Do(func() { <-release })
		if slices.Contains(requestIDs(call.logs), poisonLog) || slices.Contains(requestIDs(call.rejections), poisonRejection) {
			return settlementReply{code: "22P05"}
		}
		return settleAll(call)
	})
	s := db.service
	authorization, event := settlementRequest(t, s)
	results := map[string]<-chan error{authorization.RequestID: finalizeAsync(s, authorization, event)}
	waitFor(t, func() bool { return len(db.recorded()) == 1 })
	// Queue in a known order, so the split takes a known path.
	for i := range 8 {
		authorization, event := settlementRequest(t, s)
		if i == 5 {
			authorization.RequestID, event.RequestID = poisonLog, poisonLog
		}
		results[authorization.RequestID] = finalizeAsync(s, authorization, event)
		waitFor(t, func() bool { return s.Diagnostics().Settlement.Queued == i+2 })
	}
	rejections := make([]RequestEvent, 3)
	for i := range rejections {
		rejections[i] = NewRejectionEvent(rejectionFixture())
	}
	rejections[1].RequestID = poisonRejection
	stored := make(chan []bool, 1)
	go func() { stored <- s.settleRejections(rejections) }()
	waitFor(t, func() bool { return s.Diagnostics().Settlement.Queued == 12 })
	close(release)
	for id, result := range results {
		err := <-result
		if id == poisonLog {
			var settlementErr *SettlementError
			if !errors.As(err, &settlementErr) || settlementErr.Reason != "abandoned" || settlementErr.SQLState != "22P05" {
				t.Fatalf("poisoned log error = %v", err)
			}
		} else if err != nil {
			t.Fatalf("log %s failed with the poisoned one: %v", id, err)
		}
	}
	if got := <-stored; !slices.Equal(got, []bool{true, false, true}) {
		t.Fatalf("rejections stored = %v", got)
	}
	// The batch is 8 logs, then 3 rejections. Halving fails 7 calls to find
	// both, and no content error runs twice.
	got := s.Diagnostics().Settlement
	if got.Abandoned != 1 || got.LastFailedAt == nil || got.Retrying || !s.FinalizationReady() || got.Calls != 12 || got.FailedCalls != 7 {
		t.Fatalf("diagnostics = %+v", got)
	}
}

// Any other failure runs the same call again and closes admission until a call
// succeeds. A call whose connection broke may have committed; the repeat then
// finds no hold.
func TestSettlementRetriesTheSameCallUntilTheDatabaseRecovers(t *testing.T) {
	var calls atomic.Int32
	failing := make(chan struct{})
	recovered := make(chan struct{})
	db := newFakeSettlementDatabase(t, func(call settlementCall) settlementReply {
		switch calls.Add(1) {
		case 1:
			return settlementReply{drop: true}
		case 2:
			close(failing)
			<-recovered
			return settlementReply{code: "57P01"}
		}
		return settleAll(call)
	})
	s := db.service
	authorization, event := settlementRequest(t, s)
	result := finalizeAsync(s, authorization, event)
	<-failing
	if s.FinalizationReady() || !s.Diagnostics().Settlement.Retrying {
		t.Fatal("a failing database left inference admission open")
	}
	if _, err := s.reserveFinalization(); !errors.Is(err, ErrGatewayUnavailable) {
		t.Fatalf("reservation while retrying = %v", err)
	}
	close(recovered)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	recorded := db.recorded()
	if len(recorded) != 3 || recorded[1].arrays != recorded[0].arrays || recorded[2].arrays != recorded[0].arrays {
		t.Fatalf("retries changed the call: %+v", recorded)
	}
	if got := s.Diagnostics().Settlement; got.Retrying || !s.FinalizationReady() || got.Calls != 3 || got.FailedCalls != 2 {
		t.Fatalf("diagnostics after recovery = %+v", got)
	}
}

func TestSettlementReportsEachResult(t *testing.T) {
	results := map[string]string{}
	db := newFakeSettlementDatabase(t, func(call settlementCall) settlementReply {
		// A rejection the database could not identify has a null request ID.
		reply := settlementReply{rows: [][2]string{{"", "invalid_rejection"}}}
		for _, id := range append(requestIDs(call.logs), requestIDs(call.rejections)...) {
			if result := results[id]; result != "" {
				reply.rows = append(reply.rows, [2]string{id, result})
			}
		}
		return reply
	})
	s := db.service
	for _, test := range []struct{ result, reason string }{
		{"complete", ""},
		{"hold_not_found", ""},
		{"under_reserved", ""},
		{"negative_balance", ""},
		{"payload_mismatch", "payload_mismatch"},
		{"params_mismatch", "params_mismatch"},
		{"", "unknown_result"},
		{"surprise", "unknown_result"},
	} {
		authorization, event := settlementRequest(t, s)
		results[authorization.RequestID] = test.result
		err := s.FinalizeRequest(authorization, event)
		if (test.reason == "" && err != nil) || (test.reason != "" && settlementReason(err) != test.reason) {
			t.Fatalf("result %q: error = %v, want %q", test.result, err, test.reason)
		}
	}
	valid, invalid := NewRejectionEvent(rejectionFixture()), NewRejectionEvent(rejectionFixture())
	results[invalid.RequestID] = "invalid_rejection"
	if got := s.settleRejections([]RequestEvent{valid, invalid}); !slices.Equal(got, []bool{true, false}) {
		t.Fatalf("rejections stored = %v", got)
	}
	if got := s.Diagnostics().Settlement; got.Refused != 2 || got.Abandoned != 2 || got.LastFailedAt == nil || got.UnderReserved != 1 || got.NegativeBalance != 1 || got.Reserved != 0 {
		t.Fatalf("diagnostics = %+v", got)
	}
}

func TestSettlementShutdownAnswersEveryWaitingRequest(t *testing.T) {
	stop := make(chan struct{})
	db := newFakeSettlementDatabase(t, func(call settlementCall) settlementReply {
		<-stop
		return settleAll(call)
	})
	t.Cleanup(func() { close(stop) })
	s := db.service
	authorization, event := settlementRequest(t, s)
	running := finalizeAsync(s, authorization, event)
	waitFor(t, func() bool { return len(db.recorded()) == 1 })
	authorization, event = settlementRequest(t, s)
	queued := finalizeAsync(s, authorization, event)
	waitFor(t, func() bool { return s.Diagnostics().Settlement.Queued == 2 })
	s.closeFinalizations()
	for _, result := range []<-chan error{running, queued} {
		if reason := settlementReason(<-result); reason != "closed" {
			t.Fatalf("waiting request ended with %q", reason)
		}
	}
	if _, err := s.reserveFinalization(); !errors.Is(err, ErrGatewayUnavailable) || s.FinalizationReady() {
		t.Fatal("a closed gateway admitted a request")
	}
	authorization, event = testAuthorization(), testGatewayRequestEvent()
	if reason := settlementReason(s.FinalizeRequest(authorization, event)); reason != "closed" {
		t.Fatalf("late request ended with %q", reason)
	}
}

func TestSettlementBatchFitsTheDatabaseLimits(t *testing.T) {
	f := &finalizationState{}
	for range settlementMaxLogs + 1 {
		f.logs = append(f.logs, &settlement{payload: "{}"})
	}
	for range settlementMaxRejections + 1 {
		f.rejections = append(f.rejections, &settlement{payload: "{}", rejection: true})
	}
	batch := f.take()
	logs := len(slices.DeleteFunc(slices.Clone(batch), func(item *settlement) bool { return item.rejection }))
	if logs != settlementMaxLogs || len(batch)-logs != settlementMaxRejections || len(f.logs) != 1 || len(f.rejections) != 1 {
		t.Fatalf("batch has %d logs and %d rejections", logs, len(batch)-logs)
	}
	f = &finalizationState{}
	large := strings.Repeat("x", 3<<20)
	for range 3 {
		f.rejections = append(f.rejections, &settlement{payload: large, rejection: true})
	}
	batch = f.take()
	logsJSON, rejectionsJSON := settlementArrays(batch)
	if len(batch) != 2 || len(logsJSON)+len(rejectionsJSON) > settlementMaxBytes || len(f.take()) != 1 {
		t.Fatalf("byte limit took %d rejections", len(batch))
	}
}
