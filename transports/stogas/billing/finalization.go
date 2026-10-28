package billing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	// settle_gateway_request_logs takes at most this much per call, with both
	// arrays measured as sent.
	settlementMaxLogs       = 100
	settlementMaxRejections = 256
	settlementMaxBytes      = 8 << 20
	// One call runs at a time. Calls start at least this far apart, or at once
	// when a full call waits, so an idle gateway settles each request at once
	// and a busy one in larger calls. Each call locks its organizations'
	// balance rows, so fewer calls leave a bursting organization's
	// authorizations waiting less and cost the database less CPU and WAL per
	// log, while calls a second apart hold the rows too long. Finished requests
	// keep their holds until then.
	settlementInterval = 500 * time.Millisecond
	// On its own connection, calls of 100 logs took at most about 200 ms under
	// the heaviest measured load. A call still running after this has lost its
	// connection or found the database overloaded, and runs again.
	settlementCallTimeout = 5 * time.Second
	closeTimeout          = 2 * time.Second
	retryInitialDelay     = 250 * time.Millisecond
	retryMaxDelay         = 5 * time.Second
)

// SettlementError explains why a log did not settle.
type SettlementError struct {
	// Reason is a database refusal, such as payload_mismatch, or
	// database_error when a call failed on this log alone. The hold then keeps
	// the log for an operator. Otherwise it is abandoned, closed,
	// encoding_failed or unknown_result, and a hold that the log did not
	// settle keeps its reserved amount until an operator releases it.
	Reason string
	// SQLState is the database error behind a database_error or abandoned log.
	SQLState string
}

func (e *SettlementError) Error() string {
	if e.SQLState != "" {
		return "settlement " + e.Reason + ": SQLSTATE " + e.SQLState
	}
	return "settlement " + e.Reason
}

type settlement struct {
	requestID string
	payload   string
	rejection bool
	done      chan error
}

type finalizationState struct {
	mu         sync.Mutex
	reserved   int
	closed     bool
	logs       []*settlement
	rejections []*settlement
	settling   int
	wake       chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	workers    sync.WaitGroup
	// finished lists each organization's requests whose responses ended and
	// whose logs have not settled, in the order they ended. Their holds no
	// longer count as running requests.
	finished map[string][]uuid.UUID
	// The last call failed and runs again after a delay.
	retrying    atomic.Bool
	closing     atomic.Int64
	calls       atomic.Uint64
	failedCalls atomic.Uint64
	refused     atomic.Uint64
	abandoned   atomic.Uint64
	// Unix nanoseconds of the last refused or abandoned log.
	lastFailure    atomic.Int64
	encodingFailed atomic.Bool
}

// fail counts a refused or abandoned log and records when it happened.
func (f *finalizationState) fail(counter *atomic.Uint64) {
	counter.Add(1)
	f.lastFailure.Store(time.Now().UnixNano())
}

type SettlementDiagnostics struct {
	Reserved int `json:"reserved"`
	// Closing counts authorizations the database never answered, whose holds
	// wait for a close.
	Closing         int64      `json:"closing"`
	Queued          int        `json:"queued"`
	Retrying        bool       `json:"retrying"`
	Calls           uint64     `json:"calls"`
	FailedCalls     uint64     `json:"failedCalls"`
	Refused         uint64     `json:"refused"`
	Abandoned       uint64     `json:"abandoned"`
	LastFailedAt    *time.Time `json:"lastFailedAt,omitempty"`
	UnderReserved   uint64     `json:"underReserved"`
	NegativeBalance uint64     `json:"negativeBalance"`
	EncodingFailed  bool       `json:"encodingFailed"`
}

// Every admitted request takes a place in settlement before touching the
// wallet and keeps it until the database settles its log or closes its hold.
// Places count these requests; they set no limit of their own. The caller's
// memory admission bounds them, because a request keeps its memory until
// then, and a close keeps it through HoldRequest.KeepMemory. Failing database
// calls do not close admission: every gateway shares the database, so a short
// outage would make the whole fleet unready at once. Requests then fail at
// authorization.
func (s *Service) reserveFinalization() (func(), error) {
	f := &s.finalizations
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.encodingFailed.Load() {
		return nil, ErrGatewayUnavailable
	}
	f.reserved++
	var once sync.Once
	return func() { once.Do(func() { f.mu.Lock(); f.reserved--; f.mu.Unlock() }) }, nil
}

// FinalizationReady reports whether settlement takes new requests: the gateway
// is not closing, and it has encoded every log so far.
func (s *Service) FinalizationReady() bool {
	if s == nil {
		return true
	}
	f := &s.finalizations
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.closed && !f.encodingFailed.Load()
}

// FinalizeRequest settles the request's hold with its log and returns once the
// database has decided. The caller keeps the request's admission until then.
func (s *Service) FinalizeRequest(authorization *Authorization, event RequestEvent) error {
	if authorization == nil {
		return nil
	}
	if authorization.releaseFinalization != nil {
		defer authorization.releaseFinalization()
	}
	upstreamCostRaw := event.Usage.UpstreamCostUSD
	if upstreamCostRaw == "" {
		upstreamCostRaw = ZeroChargeUSD
	}
	upstreamCostUSD, err := ParseUSD(upstreamCostRaw)
	if err != nil {
		s.finalizations.encodingFailed.Store(true)
		return &SettlementError{Reason: "encoding_failed"}
	}
	event.Usage.UpstreamCostUSD = upstreamCostUSD.String()
	billedCostUSD := calculateBilledCostUSD(authorization, upstreamCostUSD)
	event.Usage.BilledCostUSD = billedCostUSD.String()
	event.Usage.TaxUSD = calculateTaxUSD(authorization, billedCostUSD).String()
	payload, err := encodeRequestLog(event, createHoldParamsHash(authorization.ProviderKey, authorization.ProductKey, authorization.UpstreamTargetJSON))
	if err != nil {
		s.finalizations.encodingFailed.Store(true)
		return &SettlementError{Reason: "encoding_failed"}
	}
	item := &settlement{requestID: authorization.RequestID, payload: payload, done: make(chan error, 1)}
	if requestID, err := uuid.Parse(authorization.RequestID); err == nil {
		s.finalizations.finish(authorization.OrganizationID, requestID)
		defer s.finalizations.forget(authorization.OrganizationID, requestID)
	}
	s.submitSettlements(item)
	return <-item.done
}

func (f *finalizationState) finish(organizationID string, requestID uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.finished == nil {
		f.finished = make(map[string][]uuid.UUID)
	}
	f.finished[organizationID] = append(f.finished[organizationID], requestID)
}

func (f *finalizationState) forget(organizationID string, requestID uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	finished := f.finished[organizationID]
	if index := slices.Index(finished, requestID); index >= 0 {
		finished = slices.Delete(finished, index, index+1)
	}
	if len(finished) == 0 {
		delete(f.finished, organizationID)
	} else {
		f.finished[organizationID] = finished
	}
}

// finishedRequests returns the organization's last finished requests, which
// do not count against its concurrency limits, as many as one settlement call
// takes. When more wait, settlement is behind, and the older ones still count.
func (f *finalizationState) finishedRequests(organizationID string) []uuid.UUID {
	f.mu.Lock()
	defer f.mu.Unlock()
	finished := f.finished[organizationID]
	// A nil slice would reach PostgreSQL as null.
	return append([]uuid.UUID{}, finished[max(0, len(finished)-settlementMaxLogs):]...)
}

// settleRejections stores rejections through settlement and reports which ones
// the database kept.
func (s *Service) settleRejections(events []RequestEvent) []bool {
	stored := make([]bool, len(events))
	items := make([]*settlement, 0, len(events))
	indexes := make([]int, 0, len(events))
	for index, event := range events {
		payload, err := encodeRequestLog(event, "")
		if err != nil {
			continue
		}
		items = append(items, &settlement{requestID: event.RequestID, payload: payload, rejection: true, done: make(chan error, 1)})
		indexes = append(indexes, index)
	}
	s.submitSettlements(items...)
	for i, item := range items {
		stored[indexes[i]] = <-item.done == nil
	}
	return stored
}

func (s *Service) submitSettlements(items ...*settlement) {
	f := &s.finalizations
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		for _, item := range items {
			item.done <- &SettlementError{Reason: "closed"}
		}
		return
	}
	s.startFinalizationWorkersLocked()
	for _, item := range items {
		if item.rejection {
			f.rejections = append(f.rejections, item)
		} else {
			f.logs = append(f.logs, item)
		}
	}
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (s *Service) startFinalizationWorkersLocked() {
	f := &s.finalizations
	if f.ctx != nil {
		return
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.wake = make(chan struct{}, 1)
	f.workers.Add(1)
	go s.runSettlements()
}

func (s *Service) runSettlements() {
	f := &s.finalizations
	defer f.workers.Done()
	var started time.Time
	for {
		select {
		case <-f.wake:
		case <-f.ctx.Done():
			return
		}
		for {
			if !f.waitUntilDue(started.Add(settlementInterval)) {
				return
			}
			batch := f.take()
			if len(batch) == 0 {
				break
			}
			started = time.Now()
			s.settle(f.ctx, batch)
			f.mu.Lock()
			f.settling = 0
			f.mu.Unlock()
		}
	}
}

// waitUntilDue waits until the next call is due or a full call waits. It
// reports false once the gateway stops.
func (f *finalizationState) waitUntilDue(due time.Time) bool {
	timer := time.NewTimer(time.Until(due))
	defer timer.Stop()
	for !f.full() {
		select {
		case <-timer.C:
			return true
		case <-f.wake:
		case <-f.ctx.Done():
			return false
		}
	}
	return f.ctx.Err() == nil
}

func (f *finalizationState) full() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.logs) >= settlementMaxLogs || len(f.rejections) >= settlementMaxRejections
}

// take removes the oldest logs and rejections that fit in one call.
func (f *finalizationState) take() []*settlement {
	f.mu.Lock()
	defer f.mu.Unlock()
	bytes := len("[][]")
	logs := 0
	for logs < min(len(f.logs), settlementMaxLogs) && bytes+len(f.logs[logs].payload)+1 <= settlementMaxBytes {
		bytes += len(f.logs[logs].payload) + 1
		logs++
	}
	rejections := 0
	for rejections < min(len(f.rejections), settlementMaxRejections) && bytes+len(f.rejections[rejections].payload)+1 <= settlementMaxBytes {
		bytes += len(f.rejections[rejections].payload) + 1
		rejections++
	}
	batch := make([]*settlement, 0, logs+rejections)
	batch = append(append(batch, f.logs[:logs]...), f.rejections[:rejections]...)
	f.logs = dequeue(f.logs, logs)
	f.rejections = dequeue(f.rejections, rejections)
	f.settling = len(batch)
	return batch
}

// dequeue drops the first n items without keeping them reachable.
func dequeue(queue []*settlement, n int) []*settlement {
	clear(queue[:n])
	if n == len(queue) {
		return nil
	}
	return queue[n:]
}

// settle stores the batch. A failure that one log's contents can cause splits
// the batch until that log fails alone. Its hold then keeps it for an
// operator, as settlement keeps a log it refuses; a rejection has no hold and
// is dropped. Any other failure runs the same call again, which is safe:
// settlement deletes each hold it settles, so a repeated log finds no hold.
func (s *Service) settle(ctx context.Context, batch []*settlement) {
	logs, rejections := settlementArrays(batch)
	var results map[string]string
	err := s.callWithRetry(ctx, func(ctx context.Context) (err error) {
		results, err = s.callSettlement(ctx, logs, rejections)
		return err
	})
	switch {
	case err == nil:
		s.resolveSettlements(batch, results)
	case ctx.Err() != nil:
		for _, item := range batch {
			item.done <- &SettlementError{Reason: "closed"}
		}
	case len(batch) > 1:
		s.settle(ctx, batch[:len(batch)/2])
		s.settle(ctx, batch[len(batch)/2:])
	case batch[0].rejection:
		batch[0].done <- &SettlementError{Reason: "abandoned", SQLState: sqlState(err)}
	default:
		s.keepFailedLog(ctx, batch[0], sqlState(err))
	}
}

// keepFailedLog stores a log that a settlement call failed on with its hold.
// If that fails too, the log is abandoned. Control alerts once the hold
// expires, and the hold keeps its reserved amount until an operator releases
// it.
func (s *Service) keepFailedLog(ctx context.Context, item *settlement, state string) {
	f := &s.finalizations
	var result string
	err := s.callWithRetry(ctx, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, settlementCallTimeout)
		defer cancel()
		return s.db.settlement.QueryRow(ctx, s.keepFailedLogQuery, item.requestID, item.payload).Scan(&result)
	})
	switch {
	case err == nil && result == "kept":
		f.fail(&f.refused)
		item.done <- &SettlementError{Reason: "database_error", SQLState: state}
	case ctx.Err() != nil:
		item.done <- &SettlementError{Reason: "closed"}
	default:
		f.fail(&f.abandoned)
		item.done <- &SettlementError{Reason: "abandoned", SQLState: state}
	}
}

// callWithRetry runs a settlement worker call until it succeeds, fails on
// content, or the gateway stops.
func (s *Service) callWithRetry(ctx context.Context, call func(context.Context) error) error {
	f := &s.finalizations
	for delay := retryInitialDelay; ; delay = min(retryMaxDelay, delay*2) {
		err := call(ctx)
		f.calls.Add(1)
		if err == nil {
			f.retrying.Store(false)
			return nil
		}
		f.failedCalls.Add(1)
		retry := ctx.Err() == nil && !contentError(err)
		f.retrying.Store(retry)
		if !retry || !sleepContext(ctx, jitteredRetryDelay(delay)) {
			return err
		}
	}
}

func settlementArrays(batch []*settlement) (string, string) {
	var logs, rejections []byte
	for _, item := range batch {
		target := &logs
		if item.rejection {
			target = &rejections
		}
		if len(*target) == 0 {
			*target = append(*target, '[')
		} else {
			*target = append(*target, ',')
		}
		*target = append(*target, item.payload...)
	}
	end := func(array []byte) string {
		if len(array) == 0 {
			return "[]"
		}
		return string(append(array, ']'))
	}
	return end(logs), end(rejections)
}

// callSettlement returns each result by request ID. The database answers every
// log and only the rejections it refused.
func (s *Service) callSettlement(ctx context.Context, logs string, rejections string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, settlementCallTimeout)
	defer cancel()
	rows, err := s.db.settlement.Query(ctx, s.settleQuery, logs, rejections)
	if err != nil {
		return nil, fmt.Errorf("settle gateway request logs: %w", err)
	}
	defer rows.Close()
	results := map[string]string{}
	for rows.Next() {
		var requestID *string
		var result string
		if err := rows.Scan(&requestID, &result); err != nil {
			return nil, fmt.Errorf("settle gateway request logs: %w", err)
		}
		if requestID != nil {
			results[*requestID] = result
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("settle gateway request logs: %w", err)
	}
	return results, nil
}

func (s *Service) resolveSettlements(batch []*settlement, results map[string]string) {
	for _, item := range batch {
		result, found := results[item.requestID]
		if item.rejection {
			if found {
				item.done <- &SettlementError{Reason: result}
			} else {
				item.done <- nil
			}
			continue
		}
		switch result {
		case "complete", "hold_not_found":
			item.done <- nil
		case "under_reserved":
			s.underReservedSettlements.Add(1)
			item.done <- nil
		case "negative_balance":
			s.negativeBalanceSettlements.Add(1)
			item.done <- nil
		case "payload_mismatch", "invalid_amount", "invalid_payload", "params_mismatch":
			s.finalizations.fail(&s.finalizations.refused)
			item.done <- &SettlementError{Reason: result}
		default:
			s.finalizations.fail(&s.finalizations.abandoned)
			item.done <- &SettlementError{Reason: "unknown_result"}
		}
	}
}

// contentError reports a database error that a log's contents can cause: a
// data exception, a constraint or program limit, or an error the function
// raised. Retrying cannot fix it, but settling the other logs without it can.
func contentError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || len(pgErr.Code) != 5 {
		return false
	}
	switch pgErr.Code[:2] {
	case "22", "23", "54", "P0":
		return true
	}
	return false
}

// sqlState returns the error's SQLSTATE if it has the standard form. The
// gateway logs only this and the request ID.
func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || len(pgErr.Code) != 5 {
		return ""
	}
	for _, c := range []byte(pgErr.Code) {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return ""
		}
	}
	return pgErr.Code
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// PostgreSQL can still commit a hold after authorization stopped waiting for
// it, and the gateway never runs that request. Closing it releases any such
// hold at zero charge once authorizeBefore passes. The close keeps the
// request's place and memory until it ends, so memory admission bounds closes
// as it bounds requests.
func (s *Service) closeUnconfirmedAuthorization(requestID string, keyID string, authorizeBefore time.Time, release func()) {
	f := &s.finalizations
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		release()
		return
	}
	s.startFinalizationWorkersLocked()
	ctx := f.ctx
	f.workers.Add(1)
	f.closing.Add(1)
	f.mu.Unlock()
	go func() {
		defer f.workers.Done()
		defer f.closing.Add(-1)
		defer release()
		wait := time.Until(authorizeBefore)
		for delay := retryInitialDelay; ; delay = min(retryMaxDelay, delay*2) {
			if !sleepContext(ctx, wait) {
				return
			}
			err := s.closeRequestOnce(ctx, requestID, keyID, authorizeBefore)
			if err == nil || ctx.Err() != nil || !(errors.Is(err, errClosePending) || errors.Is(err, context.DeadlineExceeded) || retryableDatabaseError(err)) {
				return
			}
			wait = jitteredRetryDelay(delay)
		}
	}()
}

// The database clock has not yet passed the authorization deadline.
var errClosePending = errors.New("close gateway request: authorization deadline pending")

// Each attempt has its own deadline. Closing is idempotent, so an attempt that
// timed out is safe to repeat.
func (s *Service) closeRequestOnce(ctx context.Context, requestID string, keyID string, authorizeBefore time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, closeTimeout)
	defer cancel()
	var result string
	if err := s.db.pool.QueryRow(ctx, s.closeRequestQuery, requestID, keyID, authorizeBefore).Scan(&result); err != nil {
		return fmt.Errorf("close gateway request: %w", err)
	}
	switch result {
	case "closed", "released":
		return nil
	case "pending":
		return errClosePending
	default:
		return fmt.Errorf("unexpected close result: %s", result)
	}
}

// Call after stopping inference admission and after every request ended, so no
// log remains to settle. It stores buffered rejections and waits for closes.
// Shutdown uses the server's existing cleanup deadline.
func (s *Service) DrainFinalizations(ctx context.Context) error {
	if s == nil {
		return nil
	}
	rejections := s.stopRejectionLogs()
	ticker := time.NewTicker(retryInitialDelay)
	defer ticker.Stop()
	for {
		f := &s.finalizations
		f.mu.Lock()
		idle := len(f.logs)+len(f.rejections)+f.settling == 0 && f.closing.Load() == 0
		f.mu.Unlock()
		if idle && !blocked(rejections) {
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func blocked(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

func (s *Service) closeFinalizations() {
	f := &s.finalizations
	f.mu.Lock()
	f.closed = true
	if f.cancel != nil {
		f.cancel()
	}
	f.mu.Unlock()
	f.workers.Wait()
	f.mu.Lock()
	queued := append(f.logs, f.rejections...)
	f.logs, f.rejections = nil, nil
	f.mu.Unlock()
	for _, item := range queued {
		item.done <- &SettlementError{Reason: "closed"}
	}
}

func (s *Service) settlementDiagnostics() SettlementDiagnostics {
	f := &s.finalizations
	f.mu.Lock()
	reserved, queued := f.reserved, len(f.logs)+len(f.rejections)+f.settling
	f.mu.Unlock()
	var lastFailedAt *time.Time
	if nanos := f.lastFailure.Load(); nanos != 0 {
		at := time.Unix(0, nanos).UTC()
		lastFailedAt = &at
	}
	return SettlementDiagnostics{
		Reserved: reserved, Closing: f.closing.Load(), Queued: queued, Retrying: f.retrying.Load(),
		Calls: f.calls.Load(), FailedCalls: f.failedCalls.Load(), Refused: f.refused.Load(), Abandoned: f.abandoned.Load(),
		LastFailedAt:  lastFailedAt,
		UnderReserved: s.underReservedSettlements.Load(), NegativeBalance: s.negativeBalanceSettlements.Load(),
		EncodingFailed: f.encodingFailed.Load(),
	}
}

func jitteredRetryDelay(delay time.Duration) time.Duration {
	if delay <= time.Nanosecond {
		return delay
	}
	half := delay / 2
	return half + time.Duration(rand.Int64N(int64(delay-half)+1))
}

func retryableDatabaseError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if len(pgErr.Code) == 5 {
			switch pgErr.Code[:2] {
			case "08", "40", "53": // Connection, transaction rollback, resource exhaustion.
				return true
			}
		}
		switch pgErr.Code {
		case "55P03", "57P01", "57P02", "57P03": // Lock contention or database restart.
			return true
		}
		return false
	}
	var networkError net.Error
	return errors.As(err, &networkError) || pgconn.SafeToRetry(err) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
