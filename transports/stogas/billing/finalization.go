package billing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	settleTimeout            = 2 * time.Second
	settleMaxAttempts        = 3
	finalizationCapacity     = 8192
	finalizationWorkerCount  = 6
	finalizationInitialDelay = 250 * time.Millisecond
	finalizationMaxDelay     = 5 * time.Second
)

// RetainMemory transfers existing request admission to a smaller retained
// owner. A nil function is used by callers without an aggregate byte budget.
type RetainMemory func(bytes int) (release func(), ok bool)

type finalizationState struct {
	mu             sync.Mutex
	reserved       int
	closed         bool
	queue          chan *finalizationRetryTask
	ctx            context.Context
	cancel         context.CancelFunc
	workers        sync.WaitGroup
	pending        atomic.Int64
	abandoned      atomic.Int64
	encodingFailed atomic.Bool
}

type finalizationRetryTask struct {
	authorization       Authorization
	holdParamsHash      string
	upstreamCostUSD     string
	requestEventPayload string
	releaseMemory       func()
}

// Every admitted request reserves its eventual retry slot before touching the
// wallet. A failing destination cannot exhaust space needed by live requests.
func (s *Service) reserveFinalization() (func(), error) {
	f := &s.finalizations
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.encodingFailed.Load() || s.rejectionLogs.deliveryBlocked.Load() || f.pending.Load() != 0 || f.reserved >= finalizationCapacity {
		return nil, ErrGatewayUnavailable
	}
	f.reserved++
	var once sync.Once
	return func() { once.Do(func() { f.mu.Lock(); f.reserved--; f.mu.Unlock() }) }, nil
}

func (s *Service) FinalizationReady() bool {
	if s == nil {
		return true
	}
	f := &s.finalizations
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.closed && !f.encodingFailed.Load() && !s.rejectionLogs.deliveryBlocked.Load() && f.pending.Load() == 0 && f.reserved < finalizationCapacity
}

func (s *Service) FinalizeRequest(ctx context.Context, authorization *Authorization, event RequestEvent, retain RetainMemory) error {
	if authorization == nil {
		return nil
	}
	release := authorization.releaseFinalization
	defer func() {
		if release != nil {
			release()
		}
	}()
	s.recordRequestOutcome(authorization, event)
	holdParamsHash := createHoldParamsHash(authorization.ProviderKey, authorization.ProductKey, authorization.UpstreamTargetJSON)
	event.holdParamsHash = holdParamsHash
	upstreamCostRaw := event.Usage.UpstreamCostUSD
	if upstreamCostRaw == "" {
		upstreamCostRaw = ZeroChargeUSD
	}
	upstreamCostUSD, err := ParseUSD(upstreamCostRaw)
	if err != nil {
		s.finalizations.encodingFailed.Store(true)
		return fmt.Errorf("invalid upstream cost: %w", err)
	}
	event.Usage.UpstreamCostUSD = upstreamCostUSD.String()
	event.Usage.BilledCostUSD = calculateBilledCostUSD(authorization, upstreamCostUSD).String()
	payload, err := encodeGatewayRequestEvent(event)
	if err != nil {
		s.finalizations.encodingFailed.Store(true)
		return err
	}
	destination, deliveryErr := s.requestLogs.AppendGatewayRequest(ctx, event)
	if (destination == LogQueue || destination == LogQuarantine) && deliveryErr == nil {
		return nil
	}
	if destination == LogTinybird && deliveryErr == nil {
		// Durable evidence lets the expired-hold janitor recover a failed settlement.
		_ = s.settleWithRetry(ctx, authorization, holdParamsHash, upstreamCostUSD.String(), payload)
		return nil
	}
	task := &finalizationRetryTask{
		authorization: Authorization{KeyID: authorization.KeyID, ProductKey: authorization.ProductKey,
			ProviderKey: authorization.ProviderKey, RequestID: authorization.RequestID, releaseFinalization: release},
		holdParamsHash: holdParamsHash, upstreamCostUSD: upstreamCostUSD.String(), requestEventPayload: payload,
	}
	_ = s.finalizationContext()
	s.finalizations.pending.Add(1)
	release = nil
	if retain != nil {
		bytes := int(unsafe.Sizeof(*task)) + len(payload) + len(holdParamsHash) + len(task.upstreamCostUSD) +
			len(authorization.KeyID) + len(authorization.ProductKey) + len(authorization.ProviderKey) + len(authorization.RequestID)
		var ok bool
		task.releaseMemory, ok = retain(bytes)
		if !ok {
			// Retention normally fits within the original request reservation. If the
			// owner cannot transfer it, keep that owner alive until delivery or shutdown.
			retryCtx := s.finalizationContext()
			delay := finalizationInitialDelay
			for retryCtx.Err() == nil && !s.retryFinalization(retryCtx, task, delay) {
				delay = min(finalizationMaxDelay, delay*2)
			}
			s.finishFinalization(task, retryCtx.Err() != nil)
			return nil
		}
	}
	f := &s.finalizations
	f.mu.Lock()
	s.startFinalizationWorkersLocked()
	if f.closed {
		f.mu.Unlock()
		s.finishFinalization(task, true)
		return nil
	}
	// The reservation makes this nonblocking for all accepted requests.
	select {
	case f.queue <- task:
		f.mu.Unlock()
	default:
		f.mu.Unlock()
		// Defensive caller misuse still preserves the payload under its request owner.
		retryCtx := s.finalizationContext()
		delay := finalizationInitialDelay
		for retryCtx.Err() == nil && !s.retryFinalization(retryCtx, task, delay) {
			delay = min(finalizationMaxDelay, delay*2)
		}
		s.finishFinalization(task, retryCtx.Err() != nil)
	}
	return nil
}

func (s *Service) finalizationContext() context.Context {
	f := &s.finalizations
	f.mu.Lock()
	defer f.mu.Unlock()
	s.startFinalizationWorkersLocked()
	return f.ctx
}

func (s *Service) startFinalizationWorkersLocked() {
	f := &s.finalizations
	if f.ctx != nil {
		return
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.queue = make(chan *finalizationRetryTask, finalizationCapacity)
	if f.closed {
		f.cancel()
		return
	}
	f.workers.Add(finalizationWorkerCount)
	for range finalizationWorkerCount {
		go func() {
			defer f.workers.Done()
			delay := finalizationInitialDelay
			for {
				select {
				case <-f.ctx.Done():
					return
				case task := <-f.queue:
					if s.retryFinalization(f.ctx, task, delay) {
						s.finishFinalization(task, false)
						delay = 0
						continue
					}
					delay = max(finalizationInitialDelay, min(finalizationMaxDelay, delay*2))
					if f.ctx.Err() != nil {
						s.finishFinalization(task, true)
						return
					}
					// One attempt per turn prevents a permanently bad record from starving
					// other accepted requests. Active workers each own a reserved queue slot.
					select {
					case f.queue <- task:
					case <-f.ctx.Done():
						s.finishFinalization(task, true)
						return
					}
				}
			}
		}()
	}
}

func (s *Service) retryFinalization(ctx context.Context, task *finalizationRetryTask, delay time.Duration) bool {
	if delay > 0 {
		timer := time.NewTimer(jitteredSettleRetryDelay(delay))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return false
		}
	}
	event, err := decodeGatewayRequestEvent(task.requestEventPayload)
	if err != nil {
		s.finalizations.encodingFailed.Store(true)
		return false
	}
	event.holdParamsHash = task.holdParamsHash
	destination, err := s.requestLogs.AppendGatewayRequest(ctx, event)
	if err == nil && (destination == LogQueue || destination == LogQuarantine) {
		return true
	}
	if err == nil && destination == LogTinybird {
		_ = s.settleWithRetry(ctx, &task.authorization, task.holdParamsHash, task.upstreamCostUSD, task.requestEventPayload)
		return true
	}
	return false
}

func (s *Service) finishFinalization(task *finalizationRetryTask, abandoned bool) {
	if task.releaseMemory != nil {
		task.releaseMemory()
	}
	if task.authorization.releaseFinalization != nil {
		task.authorization.releaseFinalization()
	}
	f := &s.finalizations
	if abandoned {
		f.abandoned.Add(1)
	}
	f.pending.Add(-1)

}

// Call after stopping inference admission. Shutdown uses the server's existing
// cleanup deadline; normal operation never discards a log because time elapsed.
func (s *Service) DrainFinalizations(ctx context.Context) error {
	if s == nil {
		return nil
	}
	ticker := time.NewTicker(finalizationInitialDelay)
	defer ticker.Stop()
	for s.finalizations.pending.Load() != 0 || s.rejectionLogs.deliveryBlocked.Load() {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *Service) closeFinalizations() {
	f := &s.finalizations
	f.mu.Lock()
	f.closed = true
	if f.cancel != nil {
		f.cancel()
	}
	queue := f.queue
	f.mu.Unlock()
	f.workers.Wait()
	if queue != nil {
		for {
			select {
			case task := <-queue:
				s.finishFinalization(task, true)
			default:
				return
			}
		}
	}
}

func (s *Service) finalizationQueueDepth() int {
	s.finalizations.mu.Lock()
	defer s.finalizations.mu.Unlock()
	return len(s.finalizations.queue)
}

func jitteredSettleRetryDelay(delay time.Duration) time.Duration {
	if delay <= time.Nanosecond {
		return delay
	}
	half := delay / 2
	return half + time.Duration(rand.Int64N(int64(delay-half)+1))
}

// All attempts share the existing deadline. Hold deletion makes even an
// ambiguous connection failure safe to retry; permanent failures await review.
func (s *Service) settleWithRetry(ctx context.Context, authorization *Authorization, holdParamsHash string, upstreamCostUSD string, requestEventPayload string) error {
	ctx, cancel := context.WithTimeout(ctx, settleTimeout)
	defer cancel()
	for attempt := 0; ; attempt++ {
		err := s.settleOnce(ctx, authorization, holdParamsHash, upstreamCostUSD, requestEventPayload)
		if err == nil || attempt+1 == settleMaxAttempts || !retryableSettlementError(err) {
			return err
		}
		timer := time.NewTimer(jitteredSettleRetryDelay(finalizationInitialDelay << attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func retryableSettlementError(err error) bool {
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

// PostgreSQL derives billed cost from the hold's frozen credential source and
// verifies the request-event payload within the caller's settlement deadline.
func (s *Service) settleOnce(ctx context.Context, authorization *Authorization, holdParamsHash string, upstreamCostUSD string, requestEventPayload string) error {
	row := settleRow{}

	err := s.db.pool.QueryRow(
		ctx,
		s.settleHoldQuery,
		authorization.RequestID,
		authorization.KeyID,
		authorization.ProviderKey,
		authorization.ProductKey,
		holdParamsHash,
		upstreamCostUSD,
		requestEventPayload,
	).Scan(&row.Result, &row.BilledCostUSD, &row.BalanceAdjustmentUSD, &row.AvailableBalanceUSD)
	if err != nil {
		return fmt.Errorf("settle gateway hold: %w", err)
	}

	switch row.Result {
	case "complete", "hold_not_found":
		return nil
	case "under_reserved":
		s.underReservedSettlements.Add(1)
		return nil
	case "negative_balance":
		s.negativeBalanceSettlements.Add(1)
		return nil
	case "params_mismatch", "review_required":
		return &settleResultError{err: ErrAuthorizationClosed, result: row.Result, statusCode: 409}
	case "invalid_amount", "invalid_payload", "payload_mismatch":
		return &settleResultError{err: errors.New("invalid settlement payload"), result: row.Result, statusCode: 400}
	default:
		return fmt.Errorf("unknown settlement result: %s", row.Result)
	}
}
