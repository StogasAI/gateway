package billing

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/retry"
)

// A boot's key signs every request log row that the gateway sends to analytics, in numbered
// batches. Each row names its batch and leaf in log_batch before the gateway hashes it, so the
// leaf covers the row's own place. A batch closes at the end of each UTC minute, or once it
// holds maxLogBatchLeaves rows. The gateway stores each signed batch with its leaves through the
// database, which passes it to analytics like the rows, and Control builds a row's proof from
// them. A row's batch can close before the row reaches the database, or the row can fail to
// settle; the batch keeps its leaf either way.
const (
	maxLogBatchLeaves = 8192
	// Sealed batches wait here while the database is unreachable, each with at most 683 KiB
	// of encoded leaves. Beyond this, the oldest batch that is not being stored is dropped.
	maxPendingLogBatches = 32
	logBatchStoreTimeout = 5 * time.Second
)

// LogSigner signs this boot's request log batches. The confidential runtime provides one; a
// gateway without it logs rows without a batch.
type LogSigner interface {
	// NodeID is the attested node that every signed row names.
	NodeID() string
	// LogRowLeaf hashes one encoded row into its batch's tree.
	LogRowLeaf(row []byte) ([64]byte, error)
	// SignLogBatch signs the batch of these leaves and returns it as JSON without them.
	SignLogBatch(sequence uint32, openedAt, sealedAt time.Time, leaves [][64]byte) ([]byte, error)
}

type LogBatchDiagnostics struct {
	Signing bool `json:"signing"`
	// Sequence is the number of the newest batch.
	Sequence       uint32     `json:"sequence"`
	OpenRows       int        `json:"openRows"`
	PendingBatches int        `json:"pendingBatches"`
	SignedRows     uint64     `json:"signedRows"`
	UnsignedRows   uint64     `json:"unsignedRows"`
	StoredBatches  uint64     `json:"storedBatches"`
	DroppedBatches uint64     `json:"droppedBatches"`
	LastFailedAt   *time.Time `json:"lastFailedAt,omitempty"`
}

type openLogBatch struct {
	sequence uint32
	openedAt time.Time
	leaves   [][64]byte
}

// pendingLogBatch is a signed batch with its leaves, as the database stores it.
type pendingLogBatch struct {
	line string
}

type logBatchState struct {
	mu     sync.Mutex
	signer LogSigner
	// The newest batch's number. Numbers start at 1 and leave no gap: a batch opens only
	// with the row whose leaf it holds first.
	sequence uint32
	open     *openLogBatch
	// Sealed batches, oldest first. The worker stores the first; storing marks it.
	pending []*pendingLogBatch
	storing *pendingLogBatch
	closed  bool
	// period is how often the open batch closes, on UTC boundaries: a minute, or less in tests.
	period time.Duration
	wake   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
	diag   LogBatchDiagnostics
}

// The database refused a batch, which another attempt cannot change.
var errLogBatchRefused = errors.New("log batch refused")

// SetLogSigner makes the gateway sign its request log rows. Call it before serving.
func (s *Service) SetLogSigner(signer LogSigner) {
	b := &s.logBatches
	b.mu.Lock()
	defer b.mu.Unlock()
	b.signer = signer
}

// encodeSignedRow encodes a row as analytics stores it. With a signer, the row first takes the
// next place in the open batch, and its leaf joins the batch. A row stays unsigned, with a null
// log_batch, when it names another node, after the gateway drained, or when RFC 8785 cannot
// write it exactly, such as with an integer beyond 2^53.
func (s *Service) encodeSignedRow(event *RequestEvent) (string, error) {
	b := &s.logBatches
	b.mu.Lock()
	defer b.mu.Unlock()
	event.LogBatch = nil
	if b.signer == nil {
		return encodeRequestRow(event)
	}
	if b.closed || event.NodeID != b.signer.NodeID() || (b.open == nil && b.sequence == math.MaxUint32) {
		b.diag.UnsignedRows++
		return encodeRequestRow(event)
	}
	place := LogPosition{Sequence: b.sequence + 1}
	if b.open != nil {
		place = LogPosition{Sequence: b.open.sequence, Index: uint32(len(b.open.leaves))}
	}
	event.LogBatch = &place
	row, err := encodeRequestRow(event)
	if err != nil {
		event.LogBatch = nil
		return "", err
	}
	leaf, err := b.signer.LogRowLeaf([]byte(row))
	if err != nil {
		event.LogBatch = nil
		b.diag.UnsignedRows++
		return encodeRequestRow(event)
	}
	now := time.Now()
	if b.open == nil {
		b.sequence = place.Sequence
		b.open = &openLogBatch{sequence: place.Sequence, openedAt: now}
		b.startLocked(s)
	}
	b.open.leaves = append(b.open.leaves, leaf)
	b.diag.SignedRows++
	if len(b.open.leaves) == maxLogBatchLeaves {
		b.sealLocked(now)
	}
	return row, nil
}

// placeRow gives a row its place in the signed log, as encodeSignedRow does, for a row that
// settles later. A row that cannot be encoded stays unsigned and fails settlement.
func (s *Service) placeRow(event *RequestEvent) {
	b := &s.logBatches
	b.mu.Lock()
	signing := b.signer != nil
	b.mu.Unlock()
	if signing {
		_, _ = s.encodeSignedRow(event)
	}
}

func (b *logBatchState) startLocked(s *Service) {
	if b.done != nil {
		return
	}
	period := b.period
	if period <= 0 {
		period = time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.wake, b.cancel, b.done = make(chan struct{}, 1), cancel, make(chan struct{})
	go s.runLogBatches(ctx, period)
}

// sealLocked signs the open batch and queues it for the database.
func (b *logBatchState) sealLocked(now time.Time) {
	batch := b.open
	if batch == nil {
		return
	}
	b.open = nil
	// The wall clock can step back while a batch is open; a batch never closes before it opened.
	sealedAt := now
	if sealedAt.UnixMilli() < batch.openedAt.UnixMilli() {
		sealedAt = batch.openedAt
	}
	signed, err := b.signer.SignLogBatch(batch.sequence, batch.openedAt, sealedAt, batch.leaves)
	if err != nil || len(signed) < 2 || signed[len(signed)-1] != '}' {
		b.failLocked()
		return
	}
	if len(b.pending) == maxPendingLogBatches {
		oldest := 0
		if b.pending[0] == b.storing {
			oldest = 1
		}
		b.pending = append(b.pending[:oldest], b.pending[oldest+1:]...)
		b.failLocked()
	}
	b.pending = append(b.pending, &pendingLogBatch{line: logBatchLine(signed, batch.leaves)})
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func (b *logBatchState) failLocked() {
	b.diag.DroppedBatches++
	now := time.Now().UTC()
	b.diag.LastFailedAt = &now
}

// logBatchLine adds the leaves to a signed batch: base64url without padding of the leaves in
// order, 64 bytes each.
func logBatchLine(signed []byte, leaves [][64]byte) string {
	raw := make([]byte, 0, len(leaves)*64)
	for _, leaf := range leaves {
		raw = append(raw, leaf[:]...)
	}
	return string(signed[:len(signed)-1]) + `,"leaves":"` + base64.RawURLEncoding.EncodeToString(raw) + `"}`
}

// runLogBatches seals the open batch at the end of each period, a UTC minute, and stores sealed
// batches oldest first. After a failed call it waits before the next, as settlement does.
func (s *Service) runLogBatches(ctx context.Context, period time.Duration) {
	b := &s.logBatches
	defer close(b.done)
	untilNext := func() time.Duration { return time.Until(time.Now().Truncate(period).Add(period)) }
	tick := time.NewTimer(untilNext())
	defer tick.Stop()
	var retryAt <-chan time.Time
	delay := retryInitialDelay
	for {
		select {
		case now := <-tick.C:
			b.mu.Lock()
			b.sealLocked(now)
			b.mu.Unlock()
			tick.Reset(untilNext())
		case <-b.wake:
		case <-retryAt:
			retryAt = nil
		case <-ctx.Done():
			return
		}
		for retryAt == nil {
			b.mu.Lock()
			if len(b.pending) == 0 {
				b.mu.Unlock()
				break
			}
			batch := b.pending[0]
			b.storing = batch
			b.mu.Unlock()
			err := s.storeLogBatch(ctx, batch.line)
			if ctx.Err() != nil {
				return
			}
			b.mu.Lock()
			b.storing = nil
			if err == nil || errors.Is(err, errLogBatchRefused) || contentError(err) {
				if err == nil {
					b.diag.StoredBatches++
					delay = retryInitialDelay
				} else {
					b.failLocked()
				}
				if len(b.pending) > 0 && b.pending[0] == batch {
					b.pending[0] = nil
					b.pending = b.pending[1:]
				}
			} else {
				retryAt = time.After(retry.Jitter(delay))
				delay = min(retryMaxDelay, delay*2)
			}
			b.mu.Unlock()
		}
	}
}

func (s *Service) storeLogBatch(ctx context.Context, line string) error {
	ctx, cancel := context.WithTimeout(ctx, logBatchStoreTimeout)
	defer cancel()
	var result string
	if err := s.db.pool.QueryRow(ctx, s.storeLogBatchQuery, line).Scan(&result); err != nil {
		return fmt.Errorf("store gateway log batch: %w", err)
	}
	if result != "stored" {
		return fmt.Errorf("%w: %s", errLogBatchRefused, result)
	}
	return nil
}

// SealLogBatches signs the open batch once every row has its place, before the boot's key is
// erased. Rows after this stay unsigned; DrainFinalizations stores the sealed batches.
func (s *Service) SealLogBatches() {
	if s == nil {
		return
	}
	b := &s.logBatches
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.sealLocked(time.Now())
}

// drainLogBatches waits until the database holds every sealed batch.
func (s *Service) drainLogBatches(ctx context.Context) error {
	s.SealLogBatches()
	b := &s.logBatches
	ticker := time.NewTicker(retryInitialDelay)
	defer ticker.Stop()
	for {
		b.mu.Lock()
		idle := len(b.pending) == 0
		b.mu.Unlock()
		if idle {
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// closeLogBatches stops the worker. Batches that the database does not hold by then are lost.
func (s *Service) closeLogBatches() {
	b := &s.logBatches
	b.mu.Lock()
	b.closed = true
	cancel, done := b.cancel, b.done
	b.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	lost := len(b.pending)
	if b.open != nil {
		lost++
	}
	b.pending, b.open = nil, nil
	for range lost {
		b.failLocked()
	}
}

func (s *Service) logBatchDiagnostics() LogBatchDiagnostics {
	b := &s.logBatches
	b.mu.Lock()
	defer b.mu.Unlock()
	diagnostics := b.diag
	diagnostics.Signing = b.signer != nil && !b.closed
	diagnostics.Sequence = b.sequence
	if b.open != nil {
		diagnostics.OpenRows = len(b.open.leaves)
	}
	diagnostics.PendingBatches = len(b.pending)
	return diagnostics
}
