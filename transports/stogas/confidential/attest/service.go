package attest

import (
	"container/list"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	verifier "github.com/StogasAI/verifier/go"
)

var (
	ErrQuoteCapacity = errors.New("attestation setup capacity exhausted")
	ErrQuoteClosed   = errors.New("attestation service closed")
	ErrQuoteReport   = errors.New("invalid local attestation report")
)

// QuoteReservation acquires existing aggregate setup memory, without waiting.
// Its release function must cover this job, tree/proof and result storage until
// ownership ends. The transport separately retains its signer/session state.
// A reservation is required even for canceled or unauthenticated setup work.
type QuoteReservation func() (release func(), ok bool)

// ChannelQuote owns a reservation until Close. Report bytes are private to this
// result; callers cannot alter another connection's evidence through shared slices.
type ChannelQuote struct {
	Report  []byte
	Proof   []byte
	once    sync.Once
	release func()
}

func (q *ChannelQuote) Close() {
	if q != nil && q.release != nil {
		q.once.Do(q.release)
	}
}

type quoteJob struct {
	ctx     context.Context
	leaf    Leaf
	release func()
	result  chan quoteOutcome
	element *list.Element // guarded by Batcher.mu; nil once removed from the queue
	queued  time.Time
	owners  atomic.Int32
}

func (j *quoteJob) releaseOwner() {
	if j.owners.Add(-1) == 0 {
		j.release()
	}
}

type quoteOutcome struct {
	quote *ChannelQuote
	err   error
}

// Batcher runs one hardware request at a time. Idle work starts immediately;
// arrivals during that request form the next bounded batch. All pending work is
// admitted through the supplied memory reservation, not an unbounded channel.
type Batcher struct {
	attester Attester
	reserve  QuoteReservation
	ctx      context.Context
	cancel   context.CancelFunc
	wake     chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	pending  list.List
	stats    QuoteDiagnostics
}

type QuoteDiagnostics struct {
	Pending        int    `json:"pending"`
	Active         int    `json:"active"`
	PeakPending    int    `json:"peakPending"`
	Batches        uint64 `json:"batches"`
	Completed      uint64 `json:"completed"`
	Canceled       uint64 `json:"canceled"`
	Failed         uint64 `json:"failed"`
	Rejected       uint64 `json:"rejected"`
	QueueWaitNanos uint64 `json:"queueWaitNanos"`
	ReportNanos    uint64 `json:"reportNanos"`
}

func NewBatcher(attester Attester, reserve QuoteReservation) (*Batcher, error) {
	if attester == nil || reserve == nil {
		return nil, errors.New("attestation requires a backend and memory admission")
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Batcher{attester: attester, reserve: reserve, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{})}
	go b.run()
	return b, nil
}

// Quote transfers result ownership to the caller on success. Cancellation returns
// promptly, but a dispatched job keeps its reservation until the hardware returns.
func (b *Batcher) Quote(ctx context.Context, leaf Leaf) (*ChannelQuote, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if leaf == (Leaf{}) {
		return nil, errAbsentLeaf
	}
	if b.ctx.Err() != nil {
		return nil, ErrQuoteClosed
	}
	release, ok := b.reserve()
	if !ok || release == nil {
		b.mu.Lock()
		b.stats.Rejected++
		b.mu.Unlock()
		return nil, ErrQuoteCapacity
	}
	job := &quoteJob{ctx: ctx, leaf: leaf, release: release, result: make(chan quoteOutcome), queued: time.Now()}
	job.owners.Store(1)
	b.mu.Lock()
	if b.ctx.Err() != nil {
		b.mu.Unlock()
		release()
		return nil, ErrQuoteClosed
	}
	job.element = b.pending.PushBack(job)
	b.stats.Pending++
	b.stats.PeakPending = max(b.stats.PeakPending, b.stats.Pending)
	b.mu.Unlock()
	select {
	case b.wake <- struct{}{}:
	default:
	}
	select {
	case outcome := <-job.result:
		if err := ctx.Err(); err != nil {
			outcome.quote.Close()
			return nil, err
		}
		return outcome.quote, outcome.err
	case <-ctx.Done():
		b.removeCanceled(job)
		return nil, ctx.Err()
	case <-b.ctx.Done():
		b.removeCanceled(job)
		return nil, ErrQuoteClosed
	}
}

func (b *Batcher) removeCanceled(job *quoteJob) {
	b.mu.Lock()
	queued := job.element != nil
	if queued {
		b.pending.Remove(job.element)
		job.element = nil
		b.stats.Pending--
		b.stats.Canceled++
	}
	b.mu.Unlock()
	if queued {
		job.releaseOwner()
	}
}

// Close prevents admission and waits for actual hardware completion. A timed-out
// caller may stop waiting; it does not start a second worker or free active memory.
func (b *Batcher) Close(ctx context.Context) error {
	b.cancel()
	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Batcher) Diagnostics() QuoteDiagnostics {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}

func (b *Batcher) run() {
	defer close(b.done)
	for {
		select {
		case <-b.ctx.Done():
			b.clearQueue()
			return
		case <-b.wake:
		}
		for b.ctx.Err() == nil {
			jobs := b.takeBatch()
			if len(jobs) == 0 {
				break
			}
			b.generate(jobs)
		}
	}
}

func (b *Batcher) takeBatch() []*quoteJob {
	b.mu.Lock()
	defer b.mu.Unlock()
	jobs := make([]*quoteJob, 0, min(b.pending.Len(), MaxBatchLeaves))
	for len(jobs) < cap(jobs) {
		job := b.pending.Remove(b.pending.Front()).(*quoteJob)
		job.element = nil
		b.stats.Pending--
		b.stats.QueueWaitNanos += uint64(time.Since(job.queued))
		jobs = append(jobs, job)
	}
	b.stats.Active = len(jobs)
	return jobs
}

func (b *Batcher) clearQueue() {
	for {
		jobs := b.takeBatch()
		if len(jobs) == 0 {
			return
		}
		for _, job := range jobs {
			b.deliver(job, nil, ErrQuoteClosed)
		}
		for _, job := range jobs {
			job.releaseOwner()
		}
	}
}

func (b *Batcher) generate(jobs []*quoteJob) {
	// A proof result can be consumed before other results in its batch. Keep
	// every job's worker ownership through the shared tree's last use, so those
	// early closes cannot release the memory backing an unfinished batch.
	defer func() {
		for _, job := range jobs {
			job.releaseOwner()
		}
	}()
	// Cancellation can win after removal from the queue but before dispatch.
	active := make([]*quoteJob, 0, len(jobs))
	for _, job := range jobs {
		if job.ctx.Err() != nil || b.ctx.Err() != nil {
			b.deliver(job, nil, context.Canceled)
		} else {
			active = append(active, job)
		}
	}
	if len(active) == 0 {
		return
	}
	leaves := make([][64]byte, len(active))
	for i, job := range active {
		leaves[i] = job.leaf.hash
	}
	reportData, proofs, err := verifier.QuoteBatch(leaves)
	var report []byte
	if err == nil {
		start := time.Now()
		var envelope []byte
		envelope, err = b.attester.Quote(b.ctx, reportData)
		b.mu.Lock()
		b.stats.Batches++
		b.stats.ReportNanos += uint64(time.Since(start))
		b.mu.Unlock()
		if err == nil {
			report, err = batchReport(envelope, reportData)
		}
	}
	for i, job := range active {
		if job.ctx.Err() != nil || b.ctx.Err() != nil {
			b.deliver(job, nil, context.Canceled)
			continue
		}
		if err != nil {
			b.deliver(job, nil, err)
			continue
		}
		job.owners.Add(1)
		b.deliver(job, &ChannelQuote{Report: append([]byte(nil), report...), Proof: proofs[i], release: job.releaseOwner}, nil)
	}
}

func (b *Batcher) deliver(job *quoteJob, quote *ChannelQuote, err error) {
	// This unbuffered handoff transfers the reservation only if its caller receives
	// it. A disconnected caller cannot leave a retained result in a channel.
	canceled := false
	select {
	case job.result <- quoteOutcome{quote: quote, err: err}:
	case <-job.ctx.Done():
		canceled = true
	case <-b.ctx.Done():
		canceled = true
	}
	if quote != nil && canceled {
		quote.Close()
	}
	b.mu.Lock()
	b.stats.Active--
	if canceled {
		b.stats.Canceled++
	} else if err != nil {
		b.stats.Failed++
	} else {
		b.stats.Completed++
	}
	b.mu.Unlock()
}

// This is a local shape/binding check, not client hardware-signature validation.
func batchReport(encoded []byte, expected [64]byte) ([]byte, error) {
	var envelope Envelope
	if len(encoded) > 256*1024 || json.Unmarshal(encoded, &envelope) != nil || envelope.Schema != EnvelopeSchemaV1 || envelope.Provider != ProviderSEVGuest {
		return nil, ErrQuoteReport
	}
	report, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Report)
	if err != nil || len(report) != snpReportSize || !isSNPReport(report) || binary.LittleEndian.Uint32(report[0x30:0x34]) != 0 {
		return nil, ErrQuoteReport
	}
	if [64]byte(report[0x50:0x90]) != expected {
		return nil, ErrQuoteReport
	}
	return report, nil
}
