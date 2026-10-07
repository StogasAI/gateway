package exporter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

const (
	memoryLimit       = 64 << 20
	maxBatchBytes     = 512 << 10
	maxBatchRecords   = 64
	batchDelay        = 200 * time.Millisecond
	deliveryAge       = 30 * time.Second
	deliveryTimeout   = 5 * time.Second
	deliveryWorkers   = 4
	maxPendingRecords = 512
)

// Lease accounts retained export allocations in the gateway's shared budget.
// Export admission is nonwaiting; a failed Grow drops capture, never inference.
type Lease interface {
	Grow(int) bool
	Release()
}
type Options struct {
	Local    bool
	NewLease func() Lease
}
type Diagnostics struct {
	ReservedBytes    int64  `json:"reservedBytes"`
	MemoryLimitBytes int64  `json:"memoryLimitBytes"`
	PendingRecords   int64  `json:"pendingRecords"`
	Delivered        uint64 `json:"delivered"`
	Dropped          uint64 `json:"dropped"`
	Retried          uint64 `json:"retried"`
	Rejected         uint64 `json:"rejected"`
	Truncated        uint64 `json:"truncated"`
}
type Engine struct {
	options                                          Options
	client                                           deliveryClient
	ctx                                              context.Context
	cancel                                           context.CancelFunc
	mu                                               sync.Mutex
	closed                                           bool
	input                                            chan *job
	batches                                          chan *delivery
	results                                          chan *delivery
	done                                             chan struct{}
	workers                                          sync.WaitGroup
	bytes, pending                                   atomic.Int64
	delivered, dropped, retried, rejected, truncated atomic.Uint64
}
type reservation struct {
	engine *Engine
	lease  Lease
	bytes  int
}

func (r *reservation) grow(n int) bool {
	if n <= 0 {
		return true
	}
	for {
		previous := r.engine.bytes.Load()
		if int64(n) > memoryLimit-previous {
			return false
		}
		if r.engine.bytes.CompareAndSwap(previous, previous+int64(n)) {
			break
		}
	}
	if r.lease != nil && !r.lease.Grow(n) {
		r.engine.bytes.Add(-int64(n))
		return false
	}
	r.bytes += n
	return true
}
func (r *reservation) release() {
	if r == nil {
		return
	}
	r.engine.bytes.Add(-int64(r.bytes))
	r.bytes = 0
	if r.lease != nil {
		r.lease.Release()
		r.lease = nil
	}
}
func (e *Engine) reserve() *reservation {
	r := &reservation{engine: e}
	if e.options.NewLease != nil {
		r.lease = e.options.NewLease()
	}
	return r
}

type Capture struct {
	engine        *Engine
	tenant        string
	destinations  []exportconfig.Destination
	input, output conversation
	reservation   *reservation
	parameters    pcommon.Map
}

// Record is the explicit metadata boundary. Metadata contains the existing
// customer request event, never the gateway state, credentials or HTTP headers.
type Record struct {
	RequestID, Model, ResponseModel, Provider, RequestType, Version                 string
	StartedAt, EndedAt                                                              time.Time
	Outcome, ErrorCode                                                              string
	ErrorStatus                                                                     int
	InputTokens, OutputTokens, CachedInputTokens, CacheWriteTokens, ReasoningTokens *int64
	TimeToFirstTokenMS                                                              *uint32
	FinishReason                                                                    string
	CostUSD, Metadata                                                               string
}
type job struct {
	target      exportconfig.Destination
	group       [32]byte
	traces      ptrace.Traces
	encodedSize int
	created     time.Time
	reservation *reservation
}

func New(ctx context.Context, options Options) *Engine {
	ctx, cancel := context.WithCancel(ctx)
	e := &Engine{options: options, ctx: ctx, cancel: cancel, input: make(chan *job, maxPendingRecords), batches: make(chan *delivery), results: make(chan *delivery, deliveryWorkers), done: make(chan struct{})}
	e.client = newDeliveryClient(options.Local)
	for range deliveryWorkers {
		e.workers.Add(1)
		go e.worker()
	}
	go e.batch()
	return e
}
func (e *Engine) Start(tenant, requestID string, config *exportconfig.Config) *Capture {
	if e == nil || config == nil || len(config.Destinations) == 0 {
		return nil
	}
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return nil
	}
	r := e.reserve()
	if !r.grow(4096) {
		r.release()
		e.dropped.Add(1)
		return nil
	}
	c := &Capture{engine: e, tenant: tenant, reservation: r, parameters: pcommon.NewMap()}
	c.input.budget = r
	c.output.budget = r
	c.output.output = true
	for _, d := range config.Destinations {
		if sampleValue(requestID) >= d.Rate() {
			continue
		}
		raw, _ := json.Marshal(d)
		if !r.grow(len(raw)*4 + 512) {
			clear(raw)
			e.dropped.Add(1)
			continue
		}
		// This copy also detaches strings from decrypted source-document buffers.
		var copy exportconfig.Destination
		err := json.Unmarshal(raw, &copy)
		clear(raw)
		if err != nil {
			continue
		}
		c.destinations = append(c.destinations, copy)
		if d.InputEnabled() {
			c.input.limit = max(c.input.limit, d.CaptureLimit())
		}
		if d.OutputEnabled() {
			c.output.limit = max(c.output.limit, d.CaptureLimit())
		}
	}
	if len(c.destinations) == 0 {
		r.release()
		return nil
	}
	return c
}
func (c *Capture) Discard() {
	if c == nil || c.reservation == nil {
		return
	}
	c.input.clear()
	c.output.clear()
	c.destinations = nil
	c.reservation.release()
	c.reservation = nil
}
func (c *Capture) Finish(record Record) {
	if c == nil || c.reservation == nil {
		return
	}
	defer c.Discard()
	for _, d := range c.destinations {
		if !d.Match(record.Outcome, record.ErrorStatus, record.ErrorCode) {
			continue
		}
		r := c.engine.reserve()
		// Covers pdata objects, JSON escaping and the overlapping batch encoder.
		size := len(record.Metadata) + len(record.Model) + len(record.ResponseModel) + len(record.Provider)
		if d.InputEnabled() {
			size += min(c.input.used, d.CaptureLimit())
		}
		if d.OutputEnabled() {
			size += min(c.output.used, d.CaptureLimit())
		}
		if !r.grow(size*24 + len(d.URL)*4 + exportconfig.MaxHeaderBytes*4 + 16384) {
			r.release()
			c.engine.dropped.Add(1)
			continue
		}
		limit := d.CaptureLimit()
		var traces ptrace.Traces
		var encoded []byte
		truncated := false
		for {
			traces, truncated = c.trace(record, d, limit)
			request := ptraceotlp.NewExportRequestFromTraces(traces)
			var err error
			if d.Encoding == "protobuf" {
				encoded, err = request.MarshalProto()
			} else {
				encoded, err = request.MarshalJSON()
			}
			if err != nil {
				encoded = nil
				break
			}
			if len(encoded) <= maxBatchBytes-1024 {
				break
			}
			clear(encoded)
			if limit == 0 {
				encoded = nil
				break
			}
			limit /= 2
		}
		if encoded == nil {
			r.release()
			c.engine.dropped.Add(1)
			continue
		}
		if truncated {
			c.engine.truncated.Add(1)
		}
		n := len(encoded)
		clear(encoded)
		id := d.Identity()
		group := sha256.Sum256(append([]byte(c.tenant+"\x00"), id[:]...))
		j := &job{target: d, group: group, traces: traces, encodedSize: n, created: time.Now(), reservation: r}
		c.engine.enqueue(j)
	}
}
func (e *Engine) enqueue(j *job) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.pending.Load() >= maxPendingRecords {
		e.drop(j)
		return
	}
	e.pending.Add(1)
	select {
	case e.input <- j:
	default:
		e.pending.Add(-1)
		e.drop(j)
	}
}
func (e *Engine) drop(j *job) {
	e.dropped.Add(1)
	j.traces = ptrace.Traces{}
	j.target = exportconfig.Destination{}
	j.reservation.release()
}
func (e *Engine) release(batch []*job) {
	for _, j := range batch {
		j.traces = ptrace.Traces{}
		j.target = exportconfig.Destination{}
		j.reservation.release()
		e.pending.Add(-1)
	}
}

// batch owns all waiting work. Backoff never occupies an HTTP worker, so an
// unavailable destination cannot monopolize workers while waiting to retry.
func (e *Engine) batch() {
	defer close(e.done)
	defer close(e.batches)
	groups := map[[32]byte][]*job{}
	sizes := map[[32]byte]int{}
	var waiting []*delivery
	inflight := 0
	input, stopped := e.input, e.ctx.Done()
	flush := func(key [32]byte) {
		jobs := groups[key]
		delete(groups, key)
		delete(sizes, key)
		waiting = append(waiting, &delivery{jobs: jobs, deadline: jobs[0].created.Add(deliveryAge)})
	}
	timer := time.NewTimer(batchDelay)
	defer timer.Stop()
	for {
		now := time.Now()
		wake := now.Add(deliveryAge)
		for key, jobs := range groups {
			at := jobs[0].created.Add(batchDelay)
			if input == nil || !now.Before(at) {
				flush(key)
			} else if at.Before(wake) {
				wake = at
			}
		}
		ready := -1
		for i := 0; i < len(waiting); {
			b := waiting[i]
			if e.ctx.Err() != nil || !now.Before(b.deadline) {
				e.dropped.Add(uint64(len(b.jobs)))
				e.releaseDelivery(b)
				waiting = slices.Delete(waiting, i, i+1)
				continue
			}
			if !now.Before(b.nextAttempt) {
				if ready == -1 {
					ready = i
				}
			} else if b.nextAttempt.Before(wake) {
				wake = b.nextAttempt
			}
			if b.deadline.Before(wake) {
				wake = b.deadline
			}
			i++
		}
		if input == nil && len(groups) == 0 && len(waiting) == 0 && inflight == 0 {
			return
		}
		var dispatch chan *delivery
		var next *delivery
		if ready >= 0 {
			dispatch, next = e.batches, waiting[ready]
		}
		timer.Reset(max(0, time.Until(wake)))
		select {
		case j, ok := <-input:
			if !ok {
				input = nil
				continue
			}
			if sizes[j.group]+j.encodedSize > maxBatchBytes {
				flush(j.group)
			}
			groups[j.group] = append(groups[j.group], j)
			sizes[j.group] += j.encodedSize
			if len(groups[j.group]) >= maxBatchRecords {
				flush(j.group)
			}
		case dispatch <- next:
			waiting = slices.Delete(waiting, ready, ready+1)
			inflight++
		case b := <-e.results:
			inflight--
			if b.finished {
				e.releaseDelivery(b)
			} else {
				waiting = append(waiting, b)
			}
		case <-timer.C:
		case <-stopped:
			// Also stop admission when the parent context ends before Close.
			e.mu.Lock()
			if !e.closed {
				e.closed = true
				close(e.input)
			}
			e.mu.Unlock()
			stopped = nil
		}
	}
}
func (e *Engine) releaseDelivery(b *delivery) {
	clear(b.payload)
	b.payload = nil
	e.release(b.jobs)
}
func (e *Engine) worker() {
	defer e.workers.Done()
	for b := range e.batches {
		e.deliver(b)
		e.results <- b
	}
}
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		close(e.input)
	}
	e.mu.Unlock()
	timer := time.AfterFunc(deliveryTimeout, e.cancel)
	<-e.done
	e.workers.Wait()
	timer.Stop()
	e.cancel()
	e.client.close()
}
func (e *Engine) Diagnostics() Diagnostics {
	if e == nil {
		return Diagnostics{}
	}
	return Diagnostics{ReservedBytes: e.bytes.Load(), MemoryLimitBytes: memoryLimit, PendingRecords: e.pending.Load(), Delivered: e.delivered.Load(), Dropped: e.dropped.Load(), Retried: e.retried.Load(), Rejected: e.rejected.Load(), Truncated: e.truncated.Load()}
}
func sha256ID(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}
