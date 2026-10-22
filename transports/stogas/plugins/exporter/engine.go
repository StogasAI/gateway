package exporter

import (
	"container/list"
	"context"
	"encoding/json"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
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

// Counts are per destination delivery. Memory drops separate gateway capacity
// from receiver failures, which also include expiry and shutdown.
type Diagnostics struct {
	ReservedBytes     int64  `json:"reservedBytes"`
	PendingDeliveries int64  `json:"pendingDeliveries"`
	Delivered         uint64 `json:"delivered"`
	Retried           uint64 `json:"retried"`
	Failed            uint64 `json:"failed"`
	MemoryDropped     uint64 `json:"memoryDropped"`
}

// Each destination delivery runs independently, so a slow receiver delays only
// its own records. Memory admission bounds retained records, and Reclaim gives
// that memory back to inference, oldest record first.
type Engine struct {
	options                                   Options
	client                                    deliveryClient
	ctx                                       context.Context
	cancel                                    context.CancelFunc
	mu                                        sync.Mutex
	closed                                    bool
	records                                   list.List
	deliveries                                sync.WaitGroup
	bytes, pending                            atomic.Int64
	delivered, retried, failed, memoryDropped atomic.Uint64
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
	if !r.lease.Grow(n) {
		return false
	}
	r.bytes += n
	r.engine.bytes.Add(int64(n))
	return true
}
func (r *reservation) release() {
	r.lease.Release()
	r.engine.bytes.Add(-int64(r.bytes))
	r.bytes = 0
}

// Capture owns detached public JSON until Finish transfers it to delivery.
// Its methods run on the request's single processing goroutine.
type Capture struct {
	engine                      *Engine
	destinations                []exportconfig.Destination
	content                     bool
	request, response, metadata []byte
	events                      [][]byte
	reservation                 *reservation
	duration                    time.Duration
}

// Duration is the time capture added to the request: copying public content
// and describing inline attachments. Event encoding and delivery come after
// the response.
func (c *Capture) Duration() *uint32 {
	if c == nil {
		return nil
	}
	value := uint32(min(max(c.duration.Microseconds(), 0), int64(^uint32(0))))
	return &value
}

// Active reports whether content is still captured, so callers can skip
// encoding output that a dropped capture or destinations without content
// would discard.
func (c *Capture) Active() bool { return c.held() && c.content }

// held reports whether the capture still owns memory for a record.
func (c *Capture) held() bool { return c != nil && c.reservation != nil }

func (c *Capture) measure(startedAt time.Time) {
	c.duration += time.Since(startedAt)
}

// record owns one finished payload shared by its destination deliveries.
// metadataParts leaves out the content of parts and shares its buffers.
type record struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	requestID            string
	size, metadataSize   int64
	mu                   sync.Mutex
	parts, metadataParts [][]byte
	reservation          *reservation
	// Guarded by Engine.mu.
	remaining int
	element   *list.Element
	reclaimed bool
}

// release erases the payload under the read lock and returns its reservation.
// Reclaim and the last delivery may both call it.
func (r *record) release() int64 {
	r.mu.Lock()
	parts := r.parts
	r.parts, r.metadataParts = nil, nil
	r.mu.Unlock()
	if parts == nil {
		return 0
	}
	for _, part := range parts {
		clear(part)
	}
	bytes := int64(r.reservation.bytes)
	r.reservation.release()
	return bytes
}

func New(ctx context.Context, options Options) *Engine {
	if options.NewLease == nil {
		panic("exporter requires shared memory admission")
	}
	e := &Engine{options: options, client: newDeliveryClient(options.Local, options.NewLease)}
	e.ctx, e.cancel = context.WithCancel(ctx)
	return e
}

// Start returns nil only when no export applies. A capture dropped here still
// marks the request record as exported, so receivers can find the records that
// never arrived.
func (e *Engine) Start(config *exportconfig.Config) *Capture {
	if e == nil || config == nil || len(config.Destinations) == 0 {
		return nil
	}
	dropped := &Capture{engine: e}
	e.mu.Lock()
	closed := e.closed || e.ctx.Err() != nil
	e.mu.Unlock()
	if closed {
		e.failed.Add(uint64(len(config.Destinations)))
		return dropped
	}
	r := &reservation{engine: e, lease: e.options.NewLease()}
	// The measured per-destination state includes the capture and record.
	size := 0
	for _, d := range config.Destinations {
		size += len(d.URL) + deliveryStateBytes
		for key, value := range d.Headers {
			size += len(key) + len(value)
		}
	}
	if !r.grow(size) {
		r.release()
		e.memoryDropped.Add(uint64(len(config.Destinations)))
		return dropped
	}
	c := &Capture{engine: e, reservation: r}
	for _, d := range config.Destinations {
		copy := exportconfig.Destination{URL: strings.Clone(d.URL), Headers: make(map[string]string, len(d.Headers)), Content: d.Content}
		for key, value := range d.Headers {
			copy.Headers[strings.Clone(key)] = strings.Clone(value)
		}
		c.destinations = append(c.destinations, copy)
		c.content = c.content || d.SendsContent()
	}
	return c
}
func (c *Capture) Discard() {
	if !c.held() {
		return
	}
	clear(c.request)
	clear(c.response)
	clear(c.metadata)
	for _, event := range c.events {
		clear(event)
	}
	c.request, c.response, c.metadata, c.events, c.destinations = nil, nil, nil, nil, nil
	c.reservation.release()
	c.reservation = nil
}
func (c *Capture) grow(n int) bool {
	if !c.held() {
		return false
	}
	if c.reservation.grow(n) {
		return true
	}
	c.engine.memoryDropped.Add(uint64(len(c.destinations)))
	c.Discard()
	return false
}

// Finish appends captured content to the canonical event. A captured signed
// metadata object wins over the unsigned final metadata, preserving its signature.
func (c *Capture) Finish(requestID string, event any, finalMetadata any) {
	if !c.held() {
		return
	}
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded) < 2 || encoded[0] != '{' {
		c.engine.failed.Add(uint64(len(c.destinations)))
		c.Discard()
		return
	}
	if c.metadata == nil {
		metadata, err := json.Marshal(finalMetadata)
		if err != nil {
			c.engine.failed.Add(uint64(len(c.destinations)))
			c.Discard()
			clear(encoded)
			return
		}
		c.Metadata(metadata)
		clear(metadata)
	}
	// Parts retain the original JSON buffers without copying the whole body.
	capacity := len(c.events)*2 + 10
	if !c.grow(len(encoded) + (capacity+4)*24) {
		clear(encoded)
		return
	}
	parts := make([][]byte, 0, capacity)
	parts = append(parts, encoded[:len(encoded)-1], []byte(`,"stogas":`), c.metadata)
	metadataParts := append(parts[:len(parts):len(parts)], []byte{'}'})
	if c.content {
		parts = append(parts, []byte(`,"request":`), c.request)
		if len(c.request) == 0 {
			parts[len(parts)-1] = []byte(`null`)
		}
		if c.events != nil {
			parts = append(parts, []byte(`,"events":[`))
			for i, event := range c.events {
				if i > 0 {
					parts = append(parts, []byte{','})
				}
				parts = append(parts, event)
			}
			parts = append(parts, []byte{']'})
		} else {
			parts = append(parts, []byte(`,"response":`), c.response)
			if len(c.response) == 0 {
				parts[len(parts)-1] = []byte(`null`)
			}
		}
	}
	parts = append(parts, []byte{'}'})
	r := &record{requestID: requestID, parts: parts, metadataParts: metadataParts, reservation: c.reservation, remaining: len(c.destinations)}
	for _, part := range parts {
		r.size += int64(len(part))
	}
	for _, part := range metadataParts {
		r.metadataSize += int64(len(part))
	}
	destinations := c.destinations
	c.request, c.response, c.metadata, c.events, c.destinations, c.reservation = nil, nil, nil, nil, nil, nil
	c.engine.start(r, destinations)
}

func (e *Engine) start(r *record, destinations []exportconfig.Destination) {
	r.ctx, r.cancel = context.WithTimeout(e.ctx, deliveryWindow)
	e.mu.Lock()
	if e.closed || e.ctx.Err() != nil {
		e.mu.Unlock()
		e.failed.Add(uint64(len(destinations)))
		r.cancel()
		r.release()
		return
	}
	r.element = e.records.PushBack(r)
	e.pending.Add(int64(len(destinations)))
	e.deliveries.Add(len(destinations))
	e.mu.Unlock()
	for _, d := range destinations {
		go e.deliver(r, d)
	}
}

func (e *Engine) deliver(r *record, d exportconfig.Destination) {
	var result attempt
	defer func() { e.finishDelivery(r, result) }()
	for attempts := 1; ; attempts++ {
		result = e.client.send(r.ctx, d, r)
		if result.delivered || !result.retryable || attempts == maxAttempts {
			return
		}
		delay := retryDelay/2 + rand.N(retryDelay)
		if result.retryAfter != nil {
			delay = *result.retryAfter
		}
		if deadline, _ := r.ctx.Deadline(); time.Until(deadline) <= delay {
			return
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
			e.retried.Add(1)
		case <-r.ctx.Done():
			timer.Stop()
			return
		}
	}
}

func (e *Engine) finishDelivery(r *record, result attempt) {
	e.mu.Lock()
	switch {
	case result.delivered:
		e.delivered.Add(1)
	case r.reclaimed || result.memoryDropped:
		e.memoryDropped.Add(1)
	default:
		e.failed.Add(1)
	}
	r.remaining--
	last := r.remaining == 0
	if last && r.element != nil {
		e.records.Remove(r.element)
		r.element = nil
	}
	e.mu.Unlock()
	if last {
		r.cancel()
		r.release()
	}
	e.pending.Add(-1)
	e.deliveries.Done()
}

// Reclaim ends delivery of the oldest finished records until needed bytes are
// free. Captures for active requests stay with those requests.
func (e *Engine) Reclaim(needed int64) int64 {
	if e == nil {
		return 0
	}
	var reclaimed []*record
	var selected int64
	e.mu.Lock()
	for selected < needed && e.records.Len() > 0 {
		r := e.records.Remove(e.records.Front()).(*record)
		r.element, r.reclaimed = nil, true
		selected += int64(r.reservation.bytes)
		reclaimed = append(reclaimed, r)
	}
	e.mu.Unlock()
	var freed int64
	for _, r := range reclaimed {
		r.cancel()
		freed += r.release()
	}
	return freed
}

func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	drained := make(chan struct{})
	go func() { e.deliveries.Wait(); close(drained) }()
	timer := time.AfterFunc(shutdownDrain, e.cancel)
	<-drained
	timer.Stop()
	e.cancel()
	e.client.close()
}
func (e *Engine) Diagnostics() Diagnostics {
	if e == nil {
		return Diagnostics{}
	}
	return Diagnostics{ReservedBytes: e.bytes.Load(), PendingDeliveries: e.pending.Load(), Delivered: e.delivered.Load(), Retried: e.retried.Load(), Failed: e.failed.Load(), MemoryDropped: e.memoryDropped.Load()}
}
