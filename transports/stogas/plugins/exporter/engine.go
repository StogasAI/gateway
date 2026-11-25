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

// destination is one receiver of a capture, with the request's sample position
// for it. take decides whether it gets bodies, once the outcome is known.
type destination struct {
	exportconfig.Destination
	position float64
	content  bool
}

// form is the shape of a record that a destination takes: its format, with or
// without bodies. Each trace form follows a version of the GenAI conventions.
type form int

const (
	formJSON form = iota
	formJSONContent
	formTrace141
	formTrace141Content
	formTrace01
	formTrace01Content
	forms
)

func (d destination) form() form {
	f := formJSON
	switch d.Format {
	case exportconfig.FormatOTLPGenAI141:
		f = formTrace141
	case exportconfig.FormatOTLPGenAI01:
		f = formTrace01
	}
	if d.content {
		f++
	}
	return f
}

// trace reports the conventions of a trace form, and whether it holds bodies.
func (f form) trace() (conventions, bool) {
	if f >= formTrace01 {
		return conventions01, f == formTrace01Content
	}
	return conventions141, f == formTrace141Content
}

// Trace is what a trace export needs and the request record does not hold:
// the model that the request named, and the caller's trace and span from its
// traceparent header, both empty without one.
type Trace struct {
	Model, TraceID, ParentSpanID string
}

// Capture owns detached public JSON until Finish transfers it to delivery.
// Its methods run on the request's single processing goroutine.
type Capture struct {
	engine       *Engine
	destinations []destination
	// The outcomes whose record a destination gets, in the order of
	// exportconfig.Outcomes. It outlives a dropped capture.
	due                         [len(exportconfig.Outcomes)]bool
	content                     bool
	trace                       Trace
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

// payload is a record in one form, as parts that a delivery sends in order.
type payload struct {
	parts [][]byte
	size  int64
}

// record owns one finished record, in each form that its destination
// deliveries take. The JSON form without bodies shares the buffers of the
// form with them.
type record struct {
	ctx         context.Context
	cancel      context.CancelFunc
	requestID   string
	mu          sync.Mutex
	payloads    [forms]payload
	released    bool
	reservation *reservation
	// Guarded by Engine.mu.
	remaining int
	element   *list.Element
	reclaimed bool
}

// release erases the payload under the read lock and returns its reservation.
// Reclaim calls it for a record it takes, and the last delivery for any other.
func (r *record) release() int64 {
	r.mu.Lock()
	released, payloads := r.released, r.payloads
	r.released, r.payloads = true, [forms]payload{}
	r.mu.Unlock()
	if released {
		return 0
	}
	for _, payload := range payloads {
		for _, part := range payload.parts {
			clear(part)
		}
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

// Start returns nil only when no export applies: no destination, or none whose
// sample reaches this request however it ends. Such a request copies nothing. A
// capture dropped here still marks the request record as exported, so receivers
// can find the records that never arrived. sessionID is empty for a request
// that names no session.
func (e *Engine) Start(config *exportconfig.Config, requestID, sessionID string, trace Trace) *Capture {
	if e == nil || config == nil || len(config.Destinations) == 0 {
		return nil
	}
	dropped := &Capture{engine: e}
	// The measured per-destination state includes the capture and record.
	size, reached := 0, 0
	for _, d := range config.Destinations {
		position := d.Position(requestID, sessionID)
		if position >= d.Reach() {
			continue
		}
		reached++
		for i, outcome := range exportconfig.Outcomes {
			dropped.due[i] = dropped.due[i] || position < d.Rate(outcome)
		}
		size += len(d.URL) + deliveryStateBytes
		for key, value := range d.Headers {
			size += len(key) + len(value)
		}
	}
	if reached == 0 {
		return nil
	}
	e.mu.Lock()
	closed := e.closed || e.ctx.Err() != nil
	e.mu.Unlock()
	if closed {
		e.failed.Add(uint64(reached))
		return dropped
	}
	r := &reservation{engine: e, lease: e.options.NewLease()}
	if !r.grow(size) {
		r.release()
		e.memoryDropped.Add(uint64(reached))
		return dropped
	}
	c := &Capture{engine: e, due: dropped.due, trace: trace, reservation: r}
	for _, d := range config.Destinations {
		position := d.Position(requestID, sessionID)
		if position >= d.Reach() {
			continue
		}
		copy := exportconfig.Destination{URL: strings.Clone(d.URL), Headers: make(map[string]string, len(d.Headers)), Format: d.Format, SampleBy: d.SampleBy}
		for key, value := range d.Headers {
			copy.Headers[strings.Clone(key)] = strings.Clone(value)
		}
		if d.Sample != nil {
			sample := *d.Sample
			copy.Sample = &sample
		}
		if d.Content != nil {
			content := *d.Content
			copy.Content = &content
		}
		c.destinations = append(c.destinations, destination{Destination: copy, position: position})
		// Bodies are copied only for a request that can send them.
		c.content = c.content || position < d.ContentReach()
	}
	return c
}

// Due reports whether a destination gets the record of a request that ended
// with this outcome. It holds for a dropped capture too, whose record was due
// and did not leave.
func (c *Capture) Due(outcome string) bool {
	if c == nil {
		return false
	}
	for i, name := range exportconfig.Outcomes {
		if name == outcome {
			return c.due[i]
		}
	}
	return false
}

// take keeps the destinations that get this outcome's record, decides which
// of them get its bodies, and reports whether one is left. A receiver that two
// destinations name, one sampling by request and one by session, gets the
// record once, with bodies if either sends them. The capture's content stays
// as captured.
func (c *Capture) take(outcome string) bool {
	due := c.destinations[:0]
next:
	for _, d := range c.destinations {
		if d.position >= d.Rate(outcome) {
			continue
		}
		d.content = d.position < d.ContentRate(outcome)
		for i := range due {
			if due[i].SampleBy != d.SampleBy && due[i].SameReceiver(d.Destination) {
				due[i].content = due[i].content || d.content
				continue next
			}
		}
		due = append(due, d)
	}
	clear(c.destinations[len(due):])
	c.destinations = due
	return len(due) > 0
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

// Held is an export kept for a record that is not complete yet. It keeps the
// capture's destinations and response, and memory admission for those bytes
// alone: delivery state is admitted again when it leaves.
type Held struct {
	engine       *Engine
	destinations []destination
	content      bool
	trace        Trace
	response     []byte
	reservation  *reservation
}

// Hold ends the capture and keeps its export for Held.Finish. It returns nil
// when the capture holds nothing or admission refuses the bytes it keeps.
func (c *Capture) Hold() *Held {
	if !c.held() {
		return nil
	}
	h := &Held{engine: c.engine, destinations: c.destinations, content: c.content, trace: c.trace, response: c.response}
	c.destinations, c.response = nil, nil
	c.Discard()
	size := len(h.response)
	for _, d := range h.destinations {
		size += len(d.URL)
		for key, value := range d.Headers {
			size += len(key) + len(value)
		}
	}
	h.reservation = &reservation{engine: h.engine, lease: h.engine.options.NewLease()}
	if !h.reservation.grow(size) {
		h.engine.memoryDropped.Add(uint64(len(h.destinations)))
		h.Discard()
		return nil
	}
	return h
}

// Finish sends the export with the record, as Capture.Finish does.
func (h *Held) Finish(requestID, outcome string, event any) {
	if h == nil || h.reservation == nil {
		return
	}
	c := &Capture{engine: h.engine, destinations: h.destinations, content: h.content, trace: h.trace, response: h.response, reservation: h.reservation}
	h.destinations, h.response, h.reservation = nil, nil, nil
	if !c.take(outcome) {
		c.Discard()
		return
	}
	if c.grow(len(c.destinations) * deliveryStateBytes) {
		c.finish(requestID, event)
	}
}

func (h *Held) Discard() {
	if h == nil || h.reservation == nil {
		return
	}
	clear(h.response)
	h.destinations, h.response = nil, nil
	h.reservation.release()
	h.reservation = nil
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

// Finish sends the record to the destinations that get this outcome's, and
// appends captured content to the canonical event. The signed metadata of a
// response that carried a receipt goes with it as the client received it; any
// other record needs none, because the metadata only repeats the record.
func (c *Capture) Finish(requestID, outcome string, event any) {
	if !c.held() {
		return
	}
	if !c.take(outcome) {
		c.Discard()
		return
	}
	c.finish(requestID, event)
}

func (c *Capture) finish(requestID string, event any) {
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded) < 2 || encoded[0] != '{' {
		c.engine.failed.Add(uint64(len(c.destinations)))
		c.Discard()
		return
	}
	// Parts retain the original JSON buffers without copying the whole body.
	capacity := len(c.events)*2 + 10
	if !c.grow(len(encoded) + (capacity+4)*24) {
		clear(encoded)
		return
	}
	parts := make([][]byte, 0, capacity)
	parts = append(parts, encoded[:len(encoded)-1])
	if c.metadata != nil {
		parts = append(parts, []byte(`,"stogas":`), c.metadata)
	}
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
	r := &record{requestID: requestID, reservation: c.reservation, remaining: len(c.destinations)}
	r.payloads[formJSON].parts, r.payloads[formJSONContent].parts = metadataParts, parts
	for _, d := range c.destinations {
		f := d.form()
		if f < formTrace141 || r.payloads[f].parts != nil {
			continue
		}
		trace, ok := c.traceForm(encoded, f)
		if !ok {
			clear(encoded)
			for _, built := range r.payloads[formTrace141:] {
				for _, part := range built.parts {
					clear(part)
				}
			}
			return
		}
		r.payloads[f].parts = [][]byte{trace}
	}
	for f := range r.payloads {
		for _, part := range r.payloads[f].parts {
			r.payloads[f].size += int64(len(part))
		}
	}
	destinations := c.destinations
	c.request, c.response, c.metadata, c.events, c.destinations, c.reservation = nil, nil, nil, nil, nil, nil
	c.engine.start(r, destinations)
}

func (e *Engine) start(r *record, destinations []destination) {
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

func (e *Engine) deliver(r *record, d destination) {
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
	// Reclaim releases the records it takes, so that it reports every byte it frees.
	release := last && !r.reclaimed
	if last && r.element != nil {
		e.records.Remove(r.element)
		r.element = nil
	}
	e.mu.Unlock()
	if last {
		r.cancel()
	}
	if release {
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
