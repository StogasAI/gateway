package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	requestLogBatchWindow        = 50 * time.Millisecond
	requestLogMinRequestInterval = 250 * time.Millisecond
	requestLogMaxEventBytes      = 64 * 1024
	requestLogMaxBatchBytes      = 1024 * 1024
	requestLogMaxBatchRows       = 4096
	requestLogQueueCapacity      = 2048
	requestLogAppendTimeout      = 10 * time.Second
	// A batch can try the queue and then Tinybird; each has its own deadline.
	requestLogAppendWaitTimeout   = 2*requestLogAppendTimeout + time.Second
	requestLogCircuitOpenDuration = 30 * time.Second
)

type LogDestination uint8

const (
	LogNotStored LogDestination = iota
	LogQueue
	LogTinybird
)

type logDelivery struct {
	destination LogDestination
	err         error
}
type requestLogAppendRequest struct {
	line   []byte
	result chan logDelivery
}

// RequestLogConfig sends immutable final records to the durable queue first.
// Tinybird is the independently authenticated fallback when queue delivery fails.
type RequestLogConfig struct {
	QueueURL                    string
	QueueToken                  string
	AccessClientID              string
	AccessClientSecret          string
	TinybirdHost                string
	TinybirdToken               string
	AllowInsecurePrivateNetwork bool
}

type RequestLogClient struct {
	primary            *requestLogSink
	fallback           *requestLogSink
	batchWindow        time.Duration
	minRequestInterval time.Duration
	maxBatchBytes      int
	maxBatchRows       int
	queue              chan requestLogAppendRequest
	stop               chan struct{}
	startOnce          sync.Once
	workerWG           sync.WaitGroup
	mu                 sync.RWMutex
	closed             bool
	batches            atomic.Uint64
	batchFailures      atomic.Uint64
	rows               atomic.Uint64
}

type RequestLogDiagnostics struct {
	BatchFailures uint64                     `json:"batchFailures"`
	Batches       uint64                     `json:"batches"`
	Closed        bool                       `json:"closed"`
	QueueCapacity int                        `json:"queueCapacity"`
	QueueDepth    int                        `json:"queueDepth"`
	Rows          uint64                     `json:"rows"`
	Primary       *RequestLogSinkDiagnostics `json:"primary,omitempty"`
	Fallback      *RequestLogSinkDiagnostics `json:"fallback,omitempty"`
}

// The private hold binding travels with the canonical event. It is excluded
// from customer history and is required before recovery can apply a charge.
type requestLogRecord struct {
	RequestEvent
	HoldParamsHash string `json:"hold_params_hash"`
}

func NewRequestLogClient(config RequestLogConfig) (*RequestLogClient, error) {
	primary, err := newRequestLogSink(config.QueueURL, config.QueueToken, config.AllowInsecurePrivateNetwork, true)
	if err != nil {
		return nil, err
	}
	fallback, err := newRequestLogSink(config.TinybirdHost, config.TinybirdToken, config.AllowInsecurePrivateNetwork, false)
	if err != nil {
		return nil, err
	}
	if primary == nil && fallback == nil {
		return nil, nil
	}
	if primary != nil {
		primary.accessClientID = config.AccessClientID
		primary.accessClientSecret = config.AccessClientSecret
	}
	return &RequestLogClient{
		primary: primary, fallback: fallback,
		batchWindow: requestLogBatchWindow, minRequestInterval: requestLogMinRequestInterval,
		maxBatchBytes: requestLogMaxBatchBytes, maxBatchRows: requestLogMaxBatchRows,
		queue: make(chan requestLogAppendRequest, requestLogQueueCapacity), stop: make(chan struct{}),
	}, nil
}

func (c *RequestLogClient) AppendGatewayRequest(ctx context.Context, event RequestEvent) (LogDestination, error) {
	if err := ctx.Err(); err != nil {
		return LogNotStored, err
	}
	result, err := c.enqueueGatewayRequest(event)
	if err != nil {
		return LogNotStored, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, requestLogAppendWaitTimeout)
	defer cancel()
	select {
	case result := <-result:
		return result.destination, result.err
	case <-waitCtx.Done():
		return LogNotStored, fmt.Errorf("save request log: %w", waitCtx.Err())
	}
}

// Any ambiguous delivery replays the immutable batch with the same identities.
func (c *RequestLogClient) appendGatewayRequests(ctx context.Context, events []RequestEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	results := make([]<-chan logDelivery, 0, len(events))
	for _, event := range events {
		result, err := c.enqueueGatewayRequest(event)
		if err != nil {
			return err
		}
		results = append(results, result)
	}
	waitCtx, cancel := context.WithTimeout(ctx, requestLogAppendWaitTimeout)
	defer cancel()
	for _, result := range results {
		select {
		case result := <-result:
			if result.err != nil {
				return result.err
			}
		case <-waitCtx.Done():
			return waitCtx.Err()
		}
	}
	return nil
}

func (c *RequestLogClient) enqueueGatewayRequest(event RequestEvent) (<-chan logDelivery, error) {
	if c == nil {
		return nil, errors.New("request log delivery is not configured")
	}
	if event.SchemaVersion != RequestLogSchemaVersion {
		return nil, fmt.Errorf("unsupported request log schema version: %d", event.SchemaVersion)
	}
	line, err := json.Marshal(requestLogRecord{RequestEvent: event, HoldParamsHash: event.holdParamsHash})
	if err != nil {
		return nil, fmt.Errorf("marshal request log: %w", err)
	}
	line = append(line, '\n')
	if len(line) > requestLogMaxEventBytes {
		return nil, fmt.Errorf("request log is %d bytes, limit is %d", len(line), requestLogMaxEventBytes)
	}
	request := requestLogAppendRequest{line: line, result: make(chan logDelivery, 1)}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, errors.New("request log client is closed")
	}
	c.startOnce.Do(func() { c.workerWG.Add(1); go c.run() })
	select {
	case c.queue <- request:
		return request.result, nil
	default:
		return nil, errors.New("request log microbatch queue is full")
	}
}

func (c *RequestLogClient) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.stop)
	}
	c.mu.Unlock()
	c.workerWG.Wait()
	c.primary.close()
	c.fallback.close()
}

func (c *RequestLogClient) run() {
	defer c.workerWG.Done()
	var pending *requestLogAppendRequest
	var lastDispatch time.Time
	closing := false
	for {
		first, ok := c.nextBatchRequest(pending, closing)
		pending = nil
		if !ok {
			if closing {
				return
			}
			closing = true
			continue
		}
		batch, next, stopped := c.collectBatch(first, closing, lastDispatch)
		pending = next
		closing = closing || stopped
		c.waitForDispatch(lastDispatch)
		lastDispatch = time.Now()
		result := c.appendBatch(batch)
		c.batches.Add(1)
		c.rows.Add(uint64(len(batch)))
		if result.err != nil {
			c.batchFailures.Add(1)
		}
		for _, request := range batch {
			request.result <- result
		}
	}
}

func (c *RequestLogClient) appendBatch(batch []requestLogAppendRequest) logDelivery {
	var body bytes.Buffer
	for _, request := range batch {
		body.Write(request.line)
	}
	if c.primary != nil && c.primary.append(body.Bytes(), len(batch)) == nil {
		return logDelivery{destination: LogQueue}
	}
	var analytics bytes.Buffer
	for _, request := range batch {
		event, err := decodeGatewayRequestEvent(string(request.line))
		if err != nil {
			return logDelivery{err: err}
		}
		var binding struct {
			HoldParamsHash string `json:"hold_params_hash"`
		}
		if err := json.Unmarshal(request.line, &binding); err != nil {
			return logDelivery{err: err}
		}
		event.holdParamsHash = binding.HoldParamsHash
		encoded, err := json.Marshal(tinybirdGatewayRequestEvent(event))
		if err != nil {
			return logDelivery{err: err}
		}
		analytics.Write(encoded)
		analytics.WriteByte('\n')
	}
	if c.fallback == nil {
		return logDelivery{err: errors.New("durable request log queue unavailable")}
	}
	if err := c.fallback.append(analytics.Bytes(), len(batch)); err != nil {
		return logDelivery{err: err}
	}
	return logDelivery{destination: LogTinybird}
}

func (c *RequestLogClient) Diagnostics() *RequestLogDiagnostics {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	return &RequestLogDiagnostics{
		BatchFailures: c.batchFailures.Load(), Batches: c.batches.Load(), Closed: closed,
		QueueCapacity: cap(c.queue), QueueDepth: len(c.queue), Rows: c.rows.Load(),
		Primary: c.primary.diagnostics(), Fallback: c.fallback.diagnostics(),
	}
}

func (c *RequestLogClient) nextBatchRequest(pending *requestLogAppendRequest, closing bool) (requestLogAppendRequest, bool) {
	if pending != nil {
		return *pending, true
	}
	if closing {
		select {
		case appendRequest := <-c.queue:
			return appendRequest, true
		default:
			return requestLogAppendRequest{}, false
		}
	}

	select {
	case appendRequest := <-c.queue:
		return appendRequest, true
	case <-c.stop:
		return requestLogAppendRequest{}, false
	}
}

func (c *RequestLogClient) collectBatch(
	first requestLogAppendRequest,
	closing bool,
	lastDispatch time.Time,
) ([]requestLogAppendRequest, *requestLogAppendRequest, bool) {
	batch := make([]requestLogAppendRequest, 1, min(c.maxBatchRows, len(c.queue)+1))
	batch[0] = first
	batchBytes := len(first.line)

	if closing {
		batch, _, pending := c.drainBatch(batch, batchBytes)
		return batch, pending, true
	}

	flushAt := time.Now().Add(c.batchWindow)
	nextAllowed := lastDispatch.Add(c.minRequestInterval)
	if nextAllowed.After(flushAt) {
		flushAt = nextAllowed
	}
	timer := time.NewTimer(max(time.Until(flushAt), 0))
	defer timer.Stop()

	for c.batchHasCapacity(batch, batchBytes) {
		select {
		case appendRequest := <-c.queue:
			if !c.batchCanAppend(batch, batchBytes, appendRequest) {
				select {
				case <-timer.C:
					return batch, &appendRequest, false
				case <-c.stop:
					return batch, &appendRequest, true
				}
			}
			batch = append(batch, appendRequest)
			batchBytes += len(appendRequest.line)
		case <-timer.C:
			return batch, nil, false
		case <-c.stop:
			batch, _, pending := c.drainBatch(batch, batchBytes)
			return batch, pending, true
		}
	}

	select {
	case <-timer.C:
		return batch, nil, false
	case <-c.stop:
		return batch, nil, true
	}
}

func (c *RequestLogClient) drainBatch(
	batch []requestLogAppendRequest,
	batchBytes int,
) ([]requestLogAppendRequest, int, *requestLogAppendRequest) {
	for c.batchHasCapacity(batch, batchBytes) {
		select {
		case appendRequest := <-c.queue:
			if !c.batchCanAppend(batch, batchBytes, appendRequest) {
				return batch, batchBytes, &appendRequest
			}
			batch = append(batch, appendRequest)
			batchBytes += len(appendRequest.line)
		default:
			return batch, batchBytes, nil
		}
	}
	return batch, batchBytes, nil
}

func (c *RequestLogClient) batchHasCapacity(batch []requestLogAppendRequest, batchBytes int) bool {
	return len(batch) < c.maxBatchRows && batchBytes < c.maxBatchBytes
}

func (c *RequestLogClient) batchCanAppend(
	batch []requestLogAppendRequest,
	batchBytes int,
	appendRequest requestLogAppendRequest,
) bool {
	return len(batch) < c.maxBatchRows && batchBytes+len(appendRequest.line) <= c.maxBatchBytes
}

func (c *RequestLogClient) waitForDispatch(lastDispatch time.Time) {
	if lastDispatch.IsZero() {
		return
	}
	delay := time.Until(lastDispatch.Add(c.minRequestInterval))
	if delay > 0 {
		time.Sleep(delay)
	}
}
