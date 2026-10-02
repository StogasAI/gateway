package stogashttp

import (
	"context"
	"io"
	"sync"
)

// One producer hands bounded frames to one response consumer. Closing the
// consumer does not release bytes still held by a producer that is stopping.
type sseStreamEvent struct {
	data     []byte
	reserved int
}

type sseStreamReader struct {
	eventCh        chan sseStreamEvent
	closeCh        chan struct{}
	closeOnce      sync.Once
	doneOnce       sync.Once
	deliveryMemory *requestMemoryLease
	readMu         sync.Mutex
	consumerDone   bool
	producerDone   bool
	current        sseStreamEvent
}

func newSSEStreamReader(deliveryMemory *requestMemoryLease) *sseStreamReader {
	return &sseStreamReader{
		eventCh:        make(chan sseStreamEvent, 1),
		closeCh:        make(chan struct{}),
		deliveryMemory: deliveryMemory,
	}
}

func (r *sseStreamReader) Read(p []byte) (int, error) {
	r.readMu.Lock()
	defer r.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.current.data) == 0 {
		select {
		case <-r.closeCh:
			r.finishConsumer()
			return 0, io.EOF
		default:
		}
		var (
			event sseStreamEvent
			ok    bool
		)
		select {
		case event, ok = <-r.eventCh:
		case <-r.closeCh:
			r.finishConsumer()
			return 0, io.EOF
		}
		if !ok {
			r.finishConsumer()
			return 0, io.EOF
		}
		r.current = event
	}
	n := copy(p, r.current.data)
	clear(r.current.data[:n])
	r.current.data = r.current.data[n:]
	if len(r.current.data) == 0 {
		r.releaseEvent(r.current)
		r.current = sseStreamEvent{}
	}
	return n, nil
}

func (r *sseStreamReader) Close() error {
	r.closeOnce.Do(func() {
		close(r.closeCh)
	})
	r.readMu.Lock()
	defer r.readMu.Unlock()
	r.finishConsumer()
	return nil
}

func (r *sseStreamReader) closed() <-chan struct{} {
	return r.closeCh
}

func (r *sseStreamReader) sendErrorEvent(ctx context.Context, eventType string, data []byte) bool {
	event := frameSSEEvent(eventType, data)
	// Keep one bounded gateway error deliverable when data admission is full.
	// The one-item reader queue still bounds this control frame.
	if ctx.Err() != nil {
		sent, capacityExceeded := r.trySend(event)
		if !sent && capacityExceeded {
			sent = r.trySendUnreserved(event)
		}
		return sent
	}
	sent, capacityExceeded := r.send(ctx, event)
	if !sent && capacityExceeded {
		sent = r.sendUnreserved(ctx, event)
	}
	return sent
}

func frameSSEEvent(eventType string, data []byte) []byte {
	var event []byte
	if eventType == "" {
		event = make([]byte, 0, 6+len(data)+2)
		event = append(event, "data: "...)
	} else {
		event = make([]byte, 0, 7+len(eventType)+7+len(data)+2)
		event = append(event, "event: "...)
		event = append(event, eventType...)
		event = append(event, "\ndata: "...)
	}
	event = append(event, data...)
	event = append(event, '\n', '\n')
	return event
}

func frameSSEComment(comment string) []byte {
	event := make([]byte, 0, 2+len(comment)+2)
	event = append(event, ':', ' ')
	event = append(event, comment...)
	event = append(event, '\n', '\n')
	return event
}

func (r *sseStreamReader) sendDone(ctx context.Context) bool {
	sent, _ := r.send(ctx, frameSSEDone())
	return sent
}

func frameSSEDone() []byte {
	return []byte("data: [DONE]\n\n")
}

// Send operations transfer ownership of the frame, or clear it on rejection.
// Capacity rejection alone leaves ownership with the caller for error fallback.
func (r *sseStreamReader) send(ctx context.Context, event []byte) (sent, capacityExceeded bool) {
	select {
	case <-r.closeCh:
		clear(event)
		return false, false
	case <-ctx.Done():
		clear(event)
		return false, false
	default:
	}
	queued, ok := r.reserveEvent(event)
	if !ok {
		return false, true
	}
	select {
	case r.eventCh <- queued:
		return true, false
	case <-r.closeCh:
		r.releaseEvent(queued)
		return false, false
	case <-ctx.Done():
		r.releaseEvent(queued)
		return false, false
	}
}

func (r *sseStreamReader) trySend(event []byte) (sent, capacityExceeded bool) {
	select {
	case <-r.closeCh:
		clear(event)
		return false, false
	default:
	}
	queued, ok := r.reserveEvent(event)
	if !ok {
		return false, true
	}
	select {
	case r.eventCh <- queued:
		return true, false
	case <-r.closeCh:
		r.releaseEvent(queued)
		return false, false
	default:
		r.releaseEvent(queued)
		return false, false
	}
}

func (r *sseStreamReader) sendUnreserved(ctx context.Context, data []byte) bool {
	select {
	case r.eventCh <- sseStreamEvent{data: data}:
		return true
	case <-r.closeCh:
		clear(data)
		return false
	case <-ctx.Done():
		clear(data)
		return false
	}
}

func (r *sseStreamReader) trySendUnreserved(data []byte) bool {
	select {
	case r.eventCh <- sseStreamEvent{data: data}:
		return true
	case <-r.closeCh:
		clear(data)
		return false
	default:
		clear(data)
		return false
	}
}

func (r *sseStreamReader) reserveEvent(data []byte) (sseStreamEvent, bool) {
	event := sseStreamEvent{data: data}
	if r.deliveryMemory == nil || len(data) == 0 {
		return event, true
	}
	if !r.deliveryMemory.grow(len(data)) {
		return sseStreamEvent{}, false
	}
	event.reserved = len(data)
	return event, true
}

func (r *sseStreamReader) releaseEvent(event sseStreamEvent) {
	clear(event.data)
	if r.deliveryMemory != nil {
		r.deliveryMemory.shrink(event.reserved)
	}
}

func (r *sseStreamReader) done() {
	r.doneOnce.Do(func() {
		close(r.eventCh)
		r.readMu.Lock()
		defer r.readMu.Unlock()
		r.producerDone = true
		if r.consumerDone {
			r.finishConsumer()
		}
	})
}

// Called with readMu held. A sender racing Close can still enqueue a frame;
// done repeats this cleanup after the last sender has returned.
func (r *sseStreamReader) finishConsumer() {
	r.consumerDone = true
	r.releaseEvent(r.current)
	r.current = sseStreamEvent{}
	for {
		select {
		case event, ok := <-r.eventCh:
			if ok {
				r.releaseEvent(event)
				continue
			}
		default:
		}
		break
	}
	if r.producerDone && r.deliveryMemory != nil {
		r.deliveryMemory.release()
	}
}

// Keep the frame's lease until Write (including its flush) has returned.
// io.Copy uses this method without allocating another copy buffer.
func (r *sseStreamReader) WriteTo(writer io.Writer) (int64, error) {
	r.readMu.Lock()
	defer r.readMu.Unlock()
	defer r.finishConsumer()
	var total int64
	for {
		if len(r.current.data) == 0 {
			select {
			case <-r.closeCh:
				return total, nil
			case event, ok := <-r.eventCh:
				if !ok {
					return total, nil
				}
				r.current = event
			}
		}
		event := r.current
		n, err := writer.Write(event.data)
		total += int64(n)
		r.releaseEvent(event)
		r.current = sseStreamEvent{}
		if err != nil {
			return total, err
		}
		if n != len(event.data) {
			return total, io.ErrShortWrite
		}
	}
}
