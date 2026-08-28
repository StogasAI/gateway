package stogashttp

import (
	"context"
	"io"
	"sync"
)

// sseStreamReader feeds pre-framed SSE events directly to fasthttp SetBodyStream
// without routing through a writer-to-reader pipe bridge.
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
	if len(r.current.data) == 0 {
		select {
		case <-r.closeCh:
			r.markConsumerDone()
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
			r.markConsumerDone()
			return 0, io.EOF
		}
		if !ok {
			r.markConsumerDone()
			return 0, io.EOF
		}
		r.current = event
	}
	n := copy(p, r.current.data)
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
	r.markConsumerDone()
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

func (r *sseStreamReader) send(ctx context.Context, event []byte) (sent, capacityExceeded bool) {
	select {
	case <-r.closeCh:
		return false, false
	case <-ctx.Done():
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
		return false
	case <-ctx.Done():
		return false
	}
}

func (r *sseStreamReader) trySendUnreserved(data []byte) bool {
	select {
	case r.eventCh <- sseStreamEvent{data: data}:
		return true
	case <-r.closeCh:
		return false
	default:
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
	if r.deliveryMemory != nil {
		r.deliveryMemory.shrink(event.reserved)
	}
}

func (r *sseStreamReader) done() {
	r.doneOnce.Do(func() {
		close(r.eventCh)
	})
}

func (r *sseStreamReader) markConsumerDone() {
	if r.deliveryMemory != nil {
		r.deliveryMemory.release()
	}
}
