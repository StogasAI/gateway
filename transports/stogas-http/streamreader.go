package stogashttp

import (
	"io"
	"sync"
)

// sseStreamReader feeds pre-framed SSE events directly to fasthttp SetBodyStream
// without routing through a writer-to-reader pipe bridge.
type sseStreamReader struct {
	eventCh   chan []byte
	closeCh   chan struct{}
	closeOnce sync.Once
	current   []byte
}

func newSSEStreamReader() *sseStreamReader {
	return &sseStreamReader{
		eventCh: make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
}

func (r *sseStreamReader) Read(p []byte) (int, error) {
	if len(r.current) == 0 {
		event, ok := <-r.eventCh
		if !ok {
			return 0, io.EOF
		}
		r.current = event
	}
	n := copy(p, r.current)
	r.current = r.current[n:]
	return n, nil
}

func (r *sseStreamReader) Close() error {
	r.closeOnce.Do(func() {
		close(r.closeCh)
	})
	return nil
}

func (r *sseStreamReader) closed() <-chan struct{} {
	return r.closeCh
}

func (r *sseStreamReader) sendEvent(eventType string, data []byte) bool {
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
	return r.send(event)
}

func (r *sseStreamReader) sendDone() bool {
	return r.send([]byte("data: [DONE]\n\n"))
}

func (r *sseStreamReader) send(event []byte) bool {
	select {
	case <-r.closeCh:
		return false
	default:
	}
	select {
	case r.eventCh <- event:
		return true
	case <-r.closeCh:
		return false
	}
}

func (r *sseStreamReader) done() {
	close(r.eventCh)
}
