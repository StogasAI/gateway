package stogashttp

import (
	"container/list"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// A client that stops reading keeps its request's handler, headers and HTTP/2
// stream for the whole write deadline. Memory pressure ends such responses,
// oldest first, unless they deliver paid inference output: organization limits
// bound that output, and its client has paid for it.
type waitingResponses struct {
	mu     sync.Mutex
	oldest list.List
	reset  uint64
}

// publicResponse holds a public request's memory charge until its handler
// returns and records each unpaid write while it may wait on the client.
type publicResponse struct {
	http.ResponseWriter
	control   *http.ResponseController
	waiting   *waitingResponses
	memory    *requestMemoryAdmission
	item      *list.Element // guarded by waiting.mu
	paid      atomic.Bool
	released  atomic.Bool
	unflushed bool
}

// publicRequests charges each public request until its handler returns and
// keeps memory pressure from closing its socket meanwhile.
func (s *Server) publicRequests(next requestHandler) requestHandler {
	if s.memory == nil {
		s.memory = newRequestMemoryAdmission()
	}
	return func(ctx *requestContext) {
		s.idleConnections.busy(ctx.request.Context())
		control := http.NewResponseController(ctx.writer)
		if ctx.request.ProtoMajor < 2 {
			// net/http ends an HTTP/1 response after its handler returns. Bound
			// that write, and clear the bound the previous response set.
			_ = control.SetWriteDeadline(time.Time{})
			defer func() { _ = control.SetWriteDeadline(time.Now().Add(downstreamWriteIdleTimeout)) }()
		}
		if !s.memory.reserve(requestLifetimeMemory, requestRetainedBytes) {
			closeUnreadRequest(ctx)
			s.writeRequestMemoryCapacity(ctx)
			return
		}
		response := &publicResponse{ResponseWriter: ctx.writer, control: control, waiting: &s.waitingResponses, memory: s.memory}
		defer response.release()
		ctx.writer, ctx.response = response, response
		next(ctx)
		if response.unflushed {
			// Deliver buffered bytes while the request is charged and its write
			// can still be ended.
			_ = response.FlushError()
		}
	}
}

// markPaid keeps memory pressure from ending the response once a billing hold
// pays for its output.
func (ctx *requestContext) markPaid() {
	if ctx.response != nil {
		ctx.response.paid.Store(true)
	}
}

func (r *publicResponse) Write(data []byte) (int, error) {
	defer r.done(r.wait())
	n, err := r.ResponseWriter.Write(data)
	if n > 0 {
		r.unflushed = true
	}
	return n, err
}

func (r *publicResponse) FlushError() error {
	defer r.done(r.wait())
	r.unflushed = false
	return r.control.Flush()
}

func (r *publicResponse) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *publicResponse) wait() bool {
	if r.paid.Load() {
		return false
	}
	r.waiting.mu.Lock()
	r.item = r.waiting.oldest.PushBack(r)
	r.waiting.mu.Unlock()
	return true
}

func (r *publicResponse) done(waited bool) {
	if !waited {
		return
	}
	r.waiting.mu.Lock()
	if r.item != nil {
		r.waiting.oldest.Remove(r.item)
		r.item = nil
	}
	r.waiting.mu.Unlock()
}

func (r *publicResponse) release() int64 {
	if !r.released.CompareAndSwap(false, true) {
		return 0
	}
	r.memory.release(requestLifetimeMemory, requestRetainedBytes)
	return requestRetainedBytes
}

// reclaim ends the unpaid write that has waited longest on its client and
// returns the request charge it released.
func (w *waitingResponses) reclaim() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	item := w.oldest.Front()
	if item == nil {
		return 0
	}
	response := w.oldest.Remove(item).(*publicResponse)
	response.item = nil
	w.reset++
	// The handler cannot leave this write before done takes the lock, so the
	// deadline ends this response and not a later one on the same stream.
	_ = response.control.SetWriteDeadline(time.Now())
	return response.release()
}
