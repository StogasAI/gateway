package stogashttp

import (
	"container/list"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// A client that stops reading keeps its request's handler, headers and HTTP/2
// stream for the whole write deadline; a client that stops sending also keeps
// its body reservation for the whole read deadline. Memory pressure ends such
// requests unless they deliver paid inference output: organization limits
// bound that output, and its client has paid for it. Uploads are never paid.
type waitingClients struct {
	mu      sync.Mutex
	writes  list.List
	uploads []*publicResponse
	ended   uint64
}

// Pressure compares this many uploads chosen at random, as Redis samples keys
// for eviction, so ending one costs the same at any upload count.
const uploadSamples = 16

// A new request counts as having received about one round trip of data, so it
// is not taken for a stalled upload before its first bytes arrive.
const uploadCredit = 16 << 10

// publicResponse holds a public request's memory charge until its handler
// returns and records each unpaid write or body read while it may wait on the
// client.
type publicResponse struct {
	http.ResponseWriter
	control *http.ResponseController
	waiting *waitingClients
	memory  *requestMemoryAdmission
	// While the request waits on its body, ctx.memory holds the body
	// reservation, and nothing else changes it.
	ctx       *requestContext
	write     *list.Element // guarded by waiting.mu
	upload    int           // index in waiting.uploads or -1; guarded by waiting.mu
	received  atomic.Int64
	paid      atomic.Bool
	released  atomic.Bool
	unflushed bool
}

type publicBody struct {
	io.ReadCloser
	response *publicResponse
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
		response := &publicResponse{ResponseWriter: ctx.writer, control: control, waiting: &s.waitingClients, memory: s.memory, ctx: ctx, upload: -1}
		defer response.release()
		ctx.writer, ctx.response = response, response
		if ctx.request.Body != http.NoBody {
			ctx.request.Body = &publicBody{ReadCloser: ctx.request.Body, response: response}
		}
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
	defer r.doneWrite(r.waitWrite())
	n, err := r.ResponseWriter.Write(data)
	if n > 0 {
		r.unflushed = true
	}
	return n, err
}

func (r *publicResponse) FlushError() error {
	defer r.doneWrite(r.waitWrite())
	r.unflushed = false
	return r.control.Flush()
}

func (r *publicResponse) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// A paid response is never ended, and an ended one has no charge left to free.
func (r *publicResponse) waitWrite() bool {
	if r.paid.Load() || r.released.Load() {
		return false
	}
	r.waiting.mu.Lock()
	r.write = r.waiting.writes.PushBack(r)
	r.waiting.mu.Unlock()
	return true
}

func (r *publicResponse) doneWrite(waited bool) {
	if !waited {
		return
	}
	r.waiting.mu.Lock()
	if r.write != nil {
		r.waiting.writes.Remove(r.write)
		r.write = nil
	}
	r.waiting.mu.Unlock()
}

func (b *publicBody) Read(data []byte) (int, error) {
	waited := b.response.waitUpload()
	n, err := b.ReadCloser.Read(data)
	b.response.received.Add(int64(n))
	if b.response.doneUpload(waited) {
		return 0, errRequestMemoryCapacity
	}
	return n, err
}

func (r *publicResponse) waitUpload() bool {
	if r.paid.Load() || r.released.Load() {
		return false
	}
	r.waiting.mu.Lock()
	r.upload = len(r.waiting.uploads)
	r.waiting.uploads = append(r.waiting.uploads, r)
	r.waiting.mu.Unlock()
	return true
}

// doneUpload reports whether memory pressure ended the upload during the read.
func (r *publicResponse) doneUpload(waited bool) bool {
	if !waited {
		return false
	}
	r.waiting.mu.Lock()
	defer r.waiting.mu.Unlock()
	if r.upload < 0 {
		return true
	}
	r.waiting.removeUpload(r)
	return false
}

func (w *waitingClients) removeUpload(r *publicResponse) {
	last := len(w.uploads) - 1
	w.uploads[r.upload] = w.uploads[last]
	w.uploads[r.upload].upload = r.upload
	w.uploads[last] = nil
	w.uploads = w.uploads[:last]
	r.upload = -1
}

func (r *publicResponse) release() int64 {
	if !r.released.CompareAndSwap(false, true) {
		return 0
	}
	r.memory.release(requestLifetimeMemory, requestRetainedBytes)
	return requestRetainedBytes
}

// reclaimWrite ends the unpaid write that has waited longest on its client and
// returns the request charge it released.
func (w *waitingClients) reclaimWrite() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	item := w.writes.Front()
	if item == nil {
		return 0
	}
	response := w.writes.Remove(item).(*publicResponse)
	response.write = nil
	w.ended++
	// The handler cannot leave this write before doneWrite takes the lock, so
	// the deadline ends this response and not a later one on the same stream.
	_ = response.control.SetWriteDeadline(time.Now())
	return response.release()
}

// reclaimUpload ends the waiting upload that has received the least per second
// since its request started and returns the request and body charges it
// released. A client that sends just enough to look busy must keep sending
// faster than the uploads it would displace.
func (w *waitingClients) reclaimUpload() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.uploads) == 0 {
		return 0
	}
	now := time.Now()
	var slowest *publicResponse
	var slowestRate float64
	for i := range min(len(w.uploads), uploadSamples) {
		candidate := w.uploads[i]
		if len(w.uploads) > uploadSamples {
			candidate = w.uploads[rand.IntN(len(w.uploads))]
		}
		rate := float64(candidate.received.Load()+uploadCredit) / float64(now.Sub(candidate.ctx.startedAt))
		if slowest == nil || rate < slowestRate {
			slowest, slowestRate = candidate, rate
		}
	}
	w.removeUpload(slowest)
	w.ended++
	// The handler cannot leave this read before doneUpload takes the lock, so
	// the deadline ends this upload and not a later request on the socket.
	_ = slowest.control.SetReadDeadline(now)
	return slowest.release() + slowest.ctx.memory.reclaim()
}
