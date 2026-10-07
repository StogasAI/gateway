package providerio

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/maximhq/bifrost/core/providers/utils"
	"github.com/valyala/fasthttp"
)

var ErrTooLarge = errors.New("provider response exceeds size limit")

// Brotli allows a 24-bit history and three groups of 256 Huffman tables. The
// pinned decoder uses at most 1,528 four-byte entries per table. Include old
// and new allocations during growth, plus its context and lookup buffers.
const BrotliDecoderReservation = 2*((1<<24)+(3*256*1528*4)) + (64 << 10)

type transport struct {
	inner     fasthttp.RoundTripper
	maximum   int64
	encrypted bool
}

// NewTransport preserves the core socket, TLS, cancellation and no-replay
// policy while reading bodies through admission before core can buffer them.
// Encrypted envelopes defer their plaintext structure charge to decryption.
func NewTransport(maximum int, encrypted bool) fasthttp.RoundTripper {
	return &transport{inner: utils.NewContextTransport(), maximum: int64(maximum), encrypted: encrypted}
}

func (t *transport) RoundTrip(hc *fasthttp.HostClient, request *fasthttp.Request, response *fasthttp.Response) (bool, error) {
	ctx := utils.RequestContext(request)
	upstream := fasthttp.AcquireResponse()
	upstream.SkipBody = response.SkipBody
	upstream.StreamBody = true
	retry, err := t.inner.RoundTrip(hc, request, upstream)
	if err != nil {
		fasthttp.ReleaseResponse(upstream)
		return retry, err
	}
	body, err := newResponseBody(ctx, upstream, t.maximum, !t.encrypted, hc.ReadTimeout)
	if err != nil {
		// newResponseBody owns upstream on both success and failure.
		return false, err
	}
	upstream.Header.CopyTo(&response.Header)
	if response.StreamBody {
		response.SetBodyStream(body, upstream.Header.ContentLength())
		return false, nil
	}
	data, err := io.ReadAll(body)
	_ = body.CloseWithError(err)
	if err != nil {
		clear(data)
		return false, err
	}
	response.SetBodyRaw(data)
	response.Header.SetContentLength(len(data))
	return false, nil
}

type responseBody struct {
	reader     io.Reader
	raw        io.Reader
	response   *fasthttp.Response
	ctx        context.Context
	readMu     sync.Mutex
	closed     atomic.Bool
	cleanup    []func()
	stopCancel func() bool
	canceled   chan struct{}
}

func newResponseBody(ctx context.Context, response *fasthttp.Response, maximum int64, countStructure bool, timeout time.Duration) (_ *responseBody, err error) {
	raw := response.BodyStream()
	if raw == nil {
		fasthttp.ReleaseResponse(response)
		return nil, errors.New("provider transport did not return a response stream")
	}
	body := &responseBody{raw: raw, response: response, ctx: ctx, canceled: make(chan struct{})}
	body.stopCancel = context.AfterFunc(ctx, func() {
		body.closeRaw(ctx.Err())
		close(body.canceled)
	})
	defer func() {
		if err != nil {
			_ = body.CloseWithError(err)
		}
	}()
	budget := budgetFrom(ctx)
	var source io.Reader = raw
	if strict, ok := raw.(interface{ ReadStrict([]byte) (int, error) }); ok {
		source = strictReader{strict.ReadStrict}
	}
	if socket, ok := raw.(interface{ SetReadDeadline(time.Time) error }); ok && timeout > 0 {
		source = &deadlineReader{source: source, setDeadline: socket.SetReadDeadline, timeout: timeout, ctx: ctx}
	}
	stage := &reader{source: source, budget: budget, limit: maximum}
	body.reader = stage
	encoding := strings.TrimSpace(string(response.Header.Peek("Content-Encoding")))
	if response.SkipBody || response.StatusCode() == fasthttp.StatusNoContent || response.StatusCode() == fasthttp.StatusNotModified {
		encoding = ""
	}
	encodings := strings.Split(strings.ToLower(encoding), ",")
	decoded := false
	for i := len(encodings) - 1; i >= 0; i-- {
		coding := strings.TrimSpace(encodings[i])
		if coding == "" || coding == "identity" {
			continue
		}
		var scratch int64
		switch coding {
		case "gzip", "x-gzip", "deflate":
			// 32-KiB history, two <=320-symbol Huffman tables (including
			// replacement overlap), a <=64-KiB gzip extra header and reader
			// buffers. A valid complete tree has at most one overflow table
			// per two symbols, each with at most 64 four-byte entries.
			scratch = 256 << 10
		case "br":
			scratch = BrotliDecoderReservation
		case "zstd":
			// One synchronous low-memory decoder: history growth plus bounded
			// 128-KiB block input/output and entropy work buffers.
			scratch = 2*maximum + 4*(128<<10)
		default:
			return nil, fmt.Errorf("unsupported provider content encoding %q", coding)
		}
		if budget != nil {
			release, admitted := budget.ReserveTemporary(scratch)
			if !admitted {
				return nil, ErrCapacity
			}
			body.cleanup = append(body.cleanup, release)
		}
		var next io.Reader
		switch coding {
		case "gzip", "x-gzip":
			decoder, decodeErr := gzip.NewReader(stage)
			if decodeErr != nil {
				return nil, decodeErr
			}
			next = decoder
			body.cleanup = append(body.cleanup, func() { _ = decoder.Close() })
		case "deflate":
			decoder, decodeErr := zlib.NewReader(stage)
			if decodeErr != nil {
				return nil, decodeErr
			}
			next = decoder
			body.cleanup = append(body.cleanup, func() { _ = decoder.Close() })
		case "br":
			next = brotli.NewReader(stage)
		case "zstd":
			decoder, decodeErr := zstd.NewReader(stage, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(uint64(maximum)), zstd.WithDecoderMaxWindow(uint64(maximum)))
			if decodeErr != nil {
				return nil, decodeErr
			}
			next = decoder
			body.cleanup = append(body.cleanup, decoder.Close)
		}
		stage = &reader{source: next, budget: budget, limit: maximum}
		body.reader = stage
		decoded = true
	}
	stage.countStructure = countStructure
	if decoded {
		response.Header.Del("Content-Encoding")
		response.Header.SetContentLength(-1)
	}
	return body, nil
}

type deadlineReader struct {
	source      io.Reader
	setDeadline func(time.Time) error
	timeout     time.Duration
	ctx         context.Context
}

type strictReader struct{ read func([]byte) (int, error) }

func (r strictReader) Read(p []byte) (int, error) { return r.read(p) }

func (r *deadlineReader) Read(p []byte) (int, error) {
	deadline := time.Now().Add(r.timeout)
	if limit, ok := r.ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := r.setDeadline(deadline); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}

func (b *responseBody) Read(p []byte) (int, error) {
	b.readMu.Lock()
	defer b.readMu.Unlock()
	if b.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := b.reader.Read(p)
	if ctxErr := b.ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	if err != nil && !errors.Is(err, io.EOF) {
		b.closeRaw(err)
	}
	return n, err
}

func (b *responseBody) closeRaw(err error) {
	if closer, ok := b.raw.(interface{ CloseWithError(error) error }); ok {
		_ = closer.CloseWithError(err)
	} else if closer, ok := b.raw.(io.Closer); ok {
		_ = closer.Close()
	}
}

func (b *responseBody) Close() error { return b.CloseWithError(nil) }

func (b *responseBody) CloseWithError(err error) error {
	if !b.closed.CompareAndSwap(false, true) {
		return nil
	}
	// Interrupt a blocked socket before waiting for the decoder's reader.
	b.closeRaw(err)
	if !b.stopCancel() {
		<-b.canceled
	}
	b.readMu.Lock()
	defer b.readMu.Unlock()
	for i := len(b.cleanup) - 1; i >= 0; i-- {
		b.cleanup[i]()
	}
	b.reader = nil
	b.cleanup = nil
	fasthttp.ReleaseResponse(b.response)
	b.response = nil
	return nil
}
