package stogashttp

import (
	"context"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

type providerResult[T any] struct {
	response T
	failure  *schemas.BifrostError
	panic    any
}

type providerStreamStart = providerResult[chan *schemas.BifrostStreamChunk]

// Canceling the provider is a request to stop, not proof that its goroutines
// and buffers have been released. The returned channel closes after the core's
// first-chunk bridge has drained its source. Keep work admission until then.
func finishProviderStream(cancel context.CancelFunc, pending <-chan providerStreamStart, stream chan *schemas.BifrostStreamChunk) {
	cancel()
	if pending != nil {
		stream = (<-pending).response
	}
	if stream != nil {
		for range stream {
		}
	}
}

// Bifrost inspects the first provider chunk before returning its stream. Allow
// the response producer to send keepalives while that first chunk is silent.
// The buffered result has exactly one consumer and never drops started work.
func awaitProviderStream(ctx *requestContext, disconnected func(), open func() (chan *schemas.BifrostStreamChunk, *schemas.BifrostError)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	stream, failure, pending := awaitProviderResult(ctx, disconnected, open, true)
	ctx.pendingStream = pending
	return stream, failure
}

// Binary control records keep buffered calls and stream startup alive without
// committing the E2EE response status. On caller timeout or disconnect, pending
// transfers the one result consumer to the provider's completion owner. That
// owner must retain admission, ingest usage, and settle without the writer.
func awaitProviderResult[T any](ctx *requestContext, disconnected func(), call func() (T, *schemas.BifrostError), streaming bool) (T, *schemas.BifrostError, <-chan providerResult[T]) {
	writer, encrypted := ctx.writer.(*sessionResponse)
	ready := make(chan providerResult[T], 1)
	go func() {
		var response providerResult[T]
		defer func() {
			// A detached call must still settle after a provider panic. When the
			// caller is waiting, preserve net/http's handler recovery boundary.
			response.panic = recover()
			if response.panic != nil {
				response.failure = &schemas.BifrostError{
					StatusCode: schemas.Ptr(500), AllowFallbacks: schemas.Ptr(false),
					Error: &schemas.ErrorField{Message: "Provider request failed"},
				}
			}
			ready <- response
		}()
		response.response, response.failure = call()
	}()
	var keepalive <-chan time.Time
	if encrypted || streaming {
		ticker := time.NewTicker(responseKeepaliveInterval)
		defer ticker.Stop()
		keepalive = ticker.C
	}
	var zero T
	for {
		select {
		case response := <-ready:
			if response.panic != nil {
				panic(response.panic)
			}
			return response.response, response.failure, nil
		case <-ctx.responseWait.done():
			return zero, nil, ready
		case <-ctx.request.Context().Done():
			disconnected()
			return zero, nil, ready
		case <-keepalive:
			if !encrypted {
				return zero, nil, ready
			}
			if err := writer.flushRecord(writer.stream.Keepalive); err != nil {
				disconnected()
				return zero, nil, ready
			}
		}
	}
}
