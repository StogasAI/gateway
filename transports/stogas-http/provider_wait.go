package stogashttp

import (
	"context"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// providerResult is one provider call's outcome. ctx is the call's own
// context, which holds the provider's response headers and invocation facts.
// A call that never started has called false.
type providerResult[T any] struct {
	response T
	failure  *schemas.BifrostError
	panic    any
	ctx      *schemas.BifrostContext
	called   bool
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

// awaitProviderResult waits for a call while the caller waits. Encrypted
// responses get keepalive records that do not commit the response status. On
// caller timeout or disconnect, and at a plain stream's first keepalive, it
// returns ready instead: the pending call then has one new owner, which keeps
// admission, ingests usage and settles without the handler.
func awaitProviderResult[T any](ctx *requestContext, disconnected func(), ready <-chan providerResult[T], keepalive <-chan time.Time) (providerResult[T], <-chan providerResult[T]) {
	writer, encrypted := ctx.writer.(*sessionResponse)
	for {
		select {
		case result := <-ready:
			return result, nil
		case <-ctx.responseWait.done():
			return providerResult[T]{}, ready
		case <-ctx.request.Context().Done():
			disconnected()
			return providerResult[T]{}, ready
		case <-keepalive:
			if !encrypted {
				return providerResult[T]{}, ready
			}
			if err := writer.flushRecord(writer.stream.Keepalive); err != nil {
				disconnected()
				return providerResult[T]{}, ready
			}
		}
	}
}
