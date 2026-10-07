package stogashttp

import (
	"context"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

type providerStreamStart struct {
	stream  chan *schemas.BifrostStreamChunk
	failure *schemas.BifrostError
}

// Canceling the provider is a request to stop, not proof that its goroutines
// and buffers have been released. The returned channel closes after the core's
// first-chunk bridge has drained its source. Keep work admission until then.
func finishProviderStream(cancel context.CancelFunc, pending <-chan providerStreamStart, stream chan *schemas.BifrostStreamChunk) {
	cancel()
	if pending != nil {
		stream = (<-pending).stream
	}
	if stream != nil {
		for range stream {
		}
	}
}

// Bifrost inspects the first provider chunk before returning its stream. Allow
// the response producer to send keepalives while that first chunk is silent.
// The buffered result has exactly one consumer and never drops started work.
func awaitProviderStream(ctx *requestContext, cancel context.CancelFunc, open func() (chan *schemas.BifrostStreamChunk, *schemas.BifrostError)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	if _, encrypted := ctx.writer.(*sessionResponse); encrypted {
		return awaitProviderResult(ctx, cancel, open)
	}
	result := make(chan providerStreamStart, 1)
	go func() { stream, failure := open(); result <- providerStreamStart{stream, failure} }()
	timer := time.NewTimer(responseKeepaliveInterval)
	defer timer.Stop()
	select {
	case started := <-result:
		return started.stream, started.failure
	case <-timer.C:
	case <-ctx.request.Context().Done():
	}
	ctx.pendingStream = result
	return nil, nil
}

// Binary control records keep buffered calls and stream startup alive without
// committing the E2EE response status. Ordinary HTTP calls remain synchronous.
// The handler is the only writer and owns admission until the provider returns,
// including after cancellation or a failed downstream write.
func awaitProviderResult[T any](ctx *requestContext, cancel context.CancelFunc, call func() (T, *schemas.BifrostError)) (T, *schemas.BifrostError) {
	writer, encrypted := ctx.writer.(*sessionResponse)
	if !encrypted {
		return call()
	}
	type result struct {
		response T
		failure  *schemas.BifrostError
		panic    any
	}
	unwrap := func(response result) (T, *schemas.BifrostError) {
		if response.panic != nil {
			panic(response.panic)
		}
		return response.response, response.failure
	}
	ready := make(chan result, 1)
	go func() {
		var response result
		defer func() {
			// Preserve net/http's handler panic boundary for provider calls.
			response.panic = recover()
			ready <- response
		}()
		response.response, response.failure = call()
	}()
	ticker := time.NewTicker(responseKeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case response := <-ready:
			return unwrap(response)
		case <-ctx.request.Context().Done():
			cancel()
			return unwrap(<-ready)
		case <-ticker.C:
			if err := writer.flushRecord(writer.stream.Keepalive); err != nil {
				cancel()
				return unwrap(<-ready)
			}
		}
	}
}
