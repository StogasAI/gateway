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
func awaitProviderStream(ctx *requestContext, open func() (chan *schemas.BifrostStreamChunk, *schemas.BifrostError)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
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
