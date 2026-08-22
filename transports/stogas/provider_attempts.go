package stogas

import (
	"context"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// providerAttemptTracer observes Bifrost's canonical llm.call and retry spans.
// Bifrost creates one of these spans for every provider attempt, including each
// fallback and same-provider retry.
type providerAttemptTracer struct {
	schemas.Tracer
	now timeSource

	deferredMu sync.Mutex
	deferred   map[string]*providerAttemptSpan
}

type timeSource func() time.Time

type providerAttemptSpan struct {
	inner   schemas.SpanHandle
	state   *State
	index   int
	endOnce sync.Once

	mu       sync.Mutex
	response *schemas.BifrostResponse
	err      *schemas.BifrostError
}

func newProviderAttemptTracer(inner schemas.Tracer) *providerAttemptTracer {
	if inner == nil {
		inner = schemas.DefaultTracer()
	}
	return &providerAttemptTracer{Tracer: inner, now: time.Now}
}

func (t *providerAttemptTracer) StartSpan(ctx context.Context, name string, kind schemas.SpanKind) (context.Context, schemas.SpanHandle) {
	spanCtx, inner := t.Tracer.StartSpan(ctx, name, kind)
	if kind != schemas.SpanKindLLMCall && kind != schemas.SpanKindRetry {
		return spanCtx, inner
	}
	bifrostCtx, ok := ctx.(*schemas.BifrostContext)
	if !ok {
		return spanCtx, inner
	}
	state, ok := StateFrom(bifrostCtx)
	if !ok {
		return spanCtx, inner
	}
	return spanCtx, &providerAttemptSpan{
		inner: inner,
		state: state,
		index: state.beginProviderAttempt(t.now()),
	}
}

func (t *providerAttemptTracer) EndSpan(handle schemas.SpanHandle, status schemas.SpanStatus, statusMsg string) {
	span, ok := handle.(*providerAttemptSpan)
	if !ok {
		t.Tracer.EndSpan(handle, status, statusMsg)
		return
	}
	span.endOnce.Do(func() {
		span.mu.Lock()
		response := span.response
		bifrostErr := span.err
		span.mu.Unlock()
		span.state.finishProviderAttempt(span.index, t.now(), response, bifrostErr)
		t.Tracer.EndSpan(span.inner, status, statusMsg)
	})
}

func (t *providerAttemptTracer) SetAttribute(handle schemas.SpanHandle, key string, value any) {
	span, inner := providerAttemptHandle(handle)
	if span != nil && key == schemas.AttrBifrostProviderName {
		if provider, ok := value.(string); ok {
			span.state.setProviderAttemptProvider(span.index, provider)
		}
	}
	t.Tracer.SetAttribute(inner, key, value)
}

func (t *providerAttemptTracer) AddEvent(handle schemas.SpanHandle, name string, attrs map[string]any) {
	_, inner := providerAttemptHandle(handle)
	t.Tracer.AddEvent(inner, name, attrs)
}

func (t *providerAttemptTracer) PopulateLLMRequestAttributes(handle schemas.SpanHandle, req *schemas.BifrostRequest) {
	_, inner := providerAttemptHandle(handle)
	t.Tracer.PopulateLLMRequestAttributes(inner, req)
}

func (t *providerAttemptTracer) PopulateLLMResponseAttributes(ctx *schemas.BifrostContext, handle schemas.SpanHandle, response *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) {
	span, inner := providerAttemptHandle(handle)
	if span != nil {
		span.mu.Lock()
		span.response = response
		span.err = bifrostErr
		span.mu.Unlock()
	}
	t.Tracer.PopulateLLMResponseAttributes(ctx, inner, response, bifrostErr)
}

func (t *providerAttemptTracer) StoreDeferredSpan(traceID string, handle schemas.SpanHandle) {
	span, inner := providerAttemptHandle(handle)
	if span != nil {
		t.deferredMu.Lock()
		if t.deferred == nil {
			t.deferred = make(map[string]*providerAttemptSpan)
		}
		t.deferred[traceID] = span
		t.deferredMu.Unlock()
	}
	t.Tracer.StoreDeferredSpan(traceID, inner)
}

func (t *providerAttemptTracer) GetDeferredSpanHandle(traceID string) schemas.SpanHandle {
	t.deferredMu.Lock()
	span := t.deferred[traceID]
	t.deferredMu.Unlock()
	if span != nil {
		return span
	}
	return t.Tracer.GetDeferredSpanHandle(traceID)
}

func (t *providerAttemptTracer) ClearDeferredSpan(traceID string) {
	t.deferredMu.Lock()
	delete(t.deferred, traceID)
	t.deferredMu.Unlock()
	t.Tracer.ClearDeferredSpan(traceID)
}

func providerAttemptHandle(handle schemas.SpanHandle) (*providerAttemptSpan, schemas.SpanHandle) {
	span, ok := handle.(*providerAttemptSpan)
	if !ok {
		return nil, handle
	}
	return span, span.inner
}
