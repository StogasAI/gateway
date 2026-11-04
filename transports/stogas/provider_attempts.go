package stogas

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
)

// providerAttemptTracer observes Bifrost's LLM-call and retry spans.
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
	upstream billing.UpstreamRecord
}

func newProviderAttemptTracer(inner schemas.Tracer) *providerAttemptTracer {
	if inner == nil {
		inner = schemas.DefaultTracer()
	}
	return &providerAttemptTracer{Tracer: inner, now: time.Now}
}

func (t *providerAttemptTracer) StartSpan(ctx context.Context, name string, kind schemas.SpanKind) (context.Context, schemas.SpanHandle) {
	spanCtx, inner := t.Tracer.StartSpan(ctx, name, kind)
	return spanCtx, t.wrapAttempt(ctx, kind, inner)
}

func (t *providerAttemptTracer) StartSpanID(ctx context.Context, name string, kind schemas.SpanKind) (string, schemas.SpanHandle) {
	id, inner := t.Tracer.StartSpanID(ctx, name, kind)
	return id, t.wrapAttempt(ctx, kind, inner)
}

func (t *providerAttemptTracer) wrapAttempt(ctx context.Context, kind schemas.SpanKind, inner schemas.SpanHandle) schemas.SpanHandle {
	if kind != schemas.SpanKindLLMCall && kind != schemas.SpanKindRetry {
		return inner
	}
	bifrostCtx, ok := ctx.(*schemas.BifrostContext)
	if !ok {
		return inner
	}
	state, ok := StateFrom(bifrostCtx)
	if !ok {
		return inner
	}
	// Providers put their response headers on the context, and retries share it, so a call that
	// gets no reply would otherwise read the previous call's request ID. Core clears them only
	// between providers.
	bifrostCtx.ClearValue(schemas.BifrostContextKeyProviderResponseHeaders)
	span := &providerAttemptSpan{
		inner: inner,
		state: state,
		index: state.beginProviderAttempt(t.now()),
	}
	if state.Resolution != nil && state.Resolution.Provider == catalog.ProviderChutes {
		chutese2ee.SetRetryObserver(bifrostCtx, span.nextChutesInvocation)
	}
	return span
}

// Chutes retries stay inside its transport, so core emits no new LLM span.
// Move this span's accounting owner forward without losing the rejected call.
func (s *providerAttemptSpan) nextChutesInvocation(status int, instanceID string, completedAt, startedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.setProviderAttemptUpstream(s.index, billing.UpstreamRecord{InstanceID: instanceID})
	s.state.finishProviderAttempt(s.index, completedAt, nil, &schemas.BifrostError{
		StatusCode: &status,
		Error:      &schemas.ErrorField{Message: "Chutes rejected the invocation before execution"},
	})
	s.index = s.state.beginProviderAttempt(startedAt)
	s.state.setProviderAttemptProvider(s.index, string(catalog.ProviderChutes))
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
		upstream := span.upstream
		index := span.index
		span.mu.Unlock()
		span.state.finishProviderAttempt(index, t.now(), response, bifrostErr)
		span.state.setProviderAttemptUpstream(index, upstream)
		t.Tracer.EndSpan(span.inner, status, statusMsg)
	})
}

func (t *providerAttemptTracer) SetAttribute(handle schemas.SpanHandle, key string, value any) {
	span, inner := providerAttemptHandle(handle)
	if span != nil && key == schemas.AttrBifrostProviderName {
		if provider, ok := value.(string); ok {
			span.mu.Lock()
			span.state.setProviderAttemptProvider(span.index, provider)
			span.mu.Unlock()
		}
	}
	t.Tracer.SetAttribute(inner, key, value)
}

func (t *providerAttemptTracer) AddEvent(handle schemas.SpanHandle, name string, attrs map[string]any) {
	_, inner := providerAttemptHandle(handle)
	t.Tracer.AddEvent(inner, name, attrs)
}

func (t *providerAttemptTracer) SpanFromHandle(handle schemas.SpanHandle) *schemas.Span {
	_, inner := providerAttemptHandle(handle)
	return t.Tracer.SpanFromHandle(inner)
}

func (t *providerAttemptTracer) PopulateLLMRequestAttributes(handle schemas.SpanHandle, req *schemas.BifrostRequest) {
	span, inner := providerAttemptHandle(handle)
	if span != nil && req != nil {
		// Core now writes provider attributes directly onto its resolved span.
		// The request supplies the same identity even when tracing is disabled.
		provider, _, _ := req.GetRequestFields()
		span.mu.Lock()
		span.state.setProviderAttemptProvider(span.index, string(provider))
		span.mu.Unlock()
	}
	t.Tracer.PopulateLLMRequestAttributes(inner, req)
}

func (t *providerAttemptTracer) PopulateLLMResponseAttributes(ctx *schemas.BifrostContext, handle schemas.SpanHandle, response *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) {
	span, inner := providerAttemptHandle(handle)
	if span != nil {
		upstream := readUpstreamRecord(ctx, span.state.Resolution, response)
		span.mu.Lock()
		span.response = response
		span.err = bifrostErr
		span.upstream = upstream
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

// RecordStreamUpstream reads the provider's headers for the call that a stream comes from, as the
// stream starts. Core reads a stream's reply only in a trace, which this gateway does not keep, so
// they would otherwise go unread. The stream's model comes from its final response instead.
func RecordStreamUpstream(ctx *schemas.BifrostContext, state *State, resolution *catalog.ResolvedRequest) {
	if state != nil {
		state.setLatestProviderAttemptUpstream(readUpstreamRecord(ctx, resolution, nil))
	}
}

// readUpstreamRecord reads what the provider said about the call that just ended. The response
// headers on the context are this call's, because each call starts without them.
func readUpstreamRecord(ctx *schemas.BifrostContext, resolution *catalog.ResolvedRequest, response *schemas.BifrostResponse) billing.UpstreamRecord {
	if ctx == nil || resolution == nil {
		return billing.UpstreamRecord{}
	}
	headers, _ := ctx.Value(schemas.BifrostContextKeyProviderResponseHeaders).(map[string]string)
	var record billing.UpstreamRecord
	for _, name := range providerRequestIDHeaders(resolution.Provider) {
		if record.RequestID = upstreamHeader(headers, name); record.RequestID != "" {
			break
		}
	}
	switch resolution.Provider {
	case schemas.Azure:
		// Azure replies can repeat the deployment's name, which the customer chose. Its header
		// names the model with its version, where Azure reports it.
		record.Model = upstreamHeader(headers, "x-ms-served-model")
	case catalog.ProviderChutes:
		// Chutes sends no request ID on encrypted calls; its records name the instance.
		record.Model = replyModel(response)
		record.InstanceID = chutese2ee.InvocationInstanceID(ctx)
	default:
		record.Model = replyModel(response)
	}
	return record
}

// providerRequestIDHeaders are the response headers that name a call to its provider's support,
// most useful first. Azure sends apim-request-id, which its support asks for, with x-request-id.
// AWS names each call in x-amzn-requestid; Claude on AWS can also carry Anthropic's request-id.
func providerRequestIDHeaders(provider schemas.ModelProvider) []string {
	switch provider {
	case schemas.OpenAI:
		return []string{"x-request-id"}
	case schemas.Anthropic:
		return []string{"request-id"}
	case schemas.Azure:
		return []string{"apim-request-id", "x-request-id"}
	case catalog.ProviderAWS:
		return []string{"x-amzn-requestid", "request-id"}
	default:
		return []string{"x-request-id", "request-id"}
	}
}

func upstreamHeader(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// replyModel is the model that a reply names.
func replyModel(response *schemas.BifrostResponse) string {
	switch {
	case response == nil:
		return ""
	case response.ChatResponse != nil:
		return response.ChatResponse.Model
	case response.ResponsesResponse != nil:
		return response.ResponsesResponse.Model
	case response.ResponsesStreamResponse != nil && response.ResponsesStreamResponse.Response != nil:
		return response.ResponsesStreamResponse.Response.Model
	}
	return ""
}

func providerAttemptHandle(handle schemas.SpanHandle) (*providerAttemptSpan, schemas.SpanHandle) {
	span, ok := handle.(*providerAttemptSpan)
	if !ok {
		return nil, handle
	}
	return span, span.inner
}
