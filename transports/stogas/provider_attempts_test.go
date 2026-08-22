package stogas

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestBifrostRetryFeedsProviderAttemptsIntoFinalEvent(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"error":{"message":"upstream unavailable","type":"server_error"}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"id":"provider-request","object":"chat.completion","created":1,"model":"gpt-5","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	t.Cleanup(server.Close)

	providerConfig := newProviderConfig(server.URL, true, false)
	providerConfig.OpenAIConfig = &schemas.OpenAIConfig{DisableStore: true}
	providerConfig.NetworkConfig.MaxRetries = 1
	providerConfig.NetworkConfig.RetryBackoffInitial = time.Millisecond
	providerConfig.NetworkConfig.RetryBackoffMax = time.Millisecond
	providerAccount := &account{
		keys: map[schemas.ModelProvider]schemas.Key{
			schemas.OpenAI: {
				ID:      "openai-test",
				Name:    "openai-test",
				Value:   *schemas.NewSecretVar("sk-test"),
				Models:  schemas.WhiteList{"*"},
				Weight:  1,
				Enabled: schemas.Ptr(true),
			},
		},
		providerConfigs: map[schemas.ModelProvider]schemas.ProviderConfig{
			schemas.OpenAI: providerConfig,
		},
	}
	tracer := newProviderAttemptTracer(schemas.DefaultTracer())
	client, err := bifrost.Init(context.Background(), schemas.BifrostConfig{
		Account:         providerAccount,
		InitialPoolSize: 1,
		Logger:          bifrost.NewDefaultLogger(schemas.LogLevelError),
		Tracer:          tracer,
	})
	if err != nil {
		t.Fatalf("initialize Bifrost: %v", err)
	}
	t.Cleanup(client.Shutdown)

	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Route:       catalog.RouteChat,
			RequestType: schemas.ChatCompletionRequest,
			Provider:    schemas.OpenAI,
			Model:       "gpt-5",
		},
		Authorization: &billing.Authorization{
			AuthorizedAmount: big.NewInt(0),
			AvailableAfter:   big.NewInt(0),
			ProviderKey:      "openai",
			RequestID:        "request-real-retry",
		},
		StartedAt:         time.Now().UTC(),
		RequestType:       string(schemas.ChatCompletionRequest),
		FinalCostUSDAtoms: "0",
	}
	ctx := schemas.NewBifrostContext(context.Background(), time.Now().Add(10*time.Second))
	SetState(ctx, state)
	state.MarkProviderStarted()
	response, bifrostErr := client.ChatCompletionRequest(ctx, &schemas.BifrostChatRequest{
		Provider: schemas.OpenAI,
		Model:    "gpt-5",
		Input: []schemas.ChatMessage{{
			Role:    schemas.ChatMessageRoleUser,
			Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("hello")},
		}},
	})
	state.MarkProviderCompleted()
	if bifrostErr != nil {
		t.Fatalf("Bifrost retry returned error after %d requests: %s", hits.Load(), bifrostErr.GetErrorString())
	}
	if response == nil {
		t.Fatal("Bifrost retry returned no response")
	}
	state.Response = &schemas.BifrostResponse{ChatResponse: response}

	event := PrepareFinalState(state)
	if event == nil {
		t.Fatal("PrepareFinalState returned nil")
	}
	if hits.Load() != 2 || len(event.ProviderAttempts) != 2 {
		t.Fatalf("real retry hits=%d attempts=%#v", hits.Load(), event.ProviderAttempts)
	}
	if event.ProviderAttempts[0].Provider != "openai" || event.ProviderAttempts[1].Provider != "openai" {
		t.Fatalf("provider re-entry path = %#v", event.ProviderAttempts)
	}
	if event.ProviderAttempts[0].Status != "provider_error" || event.ProviderAttempts[1].Status != "success" {
		t.Fatalf("provider statuses = %#v", event.ProviderAttempts)
	}
	if event.ProviderAttempts[0].LatencyMS == 0 || event.ProviderAttempts[1].LatencyMS == 0 {
		t.Fatalf("provider attempt timing was not captured: %#v", event.ProviderAttempts)
	}
	providerMS, firstOutputMS := event.ProviderTiming()
	wantProviderMS := event.ProviderAttempts[0].LatencyMS + event.ProviderAttempts[1].LatencyMS
	if providerMS != wantProviderMS || firstOutputMS != nil {
		t.Fatalf("canonical provider timing = %d,%#v, want %d,nil", providerMS, firstOutputMS, wantProviderMS)
	}
}

func TestProviderAttemptTracerFeedsRetrySequenceIntoFinalEvent(t *testing.T) {
	base := time.Now().UTC().Add(-time.Second)
	timestamps := []time.Time{
		base.Add(10 * time.Millisecond),
		base.Add(40 * time.Millisecond),
		base.Add(55 * time.Millisecond),
		base.Add(145 * time.Millisecond),
	}
	nextTimestamp := 0
	tracer := newProviderAttemptTracer(schemas.DefaultTracer())
	tracer.now = func() time.Time {
		if nextTimestamp >= len(timestamps) {
			t.Fatalf("provider attempt tracer requested an unexpected timestamp")
		}
		value := timestamps[nextTimestamp]
		nextTimestamp++
		return value
	}

	finalResponse := &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{ID: "provider-request"}}
	statusCode := 502
	firstError := &schemas.BifrostError{
		StatusCode: &statusCode,
		Error:      &schemas.ErrorField{Message: "upstream unavailable"},
	}
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Route:       catalog.RouteChat,
			RequestType: schemas.ChatCompletionRequest,
			Provider:    schemas.OpenAI,
			Model:       "gpt-5",
		},
		Authorization: &billing.Authorization{
			AuthorizedAmount: big.NewInt(0),
			AvailableAfter:   big.NewInt(0),
			ProviderKey:      "openai",
			RequestID:        "request-1",
		},
		StartedAt:           base,
		RequestType:         string(schemas.ChatCompletionRequest),
		ProviderStartedAt:   base.Add(5 * time.Millisecond),
		ProviderCompletedAt: base.Add(150 * time.Millisecond),
		Response:            finalResponse,
		FinalCostUSDAtoms:   "0",
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	SetState(ctx, state)

	_, first := tracer.StartSpan(ctx, "chat gpt-5", schemas.SpanKindLLMCall)
	tracer.SetAttribute(first, schemas.AttrBifrostProviderName, "openai")
	tracer.PopulateLLMResponseAttributes(ctx, first, nil, firstError)
	tracer.EndSpan(first, schemas.SpanStatusError, "request failed")

	_, retry := tracer.StartSpan(ctx, "retry.attempt.1", schemas.SpanKindRetry)
	tracer.SetAttribute(retry, schemas.AttrBifrostProviderName, "openai")
	tracer.PopulateLLMResponseAttributes(ctx, retry, finalResponse, nil)
	tracer.EndSpan(retry, schemas.SpanStatusOk, "")

	event := PrepareFinalState(state)
	if event == nil {
		t.Fatal("PrepareFinalState returned nil")
	}
	if len(event.ProviderAttempts) != 2 {
		t.Fatalf("provider attempts = %#v, want two attempts", event.ProviderAttempts)
	}
	firstAttempt, retryAttempt := event.ProviderAttempts[0], event.ProviderAttempts[1]
	if firstAttempt.Provider != "openai" || retryAttempt.Provider != "openai" {
		t.Fatalf("provider re-entry was not preserved: %#v", event.ProviderAttempts)
	}
	if firstAttempt.LatencyMS != 30 || retryAttempt.LatencyMS != 90 {
		t.Fatalf("provider attempt latencies = %d,%d, want 30,90", firstAttempt.LatencyMS, retryAttempt.LatencyMS)
	}
	if firstAttempt.Status != "provider_error" || retryAttempt.Status != "success" {
		t.Fatalf("provider attempt statuses = %q,%q", firstAttempt.Status, retryAttempt.Status)
	}
	if retryAttempt.ProviderRequestID != "provider-request" {
		t.Fatalf("final provider request ID = %q", retryAttempt.ProviderRequestID)
	}
	providerMS, firstOutputMS := event.ProviderTiming()
	if providerMS != 120 || firstOutputMS != nil {
		t.Fatalf("provider timing = %d,%#v, want 120,nil", providerMS, firstOutputMS)
	}
}

func TestProviderAttemptTracerRetainsDeferredStreamingAttempt(t *testing.T) {
	base := time.Now().UTC().Add(-time.Second)
	timestamps := []time.Time{
		base.Add(10 * time.Millisecond),
		base.Add(30 * time.Millisecond),
		base.Add(40 * time.Millisecond),
		base.Add(100 * time.Millisecond),
	}
	nextTimestamp := 0
	tracer := newProviderAttemptTracer(schemas.DefaultTracer())
	tracer.now = func() time.Time {
		value := timestamps[nextTimestamp]
		nextTimestamp++
		return value
	}
	state := &State{}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	SetState(ctx, state)
	statusCode := 503
	firstError := &schemas.BifrostError{
		StatusCode: &statusCode,
		Error:      &schemas.ErrorField{Message: "upstream unavailable"},
	}

	_, first := tracer.StartSpan(ctx, "chat gpt-5", schemas.SpanKindLLMCall)
	tracer.SetAttribute(first, schemas.AttrBifrostProviderName, "openai")
	tracer.PopulateLLMResponseAttributes(ctx, first, nil, firstError)
	tracer.EndSpan(first, schemas.SpanStatusError, "request failed")

	_, streamingRetry := tracer.StartSpan(ctx, "retry.attempt.1", schemas.SpanKindRetry)
	tracer.SetAttribute(streamingRetry, schemas.AttrBifrostProviderName, "openai")
	tracer.StoreDeferredSpan("trace-1", streamingRetry)
	deferred := tracer.GetDeferredSpanHandle("trace-1")
	if deferred != streamingRetry {
		t.Fatalf("deferred provider span = %#v, want wrapped retry span", deferred)
	}
	response := &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{ID: "stream-response"}}
	tracer.PopulateLLMResponseAttributes(ctx, deferred, response, nil)
	tracer.EndSpan(deferred, schemas.SpanStatusOk, "")
	tracer.ClearDeferredSpan("trace-1")

	attempts := state.providerAttemptInputs()
	if len(attempts) != 2 {
		t.Fatalf("deferred provider attempts = %#v, want two attempts", attempts)
	}
	if attempts[1].CompletedAt.Sub(attempts[1].StartedAt) != 60*time.Millisecond || attempts[1].Response != response || attempts[1].Error != nil {
		t.Fatalf("final deferred attempt was not retained: %#v", attempts[1])
	}
	if tracer.GetDeferredSpanHandle("trace-1") != nil {
		t.Fatal("deferred provider span was not cleared")
	}
}

func TestProviderAttemptInputsKeepFallbackErrorsOnTheirAttempts(t *testing.T) {
	base := time.Now().UTC().Add(-time.Second)
	primaryStatus := 503
	fallbackStatus := 429
	primaryError := &schemas.BifrostError{StatusCode: &primaryStatus, Error: &schemas.ErrorField{Message: "primary unavailable"}}
	fallbackError := &schemas.BifrostError{StatusCode: &fallbackStatus, Error: &schemas.ErrorField{Message: "fallback rate limited"}}
	state := &State{BifrostError: primaryError}
	primary := state.beginProviderAttempt(base)
	state.setProviderAttemptProvider(primary, "openai")
	state.finishProviderAttempt(primary, base.Add(20*time.Millisecond), nil, primaryError)
	fallback := state.beginProviderAttempt(base.Add(30 * time.Millisecond))
	state.setProviderAttemptProvider(fallback, "anthropic")
	state.finishProviderAttempt(fallback, base.Add(70*time.Millisecond), nil, fallbackError)

	attempts := state.providerAttemptInputs()
	if len(attempts) != 2 || attempts[0].Error != primaryError || attempts[1].Error != fallbackError {
		t.Fatalf("fallback errors were reassigned: %#v", attempts)
	}

	protocolStatus := 502
	protocolError := &schemas.BifrostError{StatusCode: &protocolStatus, Error: &schemas.ErrorField{Message: "missing usage"}}
	state.BifrostError = protocolError
	attempts = state.providerAttemptInputs()
	if attempts[1].Error != protocolError {
		t.Fatalf("final protocol failure was not projected onto the final attempt: %#v", attempts)
	}
}
