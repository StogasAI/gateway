package stogashttp

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"net/http"
)

const maxInferenceStreamResponseBytes = 64 << 20
const responseKeepaliveInterval = 15 * time.Second

// Readiness and warm-channel admission share policy state. Transient memory
// pressure is handled by request admission, without ejecting healthy LB members.
func (s *Server) admissionReady() bool {
	if s == nil || s.requests.diagnostics().Draining {
		return false
	}
	if s.runtime != nil && !s.runtime.Billing().FinalizationReady() {
		return false
	}
	if s.secure != nil && !s.secure.Readiness().Ready {
		return false
	}
	return true
}

func (s *Server) readiness(ctx *requestContext) {
	if !s.admissionReady() {
		writeNotReady(ctx)
		return
	}
	ctx.writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireAdmission(ctx *requestContext) bool {
	if s.admissionReady() {
		return true
	}
	s.rejectAdmission(ctx)
	return false
}

func (s *Server) rejectAdmission(ctx *requestContext) {
	closeUnreadRequest(ctx)
	code, message := "gateway_unavailable", "Gateway is temporarily unavailable"
	if s.requests.diagnostics().Draining {
		code, message = "gateway_draining", "Gateway is draining"
		if response, ok := ctx.writer.(*sessionResponse); ok {
			response.closing = true
		}
	}
	s.writeError(ctx, http.StatusServiceUnavailable, map[string]any{
		"error": map[string]any{"message": message, "type": "service_unavailable", "code": code},
	})
}

func writeNotReady(ctx *requestContext) {
	ctx.writer.Header().Set("Content-Type", "application/json")
	ctx.writer.WriteHeader(http.StatusServiceUnavailable)
	_, _ = ctx.writer.Write([]byte(`{"ok":false}`))
}

func (s *Server) diagnostics(ctx *requestContext) {
	// The normal inference budget also accounts for concurrent private snapshots
	// and encoding. Under pressure, keep a small scalar snapshot available.
	details := s == nil || s.memory == nil
	if s != nil && s.memory != nil {
		lease := s.memory.newLease(streamStateMemory)
		if lease.grow(maximumDiagnosticResponseBytes * int(requestBodyReservationFactor)) {
			details = true
			defer lease.release()
		}
	}
	ready := true
	reasons := []string{}
	if s != nil && s.requests.diagnostics().Draining {
		ready = false
		reasons = append(reasons, "draining")
	}
	if s != nil && s.secure != nil {
		result := s.secure.Readiness()
		ready = ready && result.Ready
		reasons = append(reasons, result.Reasons...)
	}
	if s != nil && s.runtime != nil && !s.runtime.Billing().FinalizationReady() {
		ready = false
		reasons = append(reasons, "request_finalization_pending")
	}
	identity, _ := catalog.ActiveIdentity()
	var maintenanceStatus any
	if s != nil && s.secure != nil {
		maintenanceStatus = s.secure.Diagnostics()
	}
	payload, err := marshalPayload(map[string]any{
		"catalog":     map[string]any{"active": identity},
		"maintenance": maintenanceStatus,
		"node":        s.privateDiagnosticsSnapshot(details),
		"ready":       ready,
		"reasons":     reasons,
		"schema":      "stogas.node-diagnostics.v1",
	})
	if err != nil || len(payload) > maximumDiagnosticResponseBytes {
		s.writeError(ctx, http.StatusInternalServerError, map[string]any{"error": map[string]any{"type": "internal_error", "message": "Diagnostics exceed their encoding budget"}})
		return
	}
	s.writeResponse(ctx, http.StatusOK, "application/json", payload)
}

func (s *Server) catalog(ctx *requestContext) {
	payload, ok := catalog.PublicCatalogPayload()
	if !ok {
		s.writeCatalogError(ctx, catalog.ErrCatalogUnavailable)
		return
	}
	s.writeJSON(ctx, http.StatusOK, payload)
}

func (s *Server) models(ctx *requestContext) {
	payload, ok := catalog.PublicModelsPayload()
	if !ok {
		s.writeCatalogError(ctx, catalog.ErrCatalogUnavailable)
		return
	}
	s.writeJSON(ctx, http.StatusOK, payload)
}

func (s *Server) inference(ctx *requestContext) {
	if !s.requireAdmission(ctx) {
		return
	}
	requestStartedAt := time.Now()
	if s.memory == nil {
		s.memory = newRequestMemoryAdmission()
	}
	lease := requestMemoryLeaseForInference(ctx)
	if lease == nil {
		var admitted bool
		lease, admitted = s.memory.acquire(cap(ctx.body))
		if !admitted {
			s.writeRequestMemoryCapacity(ctx)
			return
		}
	}
	ctx.memory = lease
	requestComplete := true
	defer func() {
		if requestComplete {
			clear(ctx.body)
			ctx.body = nil
			lease.release()
		}
	}()

	if ctx.request.URL.RawQuery != "" {
		s.writeError(ctx, http.StatusBadRequest, map[string]any{"error": map[string]any{"message": "Query parameters are not supported", "type": "invalid_request_error"}})
		return
	}
	if s.requests == nil {
		s.requests = newRequestDrain()
	}
	if !s.requests.begin() {
		s.rejectAdmission(ctx)
		return
	}
	defer func() {
		if requestComplete {
			s.requests.end()
		}
	}()

	prepared := s.prepareInference(ctx, requestStartedAt)
	if prepared == nil {
		return
	}
	resolution := prepared.resolution
	adapter := prepared.adapter
	bifrostCtx := prepared.bifrostCtx
	bifrostReq := prepared.bifrostReq
	cancel := prepared.cancel
	state := prepared.state
	// Receipt hashing must precede release of the received body. The provider's
	// converted request can still borrow input storage, so do not overwrite it or
	// reduce the memory lease before the provider releases its own references.
	if wantsReceipt(bifrostCtx) {
		if _, err := ctx.receiptRequestDigest(); err != nil {
			finalizePreparedFailure(bifrostCtx, s.runtime.Billing(), state, err)
			cancel()
			s.writeProofError(ctx)
			return
		}
	}
	resolution.ReleaseInput()
	ctx.body = nil
	state.MarkProviderStarted()

	switch resolution.RequestType {
	case schemas.ChatCompletionStreamRequest:
		stream, bifrostErr := awaitProviderStream(ctx, cancel, func() (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
			return s.runtime.Client().ChatCompletionStreamRequest(bifrostCtx, bifrostReq.ChatRequest)
		})
		if bifrostErr != nil {
			s.failStreamStart(ctx, bifrostCtx, state, adapter, bifrostErr, cancel)
			return
		}
		requestComplete = false
		reader := s.startSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel, func() {
			s.requests.end()
			lease.release()
		})
		ctx.body = nil
		if reader != nil {
			s.writeStream(ctx, reader)
		}
		return
	case schemas.ResponsesStreamRequest:
		stream, bifrostErr := awaitProviderStream(ctx, cancel, func() (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
			return s.runtime.Client().ResponsesStreamRequest(bifrostCtx, bifrostReq.ResponsesRequest)
		})
		if bifrostErr != nil {
			s.failStreamStart(ctx, bifrostCtx, state, adapter, bifrostErr, cancel)
			return
		}
		requestComplete = false
		reader := s.startSSEStream(ctx, bifrostCtx, state, stream, false, true, cancel, func() {
			s.requests.end()
			lease.release()
		})
		ctx.body = nil
		if reader != nil {
			s.writeStream(ctx, reader)
		}
		return
	case schemas.ChatCompletionRequest:
		defer cancel()
		response, bifrostErr := awaitProviderResult(ctx, cancel, func() (*schemas.BifrostChatResponse, *schemas.BifrostError) {
			return s.runtime.Client().ChatCompletionRequest(bifrostCtx, bifrostReq.ChatRequest)
		})
		stateResponse := &schemas.BifrostResponse{ChatResponse: response}
		if !s.completeUnaryResponse(ctx, bifrostCtx, state, adapter, stateResponse, bifrostErr) {
			return
		}
		defer stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)

		s.writeInferenceJSON(ctx, bifrostCtx, state, http.StatusOK, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
	case schemas.ResponsesRequest:
		defer cancel()
		response, bifrostErr := awaitProviderResult(ctx, cancel, func() (*schemas.BifrostResponsesResponse, *schemas.BifrostError) {
			return s.runtime.Client().ResponsesRequest(bifrostCtx, bifrostReq.ResponsesRequest)
		})
		stateResponse := &schemas.BifrostResponse{ResponsesResponse: response}
		if !s.completeUnaryResponse(ctx, bifrostCtx, state, adapter, stateResponse, bifrostErr) {
			return
		}
		defer stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)

		response = response.WithDefaults()
		response.Store = schemas.Ptr(false)
		response.Background = schemas.Ptr(false)
		s.writeInferenceJSON(ctx, bifrostCtx, state, http.StatusOK, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
	default:
		cancel()
		s.writeCatalogError(ctx, catalog.ErrUnsupportedRequest)
	}
}

func (s *Server) failStreamStart(ctx *requestContext, bifrostCtx *schemas.BifrostContext, state *stogas.State, adapter stogas.Adapter, bifrostErr *schemas.BifrostError, cancel context.CancelFunc) {
	state.MarkProviderCompleted()
	if err := adapter.IngestResponse(state, nil, bifrostErr); err != nil {
		bifrostErr = stogas.UpstreamProtocolError(err)
		state.BifrostError = bifrostErr
	}
	bifrostErr = providerResponseMemoryError(ctx, state, bifrostErr)
	stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
	cancel()
	s.writeBifrostError(ctx, bifrostErr)
}

func (s *Server) completeUnaryResponse(ctx *requestContext, bifrostCtx *schemas.BifrostContext, state *stogas.State, adapter stogas.Adapter, response *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) bool {
	state.MarkProviderCompleted()
	if err := adapter.IngestResponse(state, response, bifrostErr); err != nil {
		bifrostErr = stogas.UpstreamProtocolError(err)
		state.BifrostError = bifrostErr
	} else if bifrostErr == nil {
		if err := stogas.ValidateCompletedExecution(state); err != nil {
			bifrostErr = stogas.UpstreamProtocolError(err)
			state.BifrostError = bifrostErr
		}
	}
	adapter.SanitizeResponse(state)
	bifrostErr = providerResponseMemoryError(ctx, state, bifrostErr)
	stogas.PrepareFinalState(state)
	if bifrostErr == nil {
		bifrostErr = state.ResponseError()
	}
	if bifrostErr == nil {
		state.Export.Response(state.Response)
		return true
	}
	stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
	s.writeBifrostError(ctx, bifrostErr)
	return false
}

func (s *Server) startSSEStream(ctx *requestContext, bifrostCtx *schemas.BifrostContext, state *stogas.State, stream chan *schemas.BifrostStreamChunk, sendDone bool, includeEventName bool, cancel context.CancelFunc, completion ...func()) io.ReadCloser {
	pending := ctx.pendingStream
	ctx.pendingStream = nil
	completedAsync := false
	defer func() {
		if !completedAsync && len(completion) > 0 && completion[0] != nil {
			completion[0]()
		}
	}()
	streamProof, proofErr := s.newStreamProof(ctx, bifrostCtx, state)
	if proofErr != nil {
		state.MarkProviderCompleted()
		retainResponseFailure(state, responseProofFailure())
		finishProviderStream(cancel, pending, stream)
		stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		s.writeProofError(ctx)
		return nil
	}
	responseMemory := ctx.memory.newRetainedLease(streamStateMemory)
	deliveryMemory := ctx.memory.newRetainedLease(downstreamDeliveryMemory)
	reader := newSSEStreamReader(deliveryMemory)
	includeChatUsage := clientRequestedChatStreamUsage(state)
	completedAsync = true

	go func() {
		if len(completion) > 0 && completion[0] != nil {
			defer completion[0]()
		}
		defer responseMemory.release()
		defer stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		defer func() {
			finishProviderStream(cancel, pending, stream)
		}()
		// Finish downstream delivery independently of provider teardown. Provider
		// admission and retained state remain charged until teardown completes.
		defer reader.done()

		keepalive := time.NewTimer(responseKeepaliveInterval)
		defer keepalive.Stop()
		keepaliveC := keepalive.C
		if pending != nil {
			reader.sendUnreserved(bifrostCtx, frameSSEComment("STOGAS PROCESSING"))
		}
		clientConnected := true
		clientClosed := reader.closed()
		responseBytes := 0
		sendStreamError := func(bifrostErr *schemas.BifrostError) {
			bifrostErr = providerResponseMemoryError(ctx, state, bifrostErr)
			if !clientConnected {
				return
			}
			encoded, err := marshalPayload(bifrostErrorPayload(bifrostErr))
			if err == nil {
				_ = reader.sendErrorEvent(bifrostCtx, "", encoded)
				clear(encoded)
			}
		}
		finishRequestTimeout := func() {
			bifrostErr := streamLifetimeTimeoutError()
			if state != nil {
				state.MarkProviderCompleted()
				state.BifrostError = bifrostErr
			}
			sendStreamError(bifrostErr)
		}
		finishSuccess := func(pendingTerminal []byte) {
			defer func() { clear(pendingTerminal) }()
			state.MarkProviderCompleted()
			if state != nil && state.Adapter != nil && state.BifrostError == nil {
				if err := stogas.ValidateCompletedExecution(state); err != nil {
					state.BifrostError = stogas.UpstreamProtocolError(err)
					sendStreamError(state.BifrostError)
					return
				}
			}
			if !clientConnected {
				return
			}
			stogas.PrepareFinalState(state)
			if failure := state.ResponseError(); failure != nil {
				sendStreamError(failure)
				return
			}
			if streamProof != nil {
				if len(pendingTerminal) > 0 {
					streamProof.WriteSentChunk(pendingTerminal)
				}
				if sendDone {
					streamProof.WriteSentChunk(frameSSEDone())
				}
				streamProof.SetMetadata(proofMetadata(bifrostCtx, state))
				output, err := s.proofs.FinishStream(bifrostCtx, streamProof)
				if err != nil || output == nil || len(output.JSON) == 0 {
					proofFailure := responseProofFailure()
					retainResponseFailure(state, proofFailure)
					sendStreamError(proofFailure)
					return
				}
				sent, _ := reader.send(bifrostCtx, frameSSEComment(proofhttp.SSECommentPrefix+string(output.JSON)))
				if !sent {
					return
				}
			}
			if len(pendingTerminal) > 0 {
				sent, _ := reader.send(bifrostCtx, pendingTerminal)
				if !sent {
					return
				}
				pendingTerminal = nil // The delivery reader now owns the frame.
			}
			if sendDone {
				_ = reader.sendDone(bifrostCtx)
			}
		}

		for {
			var chunk *schemas.BifrostStreamChunk
			select {
			case <-bifrostCtx.Done():
				finishRequestTimeout()
				return
			case started := <-pending:
				pending = nil
				if started.failure != nil {
					state.MarkProviderCompleted()
					state.BifrostError = started.failure
					if state.Adapter != nil {
						if err := state.Adapter.IngestResponse(state, nil, started.failure); err != nil {
							state.BifrostError = stogas.UpstreamProtocolError(err)
						}
					}
					sendStreamError(state.BifrostError)
					return
				}
				stream = started.stream
				if stream == nil {
					finishSuccess(nil)
					return
				}
				continue
			case <-keepaliveC:
				if clientConnected {
					sent, _ := reader.send(bifrostCtx, frameSSEComment("STOGAS PROCESSING"))
					if sent {
						keepalive.Reset(responseKeepaliveInterval)
					} else {
						keepaliveC = nil
					}
				} else {
					keepaliveC = nil
				}
				continue
			case <-clientClosed:
				clientConnected = false
				if state != nil {
					state.MarkClientStopped()
				}
				clientClosed = nil
				continue
			case next, ok := <-stream:
				if !ok {
					finishSuccess(nil)
					return
				}
				chunk = next
			}

			if chunk == nil {
				continue
			}
			if state != nil && state.Adapter != nil {
				if err := state.Adapter.IngestChunk(state, chunk); err != nil {
					state.MarkProviderCompleted()
					bifrostErr := stogas.UpstreamProtocolError(err)
					state.BifrostError = bifrostErr
					sendStreamError(bifrostErr)
					return
				}
				if chunk.BifrostError == nil && state.BifrostError == nil {
					if err := stogas.ValidateStreamExecutionBeforeOutput(state); err != nil {
						state.MarkProviderCompleted()
						bifrostErr := stogas.UpstreamProtocolError(err)
						state.BifrostError = bifrostErr
						sendStreamError(bifrostErr)
						return
					}
				}
			}
			if clientConnected && state != nil {
				state.Export.Chunk(chunk)
			}
			terminal := stogas.ProviderStreamTerminal(state)

			if chunk.BifrostError != nil {
				state.MarkProviderCompleted()
				sendStreamError(chunk.BifrostError)
				return
			}

			var (
				eventName string
				payload   any
			)

			switch {
			case chunk.BifrostChatResponse != nil:
				eventName = ""
				chatResponse := chunk.BifrostChatResponse
				if !includeChatUsage && chatResponse.Usage != nil {
					if len(chatResponse.Choices) == 0 {
						if terminal {
							finishSuccess(nil)
							return
						}
						continue
					}
					copy := *chatResponse
					copy.Usage = nil
					chatResponse = &copy
				}
				extra := chatResponse.ExtraFields
				payload = publicResponsePayload(bifrostCtx, chatResponse, extra)
			case chunk.BifrostResponsesStreamResponse != nil:
				eventName = string(chunk.BifrostResponsesStreamResponse.Type)
				extra := chunk.BifrostResponsesStreamResponse.ExtraFields
				normalized := chunk.BifrostResponsesStreamResponse.WithDefaults()
				if normalized == nil {
					if terminal {
						finishSuccess(nil)
						return
					}
					continue
				}
				if normalized.Response != nil {
					normalized.Response.Store = schemas.Ptr(false)
					normalized.Response.Background = schemas.Ptr(false)
				}
				payload = publicResponsePayload(bifrostCtx, normalized, extra)
			default:
				continue
			}

			encoded, err := marshalPayload(payload)
			if err != nil {
				failure := responseEncodingFailure()
				state.MarkProviderCompleted()
				retainResponseFailure(state, failure)
				sendStreamError(failure)
				return
			}
			frame := frameSSEEvent(streamEventName(includeEventName, eventName), encoded)
			clear(encoded)
			if inferenceStreamResponseLimitExceeded(responseBytes, len(frame)) {
				clear(frame)
				bifrostErr := stogas.UpstreamProtocolError(stogas.ErrProviderResponseTooLarge)
				if state != nil {
					state.MarkProviderCompleted()
					state.BifrostError = bifrostErr
				}
				sendStreamError(bifrostErr)
				return
			}
			if !responseMemory.grow(len(frame)) {
				clear(frame)
				bifrostErr := streamMemoryCapacityError()
				if state != nil {
					state.MarkProviderCompleted()
					retainResponseFailure(state, bifrostErr)
				}
				sendStreamError(bifrostErr)
				return
			}
			responseBytes += len(frame)
			if terminal && !sendDone && streamProof != nil {
				finishSuccess(frame)
				return
			}
			if !clientConnected {
				clear(frame)
				if terminal {
					finishSuccess(nil)
					return
				}
				continue
			}
			// Hash before handing ownership to the delivery reader, which clears
			// consumed bytes. Failed delivery cannot produce normal completion.
			if streamProof != nil {
				streamProof.WriteSentChunk(frame)
			}
			sent, deliveryCapacityExceeded := reader.send(bifrostCtx, frame)
			if !sent {
				if deliveryCapacityExceeded {
					clear(frame)
					bifrostErr := streamMemoryCapacityError()
					if state != nil {
						state.MarkProviderCompleted()
						retainResponseFailure(state, bifrostErr)
					}
					sendStreamError(bifrostErr)
					return
				}
				if bifrostCtx.Err() != nil {
					finishRequestTimeout()
					return
				}
				clientConnected = false
				clientClosed = nil
				if terminal {
					finishSuccess(nil)
					return
				}
				continue
			}
			keepalive.Reset(responseKeepaliveInterval)
			if state != nil {
				if chunk.BifrostChatResponse != nil {
					state.ObserveChatStreamOutput(chunk.BifrostChatResponse)
				} else if chunk.BifrostResponsesStreamResponse != nil {
					state.ObserveResponsesStreamOutput(chunk.BifrostResponsesStreamResponse)
				}
			}
			if terminal {
				finishSuccess(nil)
				return
			}
		}
	}()

	ctx.writer.Header().Set("Content-Type", "text/event-stream")
	ctx.writer.Header().Set("Cache-Control", "no-cache")
	ctx.writer.Header().Set("X-Accel-Buffering", "no")
	return reader
}

func inferenceStreamResponseLimitExceeded(current, next int) bool {
	return current < 0 || next < 0 || current > maxInferenceStreamResponseBytes-next
}

func clientRequestedChatStreamUsage(state *stogas.State) bool {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteChat {
		return false
	}
	optionsRaw := state.Resolution.RawBody()["stream_options"]
	if len(optionsRaw) == 0 {
		return false
	}
	var options struct {
		IncludeUsage *bool `json:"include_usage"`
	}
	return json.Unmarshal(optionsRaw, &options) == nil && options.IncludeUsage != nil && *options.IncludeUsage
}

func streamLifetimeTimeoutError() *schemas.BifrostError {
	return streamTimeoutError("request_timeout")
}

func streamMemoryCapacityError() *schemas.BifrostError {
	statusCode := http.StatusServiceUnavailable
	errorType := "gateway_error"
	code := "gateway_capacity_exceeded"
	allowFallbacks := false
	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &statusCode,
		Type:           &errorType,
		AllowFallbacks: &allowFallbacks,
		Error: &schemas.ErrorField{
			Type:    &errorType,
			Code:    &code,
			Message: "Gateway capacity is temporarily exhausted",
		},
	}
}

func providerResponseMemoryError(ctx *requestContext, state *stogas.State, failure *schemas.BifrostError) *schemas.BifrostError {
	if ctx.memory == nil || !ctx.memory.responseFailed.Load() {
		return failure
	}
	failure = streamMemoryCapacityError()
	// The transport stopped reading for local capacity, so core's resulting
	// network/decode error is not evidence of an upstream service failure.
	if state != nil {
		state.BifrostError = nil
		retainResponseFailure(state, failure)
	}
	return failure
}

func streamTimeoutError(code string) *schemas.BifrostError {
	statusCode := http.StatusGatewayTimeout
	errorType := schemas.RequestTimedOut
	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &statusCode,
		Type:           &errorType,
		Error: &schemas.ErrorField{
			Type:    &errorType,
			Code:    &code,
			Message: "Upstream stream timed out",
		},
	}
}

func streamEventName(include bool, eventName string) string {
	if include {
		return eventName
	}
	return ""
}

func (s *Server) notFound(ctx *requestContext) {
	s.writeError(ctx, http.StatusNotFound, map[string]any{
		"error": map[string]any{"message": "Route not found: " + ctx.request.URL.Path, "type": "invalid_request_error"},
	})
}

func (s *Server) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), guestShutdownHardCap)
	defer cancel()
	s.shutdownWithContext(ctx)
}

func (s *Server) shutdownWithContext(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var idle <-chan struct{}
	if s.requests != nil {
		idle = s.requests.start()
	}
	var shutdowns sync.WaitGroup
	shutdownServer := func(name string, server *http.Server) {
		defer shutdowns.Done()
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
			if s.logger != nil {
				s.logger.Warn("%s shutdown deadline reached", name)
			}
		}
	}
	// Send GOAWAY and close public listeners immediately. Detached provider work
	// still owns its admission, and private diagnostics remain available for it.
	if s.server != nil {
		shutdowns.Add(1)
		go shutdownServer("gateway server", s.server)
	}
	if idle != nil {
		select {
		case <-idle:
		case <-ctx.Done():
		}
	}
	// Once provider work has ended, cleanup gets at most its own allowance,
	// even when most of the overall guest lifetime remains unused.
	cleanup := time.AfterFunc(serverShutdownTimeout, cancel)
	defer cleanup.Stop()
	if s.readinessServer != nil {
		shutdowns.Add(1)
		go shutdownServer("private readiness server", s.readinessServer)
	}
	if s.diagnosticsServer != nil {
		shutdowns.Add(1)
		go shutdownServer("private diagnostics server", s.diagnosticsServer)
	}
	shutdowns.Wait()

	if s.secure != nil {
		closed := make(chan struct{})
		go func() { s.secure.Close(); close(closed) }()
		select {
		case <-closed:
		case <-ctx.Done():
			if s.logger != nil {
				s.logger.Warn("confidential runtime shutdown incomplete")
			}
			return
		}
	}
	if s.exports != nil {
		s.exports.Close()
	}
	if s.runtime != nil {
		runtimeClosed := make(chan struct{})
		go func() {
			if err := s.runtime.Billing().DrainFinalizations(ctx); err != nil && s.logger != nil {
				s.logger.Warn("gateway finalization drain incomplete: %s", err)
			}
			s.runtime.Close()
			close(runtimeClosed)
		}()
		select {
		case <-runtimeClosed:
		case <-ctx.Done():
			if s.logger != nil {
				s.logger.Warn("gateway runtime shutdown incomplete: %s", ctx.Err())
			}
			return
		}
	}
	if s.logger != nil {
		s.logger.Info("gateway shutdown complete")
	}
}
