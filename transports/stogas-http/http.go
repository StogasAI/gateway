package stogashttp

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"github.com/valyala/fasthttp"
)

const maxInferenceStreamResponseBytes = 64 << 20

func (s *Server) readiness(ctx *fasthttp.RequestCtx) {
	if s != nil && s.memory.saturated() {
		writeNotReady(ctx)
		return
	}
	if s != nil && s.requests.diagnostics().Draining {
		writeNotReady(ctx)
		return
	}
	if s == nil {
		ctx.SetStatusCode(fasthttp.StatusNoContent)
		return
	}
	if ready, _ := s.catalogUpdater.Ready(time.Now().UTC()); !ready {
		writeNotReady(ctx)
		return
	}
	if s.secure == nil {
		ctx.SetStatusCode(fasthttp.StatusNoContent)
		return
	}
	result := s.secure.Readiness()
	if result.Ready {
		ctx.SetStatusCode(fasthttp.StatusNoContent)
		return
	}
	writeNotReady(ctx)
}

func writeNotReady(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
	ctx.SetContentType("application/json")
	_, _ = ctx.WriteString(`{"ok":false}`)
}

func (s *Server) diagnostics(ctx *fasthttp.RequestCtx) {
	ready := true
	reasons := []string{}
	if s != nil && s.memory.saturated() {
		ready = false
		reasons = append(reasons, "memory_pressure")
	}
	if s != nil && s.requests.diagnostics().Draining {
		ready = false
		reasons = append(reasons, "draining")
	}
	if s != nil && s.secure != nil {
		result := s.secure.Readiness()
		ready = ready && result.Ready
		reasons = append(reasons, result.Reasons...)
	}
	if s != nil {
		if catalogReady, reason := s.catalogUpdater.Ready(time.Now().UTC()); !catalogReady {
			ready = false
			reasons = append(reasons, reason)
		}
	}
	var catalogStatus catalog.UpdateStatus
	var controlStatus any
	if s != nil {
		catalogStatus = s.catalogUpdater.Status()
		if s.secure != nil {
			controlStatus = s.secure.ControlDiagnostics()
		}
	}
	s.writeJSON(ctx, fasthttp.StatusOK, map[string]any{
		"catalog": catalogStatus,
		"control": controlStatus,
		"node":    s.privateDiagnostics(),
		"ready":   ready,
		"reasons": reasons,
		"schema":  "stogas.node-diagnostics.v1",
	})
}

func (s *Server) catalog(ctx *fasthttp.RequestCtx) {
	payload, ok := catalog.PublicCatalogPayload()
	if !ok {
		s.writeCatalogError(ctx, catalog.ErrCatalogUnavailable)
		return
	}
	s.writeJSON(ctx, fasthttp.StatusOK, payload)
}

func (s *Server) models(ctx *fasthttp.RequestCtx) {
	payload, ok := catalog.PublicModelsPayload()
	if !ok {
		s.writeCatalogError(ctx, catalog.ErrCatalogUnavailable)
		return
	}
	s.writeJSON(ctx, fasthttp.StatusOK, payload)
}

func (s *Server) inference(ctx *fasthttp.RequestCtx) {
	requestStartedAt := time.Now()
	if s.memory == nil {
		s.memory = newRequestMemoryAdmission()
	}
	lease := requestMemoryLeaseForInference(ctx)
	if lease == nil {
		var admitted bool
		lease, admitted = s.memory.acquire(len(ctx.Request.Body()))
		if !admitted {
			s.writeRequestMemoryCapacity(ctx)
			return
		}
	}
	requestComplete := true
	defer func() {
		if requestComplete {
			lease.release()
		}
	}()

	session, ok := s.openEncryptedInference(ctx)
	if !ok {
		return
	}
	defer clear(ctx.Request.Body())
	if session != nil {
		defer s.sealBufferedEncryptedResponse(ctx, session)
	}
	if s.requests == nil {
		s.requests = newRequestDrain()
	}
	if !s.requests.begin() {
		s.writeError(ctx, fasthttp.StatusServiceUnavailable, map[string]any{
			"error": map[string]any{"message": "Gateway is draining", "type": "service_unavailable"},
		})
		return
	}
	defer func() {
		if requestComplete {
			s.requests.end()
		}
	}()

	credential, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return
	}
	ctx.RemoveUserValue(inferenceCredentialContextKey)
	nodeID := ""
	if s.secure != nil {
		if s.secure.Control != nil {
			nodeID = s.secure.Control.NodeID()
		}
	}
	var prepared *preparedCandidate
	for configAttempt := 0; configAttempt < 2 && prepared == nil; configAttempt++ {
		keyConfig, err := s.keyConfigForCredential(credential)
		if err != nil {
			s.writeBillingError(ctx, err)
			return
		}
		if keyConfig.Config.DeniedAt(time.Now().UTC()) {
			s.writeError(ctx, fasthttp.StatusForbidden, map[string]any{
				"error": map[string]any{
					"message": "Request is not allowed at this time",
					"type":    "permission_denied",
				},
			})
			return
		}
		resolutions, err := catalog.ResolveRequests(catalog.RequestInput{
			Body:            ctx.Request.Body(),
			Method:          string(ctx.Method()),
			Path:            string(ctx.Path()),
			Policy:          keyConfig.Config,
			RedactionPolicy: keyConfig.RedactionPolicy,
		})
		if err != nil {
			s.writeCatalogError(ctx, err)
			return
		}
		catalogIdentity := resolutions[0].CatalogIdentity()
		if s.proofs != nil {
			if err := s.proofs.ValidateCatalog(ctx, catalogIdentity.Digest, catalogIdentity.Sequence); err != nil {
				s.writeProofError(ctx)
				return
			}
		}

		var firstFailure *candidateFailure
		refreshConfig := false
		for _, resolution := range resolutions {
			candidate, failure := s.prepareCandidate(
				ctx,
				resolution,
				credential,
				nodeID,
				requestStartedAt,
				keyConfig.Generation,
			)
			if candidate != nil {
				prepared = candidate
				break
			}
			if firstFailure == nil {
				firstFailure = failure
			}
			if failure.refreshConfig && configAttempt == 0 {
				s.invalidateKeyConfig(credential)
				refreshConfig = true
				break
			}
			if !failure.tryNext {
				firstFailure = failure
				break
			}
		}
		if prepared != nil {
			break
		}
		if refreshConfig {
			continue
		}
		if firstFailure == nil {
			s.writeCatalogError(ctx, catalog.ErrModelUnavailable)
			return
		}
		switch firstFailure.kind {
		case candidateFailureBilling:
			s.writeBillingError(ctx, firstFailure.err)
		case candidateFailureRequest:
			s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
				"error": map[string]any{"message": firstFailure.err.Error(), "type": "invalid_request_error"},
			})
		default:
			s.writeCatalogError(ctx, firstFailure.err)
		}
		return
	}
	if prepared == nil {
		s.writeError(ctx, fasthttp.StatusServiceUnavailable, map[string]any{
			"error": map[string]any{"message": "Gateway configuration is unavailable", "type": "gateway_error"},
		})
		return
	}
	resolution := prepared.resolution
	adapter := prepared.adapter
	bifrostCtx := prepared.bifrostCtx
	bifrostReq := prepared.bifrostReq
	cancel := prepared.cancel
	state := prepared.state
	state.MarkProviderStarted()

	switch resolution.RequestType {
	case schemas.ChatCompletionStreamRequest:
		stream, bifrostErr := s.runtime.Client().ChatCompletionStreamRequest(bifrostCtx, bifrostReq.ChatRequest)
		if bifrostErr != nil {
			s.failStreamStart(ctx, bifrostCtx, state, adapter, bifrostErr, cancel)
			return
		}
		requestComplete = false
		s.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel, func() {
			s.requests.end()
			lease.release()
		})
		return
	case schemas.ResponsesStreamRequest:
		stream, bifrostErr := s.runtime.Client().ResponsesStreamRequest(bifrostCtx, bifrostReq.ResponsesRequest)
		if bifrostErr != nil {
			s.failStreamStart(ctx, bifrostCtx, state, adapter, bifrostErr, cancel)
			return
		}
		requestComplete = false
		s.writeSSEStream(ctx, bifrostCtx, state, stream, false, true, cancel, func() {
			s.requests.end()
			lease.release()
		})
		return
	case schemas.ChatCompletionRequest:
		defer cancel()
		response, bifrostErr := s.runtime.Client().ChatCompletionRequest(bifrostCtx, bifrostReq.ChatRequest)
		stateResponse := &schemas.BifrostResponse{ChatResponse: response}
		if !s.completeUnaryResponse(ctx, bifrostCtx, state, adapter, stateResponse, bifrostErr) {
			return
		}

		s.writeInferenceJSON(ctx, bifrostCtx, state, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
	case schemas.ResponsesRequest:
		defer cancel()
		response, bifrostErr := s.runtime.Client().ResponsesRequest(bifrostCtx, bifrostReq.ResponsesRequest)
		stateResponse := &schemas.BifrostResponse{ResponsesResponse: response}
		if !s.completeUnaryResponse(ctx, bifrostCtx, state, adapter, stateResponse, bifrostErr) {
			return
		}

		response = response.WithDefaults()
		response.Store = schemas.Ptr(false)
		response.Background = schemas.Ptr(false)
		s.writeInferenceJSON(ctx, bifrostCtx, state, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
	default:
		cancel()
		s.writeCatalogError(ctx, catalog.ErrUnsupportedRequest)
	}
}

func (s *Server) failStreamStart(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, state *stogas.State, adapter stogas.Adapter, bifrostErr *schemas.BifrostError, cancel context.CancelFunc) {
	state.MarkProviderCompleted()
	if err := adapter.IngestResponse(state, nil, bifrostErr); err != nil {
		bifrostErr = stogas.UpstreamProtocolError(err)
		state.BifrostError = bifrostErr
	}
	stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
	cancel()
	s.writeBifrostError(ctx, bifrostErr)
}

func (s *Server) completeUnaryResponse(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, state *stogas.State, adapter stogas.Adapter, response *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) bool {
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
	stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
	if bifrostErr == nil {
		bifrostErr = state.BifrostError
	}
	if bifrostErr == nil {
		return true
	}
	s.writeBifrostError(ctx, bifrostErr)
	return false
}

func (s *Server) writeSSEStream(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, state *stogas.State, stream chan *schemas.BifrostStreamChunk, sendDone bool, includeEventName bool, cancel context.CancelFunc, completion ...func()) {
	completedAsync := false
	defer func() {
		if !completedAsync && len(completion) > 0 && completion[0] != nil {
			completion[0]()
		}
	}()
	streamProof, proofErr := s.newStreamProof(ctx, bifrostCtx, state)
	if proofErr != nil {
		state.MarkProviderCompleted()
		s.writeProofError(ctx)
		cancel()
		return
	}
	proofTranscriptSHA256 := ""
	if session := encryptedSession(ctx); session != nil {
		proofTranscriptSHA256 = session.TranscriptSHA256()
	}
	responseMemory := s.memory.newLease(streamStateMemory)
	deliveryMemory := s.memory.newLease(downstreamDeliveryMemory)
	reader := newSSEStreamReader(deliveryMemory)
	includeChatUsage := clientRequestedChatStreamUsage(state)
	completedAsync = true

	go func() {
		if len(completion) > 0 && completion[0] != nil {
			defer completion[0]()
		}
		defer reader.done()
		defer responseMemory.release()
		defer stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		defer cancel()

		clientConnected := true
		clientClosed := reader.closed()
		responseBytes := 0
		sendStreamError := func(bifrostErr *schemas.BifrostError) {
			if !clientConnected {
				return
			}
			encoded, err := marshalPayload(bifrostErrorPayload(bifrostErr))
			if err == nil {
				_ = reader.sendErrorEvent(bifrostCtx, "", encoded)
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
			if state != nil && state.BifrostError != nil {
				sendStreamError(state.BifrostError)
				return
			}
			if streamProof != nil {
				if len(pendingTerminal) > 0 {
					streamProof.WriteSentChunk(pendingTerminal)
				}
				if sendDone {
					streamProof.WriteSentChunk(frameSSEDone())
				}
				streamProof.SetMetadata(proofMetadata(state, proofTranscriptSHA256))
				output, err := s.proofs.FinishStream(bifrostCtx, streamProof)
				if err != nil {
					encoded, encodeErr := marshalPayload(map[string]any{
						"error": map[string]any{
							"code":    responseProofErrorCode,
							"message": "Failed to build confidential response proof",
							"type":    "internal_error",
						},
					})
					if encodeErr == nil {
						_ = reader.sendErrorEvent(bifrostCtx, "", encoded)
					}
					return
				}
				if len(output.JSON) == 0 {
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
				return
			}
			frame := frameSSEEvent(streamEventName(includeEventName, eventName), encoded)
			if inferenceStreamResponseLimitExceeded(responseBytes, len(frame)) {
				bifrostErr := stogas.UpstreamProtocolError(stogas.ErrProviderResponseTooLarge)
				if state != nil {
					state.MarkProviderCompleted()
					state.BifrostError = bifrostErr
				}
				sendStreamError(bifrostErr)
				return
			}
			if !responseMemory.grow(len(frame)) {
				bifrostErr := streamMemoryCapacityError()
				if state != nil {
					state.MarkProviderCompleted()
					state.BifrostError = bifrostErr
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
				if terminal {
					finishSuccess(nil)
					return
				}
				continue
			}
			sent, deliveryCapacityExceeded := reader.send(bifrostCtx, frame)
			if !sent {
				if deliveryCapacityExceeded {
					bifrostErr := streamMemoryCapacityError()
					if state != nil {
						state.MarkProviderCompleted()
						state.BifrostError = bifrostErr
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
			if state != nil {
				if chunk.BifrostChatResponse != nil {
					state.ObserveChatStreamOutput(chunk.BifrostChatResponse)
				} else if chunk.BifrostResponsesStreamResponse != nil {
					state.ObserveResponsesStreamOutput(chunk.BifrostResponsesStreamResponse)
				}
			}
			if streamProof != nil {
				streamProof.WriteSentChunk(frame)
			}
			if terminal {
				finishSuccess(nil)
				return
			}
		}
	}()

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("X-Accel-Buffering", "no")
	if session := encryptedSession(ctx); session != nil {
		if err := s.sealStreamingEncryptedResponse(ctx, session, reader); err != nil {
			_ = reader.Close()
			s.writeError(ctx, fasthttp.StatusInternalServerError, map[string]any{
				"error": map[string]any{"message": "Failed to encrypt response", "type": "internal_error"},
			})
			return
		}
	} else {
		ctx.Response.SetBodyStream(reader, -1)
	}
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
	statusCode := fasthttp.StatusServiceUnavailable
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

func streamTimeoutError(code string) *schemas.BifrostError {
	statusCode := fasthttp.StatusGatewayTimeout
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

func (s *Server) notFound(ctx *fasthttp.RequestCtx) {
	s.writeError(ctx, fasthttp.StatusNotFound, map[string]any{
		"error": map[string]any{"message": "Route not found: " + string(ctx.Path()), "type": "invalid_request_error"},
	})
}

func (s *Server) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
	defer cancel()
	s.shutdownWithContext(ctx)
}

func (s *Server) shutdownWithContext(ctx context.Context) {
	var shutdowns sync.WaitGroup
	shutdownServer := func(name string, server *fasthttp.Server) {
		defer shutdowns.Done()
		if err := server.ShutdownWithContext(ctx); err != nil && s.logger != nil {
			s.logger.Warn("%s shutdown incomplete: %s", name, err)
		}
	}
	if s.readinessServer != nil {
		shutdowns.Add(1)
		go shutdownServer("private readiness server", s.readinessServer)
	}
	if s.server != nil {
		shutdowns.Add(1)
		go shutdownServer("gateway server", s.server)
	}
	shutdowns.Wait()
	if s.catalogUpdater != nil {
		s.catalogUpdater.Close()
	}
	if s.secure != nil {
		s.secure.Close()
	}
	if s.runtime != nil {
		runtimeClosed := make(chan struct{})
		go func() {
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
