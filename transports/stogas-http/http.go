package stogashttp

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"github.com/valyala/fasthttp"
)

const maxInferenceStreamResponseBytes = 64 << 20

func (s *Server) readiness(ctx *fasthttp.RequestCtx) {
	if s != nil && s.memory.pressured() {
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
	if s != nil && s.memory.pressured() {
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
	ctx.Response.Header.Set("X-Stogas-Catalog-Sequence", strconv.FormatUint(payload.Sequence, 10))
	ctx.Response.Header.Set("X-Stogas-Catalog-Digest", payload.RuntimeDigest)
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
		s.memory = &requestMemoryAdmission{}
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

	providerConstraint := ""
	if credential.Upstream != nil {
		providerConstraint = credential.Upstream.Provider
	}
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Body:               ctx.Request.Body(),
		Method:             string(ctx.Method()),
		Path:               string(ctx.Path()),
		ProviderConstraint: providerConstraint,
	})
	if err != nil {
		s.writeCatalogError(ctx, err)
		return
	}
	catalogIdentity := resolution.CatalogIdentity()
	if s.proofs != nil {
		if err := s.proofs.ValidateCatalog(ctx, catalogIdentity.Digest, catalogIdentity.Sequence); err != nil {
			s.writeProofError(ctx)
			return
		}
	}

	adapter := stogas.AdapterFor(resolution.Provider)
	nodeID := ""
	if s.secure != nil {
		if s.secure.Control != nil {
			nodeID = s.secure.Control.NodeID()
		}
	}
	bifrostCtx, state, cancel, err := newRequestContext(
		ctx,
		resolution,
		credential,
		adapter,
		nodeID,
	)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "invalid_request_error"},
		})
		return
	}
	state.StartedAt = requestStartedAt
	if err := adapter.ValidateRequest(state); err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}
	if err := adapter.SanitizeRequest(state); err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}
	if err := adapter.EstimateHold(state); err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}
	bifrostReq, err := resolution.ToBifrost(bifrostCtx)
	if err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}
	if err := stogas.PrepareProviderRequest(bifrostCtx, state, bifrostReq); err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}

	if err := stogas.AuthorizeState(bifrostCtx, s.runtime.Billing(), state); err != nil {
		if state.Authorization != nil {
			status := fasthttp.StatusServiceUnavailable
			state.BifrostError = &schemas.BifrostError{
				IsBifrostError: true,
				StatusCode:     &status,
				Error:          &schemas.ErrorField{Message: "BYOK key is unavailable"},
			}
			stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		}
		cancel()
		s.writeBillingError(ctx, err)
		return
	}
	if err := stogas.ApplyUpstreamCredentials(bifrostCtx, state); err != nil {
		status := fasthttp.StatusServiceUnavailable
		state.BifrostError = &schemas.BifrostError{
			IsBifrostError: true,
			StatusCode:     &status,
			Error:          &schemas.ErrorField{Message: "BYOK key is unavailable"},
		}
		stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		cancel()
		s.writeBillingError(ctx, err)
		return
	}
	if resolution.Provider == schemas.Azure {
		bifrostReq, err = resolution.ToBifrost(bifrostCtx)
		if err != nil {
			s.failPreparedProviderRequest(ctx, bifrostCtx, state, cancel, err)
			return
		}
		if err := stogas.PrepareProviderRequest(bifrostCtx, state, bifrostReq); err != nil {
			s.failPreparedProviderRequest(ctx, bifrostCtx, state, cancel, err)
			return
		}
	}
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

		s.forwardProviderHeaders(ctx, bifrostCtx, response.ExtraFields)
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
		s.forwardProviderHeaders(ctx, bifrostCtx, response.ExtraFields)
		s.writeInferenceJSON(ctx, bifrostCtx, state, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
	default:
		cancel()
		s.writeCatalogError(ctx, catalog.ErrUnsupportedRequest)
	}
}

func (s *Server) failPreparedProviderRequest(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, state *stogas.State, cancel context.CancelFunc, err error) {
	status := fasthttp.StatusBadRequest
	state.BifrostError = &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &status,
		Error:          &schemas.ErrorField{Message: "Invalid provider request"},
	}
	stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
	cancel()
	s.writeCatalogError(ctx, err)
}

func (s *Server) failStreamStart(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, state *stogas.State, adapter stogas.Adapter, bifrostErr *schemas.BifrostError, cancel context.CancelFunc) {
	state.MarkProviderCompleted()
	if err := adapter.IngestResponse(state, nil, bifrostErr); err != nil {
		bifrostErr = stogas.UpstreamProtocolError(err)
		state.BifrostError = bifrostErr
	}
	stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
	cancel()
	s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
	s.writeBifrostError(ctx, bifrostErr)
}

func (s *Server) completeUnaryResponse(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, state *stogas.State, adapter stogas.Adapter, response *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) bool {
	state.MarkProviderCompleted()
	if err := adapter.IngestResponse(state, response, bifrostErr); err != nil {
		bifrostErr = stogas.UpstreamProtocolError(err)
		state.BifrostError = bifrostErr
	} else if bifrostErr == nil {
		if !stogas.HasMeasuredUsage(state) {
			bifrostErr = stogas.UpstreamProtocolError(stogas.ErrProviderUsageMissing)
			state.BifrostError = bifrostErr
		} else if err := stogas.ValidateCompletedExecution(state); err != nil {
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
	s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
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
	reader := newSSEStreamReader()
	includeChatUsage := clientRequestedChatStreamUsage(state)
	completedAsync = true

	go func() {
		if len(completion) > 0 && completion[0] != nil {
			defer completion[0]()
		}
		defer reader.done()
		defer stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		defer cancel()

		clientConnected := true
		clientClosed := reader.closed()
		idleTimeout := streamIdleTimeout(state, s.chatIdleTimeout)
		var idleTimer *time.Timer
		var idleC <-chan time.Time
		if idleTimeout > 0 {
			idleTimer = time.NewTimer(idleTimeout)
			idleC = idleTimer.C
			defer idleTimer.Stop()
		}
		resetIdleTimer := func() {
			if idleTimer == nil {
				return
			}
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idleTimeout)
		}
		responseBytes := 0
		sendStreamError := func(bifrostErr *schemas.BifrostError) {
			if !clientConnected {
				return
			}
			encoded, err := marshalPayload(bifrostErrorPayload(bifrostErr))
			if err == nil {
				_ = reader.sendEvent("", encoded)
			}
		}
		finishSuccess := func() {
			state.MarkProviderCompleted()
			if state != nil && state.Adapter != nil && state.BifrostError == nil && !stogas.HasMeasuredUsage(state) {
				state.BifrostError = stogas.UpstreamProtocolError(stogas.ErrProviderUsageMissing)
				sendStreamError(state.BifrostError)
				return
			}
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
						_ = reader.sendEvent("", encoded)
					}
					return
				}
				encoded := output.Headers[proofhttp.HeaderProof]
				if encoded == "" || !reader.send(frameSSEComment(proofhttp.SSECommentPrefix+encoded)) {
					return
				}
			}
			if sendDone {
				_ = reader.sendDone()
			}
		}

		for {
			var chunk *schemas.BifrostStreamChunk
			select {
			case <-clientClosed:
				clientConnected = false
				if state != nil {
					state.Cancelled = true
					state.MarkClientStopped()
				}
				clientClosed = nil
				continue
			case <-idleC:
				state.MarkProviderCompleted()
				bifrostErr := streamIdleTimeoutError()
				if state != nil {
					state.BifrostError = bifrostErr
				}
				sendStreamError(bifrostErr)
				return
			case next, ok := <-stream:
				if !ok {
					finishSuccess()
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
			resetIdleTimer()

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
				if state != nil {
					state.ObserveChatProviderOutput(chatResponse)
				}
				if !includeChatUsage && chatResponse.Usage != nil {
					if len(chatResponse.Choices) == 0 {
						if terminal {
							finishSuccess()
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
				if state != nil {
					state.ObserveResponsesProviderOutput(chunk.BifrostResponsesStreamResponse)
				}
				normalized := chunk.BifrostResponsesStreamResponse.WithDefaults()
				if normalized == nil {
					if terminal {
						finishSuccess()
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
			responseBytes += len(frame)
			if !clientConnected {
				if terminal {
					finishSuccess()
					return
				}
				continue
			}
			if !reader.send(frame) {
				clientConnected = false
				clientClosed = nil
				if terminal {
					finishSuccess()
					return
				}
				continue
			}
			if streamProof != nil {
				streamProof.WriteSentChunk(frame)
			}
			if terminal {
				finishSuccess()
				return
			}
		}
	}()

	if headers, ok := bifrostCtx.Value(schemas.BifrostContextKeyProviderResponseHeaders).(map[string]string); ok {
		s.forwardProviderHeaders(ctx, bifrostCtx, schemas.BifrostResponseExtraFields{ProviderResponseHeaders: headers})
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	if session := encryptedSession(ctx); session != nil {
		if err := s.sealStreamingEncryptedResponse(ctx, session, reader); err != nil {
			reader.done()
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

func streamIdleTimeoutError() *schemas.BifrostError {
	statusCode := fasthttp.StatusGatewayTimeout
	errorType := schemas.RequestTimedOut
	code := "stream_idle_timeout"
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
	if s.readinessServer != nil {
		_ = s.readinessServer.Shutdown()
	}
	if s.server != nil {
		_ = s.server.Shutdown()
	}
	s.catalogUpdater.Close()
	if s.runtime != nil {
		s.runtime.Close()
	}
	if s.secure != nil {
		s.secure.Close()
	}
	if s.logger != nil {
		s.logger.Info("gateway shutdown complete")
	}
}
