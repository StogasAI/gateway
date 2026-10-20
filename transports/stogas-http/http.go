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

// The LB stops sending new connections to an unready gateway, but clients keep
// the ones they have. A refusal tells the SDK that this gateway did not process
// the request, so it retires the session or connection and sends the request
// again through a new one. An encrypted response carries the mark inside the
// session, where no proxy can add it. Otherwise HTTP/1 closes after this
// response and HTTP/2 sends GOAWAY and finishes its other streams.
func (s *Server) rejectAdmission(ctx *requestContext) {
	if response, ok := ctx.writer.(*sessionResponse); ok {
		response.refused = true
	} else {
		ctx.writer.Header().Set("Connection", "close")
		ctx.writer.Header().Set("Stogas-Refused", "?1")
	}
	code, message := "gateway_unavailable", "Gateway is temporarily unavailable"
	if s.requests.diagnostics().Draining {
		code, message = "gateway_draining", "Gateway is draining"
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
	// Preparation charges its peak until the run releases its input. A request
	// that fails first keeps that charge until finalization releases its state.
	preparation := s.memory.newLease(requestLifetimeMemory)
	requestComplete := true
	defer func() {
		if requestComplete {
			clear(ctx.body)
			ctx.body = nil
			preparation.release()
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
		if !requestComplete {
			return
		}
		finalize := ctx.finalize
		if finalize == nil {
			s.requests.end()
			return
		}
		// Settlement waits on the database. The caller gets the response first;
		// the request keeps its admission and memory until then.
		requestComplete = false
		body := ctx.body
		ctx.body = nil
		go func() {
			defer lease.release()
			defer preparation.release()
			defer s.requests.end()
			finalize()
			clear(body)
		}()
	}()

	if !preparation.grow(int(requestPreparationWeight(len(ctx.body), cap(ctx.body)))) {
		s.writeRequestMemoryCapacity(ctx)
		return
	}
	run := s.startRun(ctx, requestStartedAt, preparation)
	if run == nil {
		return
	}
	// Later pairs read the received body until the run releases its plan. The
	// provider's converted request can also borrow it, so it is never cleared.
	ctx.body = nil
	if requestType := run.state.Resolution.RequestType; requestType == schemas.ChatCompletionStreamRequest || requestType == schemas.ResponsesStreamRequest {
		started, pending := runProvider(ctx, run, s.openProviderStream, true)
		if pending == nil && (!started.called || started.failure != nil) {
			s.failRun(ctx, run, started.panic == nil)
			if started.panic != nil {
				panic(started.panic)
			}
			return
		}
		requestComplete = false
		reader := s.startSSEStream(ctx, run, started, pending, s.openProviderStream, func() {
			s.requests.end()
			lease.release()
		})
		if reader != nil {
			s.writeStream(ctx, reader)
		}
		return
	}
	result, pending := runProvider(ctx, run, s.callProvider, false)
	ctx.finishClientWait()
	if ctx.responseWait.timedOut() {
		retainResponseFailure(run.state, requestTimeoutError())
	}
	if pending != nil {
		requestComplete = false
		// Transfer the provider call, state, and admission together. No
		// response writer or encrypted response survives in this owner.
		go s.finishDetachedUnary(run, lease, pending, s.requests.end)
		if ctx.responseWait.timedOut() {
			s.writeBifrostError(ctx, requestTimeoutError())
		}
		return
	}
	if !result.called || result.failure != nil {
		s.failRun(ctx, run, result.panic == nil)
		if result.panic != nil {
			panic(result.panic)
		}
		return
	}
	run.commit()
	s.finalizeAfterResponse(ctx, run, result.ctx)
	outcome, failure := ingestProviderResult(lease, run.request, run.state, result.response, nil)
	if ctx.responseWait.timedOut() {
		failure = requestTimeoutError()
	}
	if failure != nil {
		captureUnaryResult(result.ctx, run.state, result.response, outcome)
		s.writeProviderError(ctx, result.ctx, failure)
		return
	}
	s.writeInferenceJSON(ctx, result.ctx, run.state, http.StatusOK, unaryResponsePayload(result.ctx, result.response))
}

func (s *Server) openProviderStream(ctx *schemas.BifrostContext, request *schemas.BifrostRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	if request.ChatRequest != nil {
		return s.runtime.Client().ChatCompletionStreamRequest(ctx, request.ChatRequest)
	}
	return s.runtime.Client().ResponsesStreamRequest(ctx, request.ResponsesRequest)
}

func (s *Server) callProvider(ctx *schemas.BifrostContext, request *schemas.BifrostRequest) (*schemas.BifrostResponse, *schemas.BifrostError) {
	if request.ChatRequest != nil {
		response, failure := s.runtime.Client().ChatCompletionRequest(ctx, request.ChatRequest)
		return &schemas.BifrostResponse{ChatResponse: response}, failure
	}
	response, failure := s.runtime.Client().ResponsesRequest(ctx, request.ResponsesRequest)
	return &schemas.BifrostResponse{ResponsesResponse: response}, failure
}

// failRun ends a run without a provider response and, when respond is set,
// answers the caller with the failure that the run reports.
func (s *Server) failRun(ctx *requestContext, run *providerRun, respond bool) {
	ctx.finishClientWait()
	failure, outcome := run.end()
	if failure == nil {
		if run.state.Authorization != nil {
			s.finalizeAfterResponse(ctx, run, run.request)
		} else {
			stogas.FinalizeExportState(run.request, run.state)
			run.cancel()
		}
		if respond && !cancelledLocally(run.local) {
			s.writeLocalError(ctx, run.local)
		}
		return
	}
	failure, callerFailure := ingestProviderResult(ctx.memory, run.request, run.state, nil, failure)
	captureExportError(run.state, failure)
	if ctx.responseWait.timedOut() {
		callerFailure = requestTimeoutError()
		retainResponseFailure(run.state, callerFailure)
	}
	s.finalizeAfterResponse(ctx, run, outcome)
	if respond {
		s.writeProviderError(ctx, outcome, callerFailure)
	}
}

// finalizeAfterResponse settles the request once its response is complete.
// outcome is the context of the call whose result the request reports.
func (s *Server) finalizeAfterResponse(ctx *requestContext, run *providerRun, outcome *schemas.BifrostContext) {
	ctx.finalize = func() {
		run.cancel()
		stogas.FinalizeState(context.WithoutCancel(outcome), s.runtime.Billing(), run.state)
	}
}

// ingestProviderResult returns the provider outcome, nil for a valid
// response, and the caller's failure, which also includes local processing
// errors.
func ingestProviderResult(memory *requestMemoryLease, request *schemas.BifrostContext, state *stogas.State, response *schemas.BifrostResponse, failure *schemas.BifrostError) (outcome, callerFailure *schemas.BifrostError) {
	state.MarkProviderCompleted()
	if err := state.Adapter.IngestResponse(state, response, failure); err != nil {
		failure = stogas.UpstreamProtocolError(err)
		state.BifrostError = failure
	} else if failure == nil {
		if err := stogas.ValidateCompletedExecution(state); err != nil {
			failure = stogas.UpstreamProtocolError(err)
			state.BifrostError = failure
		}
	}
	if request.Err() == context.DeadlineExceeded {
		failure = requestTimeoutError()
		state.BifrostError = failure
	}
	failure = providerResponseMemoryError(memory, state, failure)
	stogas.PrepareFinalState(state)
	if failure != nil {
		return failure, failure
	}
	return nil, state.ResponseError()
}

func unaryResponsePayload(ctx *schemas.BifrostContext, response *schemas.BifrostResponse) any {
	if response.ChatResponse != nil {
		return publicResponsePayload(ctx, response.ChatResponse, response.ChatResponse.ExtraFields)
	}
	value := response.ResponsesResponse.WithDefaults()
	value.Store, value.Background = schemas.Ptr(false), schemas.Ptr(false)
	return publicResponsePayload(ctx, value, value.ExtraFields)
}

// finishDetachedUnary owns a unary call after its caller stopped waiting. It
// makes no other call, because nobody waits for one.
func (s *Server) finishDetachedUnary(run *providerRun, memory *requestMemoryLease, pending <-chan providerResult[*schemas.BifrostResponse], complete func()) {
	defer complete()
	defer memory.release()
	defer run.cancel()
	outcome := run.request
	defer func() { stogas.FinalizeState(context.WithoutCancel(outcome), s.runtime.Billing(), run.state) }()
	result := <-pending
	switch {
	case !result.called:
		run.stopped()
	case result.failure != nil:
		run.failed(result.failure, result.ctx)
	default:
		run.commit()
		outcome = result.ctx
		failure, _ := ingestProviderResult(memory, run.request, run.state, result.response, nil)
		captureUnaryResult(result.ctx, run.state, result.response, failure)
		return
	}
	failure, attempt := run.end()
	if failure == nil {
		return
	}
	outcome = attempt
	failure, _ = ingestProviderResult(memory, run.request, run.state, nil, failure)
	captureUnaryResult(attempt, run.state, nil, failure)
}

// startSSEStream delivers the run's stream. A pending call is still starting;
// until one starts, the writer makes the retries and fallback calls that the
// run allows while the caller waits.
func (s *Server) startSSEStream(ctx *requestContext, run *providerRun, started providerStreamStart, pending <-chan providerStreamStart, open providerCall[chan *schemas.BifrostStreamChunk], completion func()) io.ReadCloser {
	state, request := run.state, run.request
	stream, outcome := started.response, started.ctx
	if pending == nil {
		run.commit()
	} else {
		outcome = request
	}
	sendDone := state.Resolution.Route == catalog.RouteChat
	includeEventName := !sendDone
	wait, memory, stopObservation := ctx.responseWait, ctx.memory, ctx.stopClientObservation
	deliveryStopped := ctx.request.Context().Err() != nil || wait.timedOut()
	completedAsync := false
	defer func() {
		if !completedAsync {
			completion()
		}
	}()
	var streamProof *proofhttp.Stream
	var deliveryFailure *schemas.BifrostError
	if wait.timedOut() {
		deliveryFailure = requestTimeoutError()
	} else if !deliveryStopped {
		var err error
		streamProof, err = s.newStreamProof(ctx, outcome, state)
		if err != nil {
			deliveryFailure = responseProofFailure()
			deliveryStopped = true
		}
	}
	if deliveryFailure != nil {
		retainResponseFailure(state, deliveryFailure)
	}
	if deliveryStopped {
		ctx.finishClientWait()
	}
	responseMemory := memory.newRetainedLease(streamStateMemory)
	deliveryMemory := memory.newRetainedLease(downstreamDeliveryMemory)
	reader := newSSEStreamReader(deliveryMemory)
	if deliveryStopped {
		_ = reader.Close()
	}
	includeChatUsage := clientRequestedChatStreamUsage(state)
	completedAsync = true

	go func() {
		defer completion()
		defer responseMemory.release()
		defer func() { stogas.FinalizeState(context.WithoutCancel(outcome), s.runtime.Billing(), state) }()
		defer func() { finishProviderStream(run.cancel, pending, stream) }()
		// Finish downstream delivery independently of provider teardown. Provider
		// admission and retained state remain charged until teardown completes.
		finishDelivery := func() {
			wait.stop()
			if stopObservation != nil {
				stopObservation()
			}
			reader.done()
		}
		defer finishDelivery()

		keepalive := time.NewTimer(responseKeepaliveInterval)
		defer keepalive.Stop()
		keepaliveC := keepalive.C
		deliveryContext := wait.deliveryContext(request)
		if pending != nil && !deliveryStopped {
			reader.sendUnreserved(deliveryContext, frameSSEComment("STOGAS PROCESSING"))
		}
		clientConnected := !deliveryStopped
		clientClosed := reader.closed()
		deadlineDone := wait.done()
		if deliveryStopped {
			clientClosed, deadlineDone, keepaliveC = nil, nil, nil
		}
		providerDone := request.Done()
		responseBytes := 0
		sendClientError := func(bifrostErr *schemas.BifrostError) {
			bifrostErr = providerResponseMemoryError(memory, state, bifrostErr)
			if !clientConnected {
				return
			}
			encoded, err := marshalPayload(bifrostErrorPayload(bifrostErr))
			if err == nil {
				_ = reader.sendErrorEvent(request, "", encoded)
				clear(encoded)
			}
		}
		// Export events keep provider output and the failure that ended it.
		// Caller timeouts and receipt failures end only delivery; the canonical
		// event records them.
		sendStreamError := func(bifrostErr *schemas.BifrostError) {
			wait.stop()
			if state.Export.Active() {
				encoded, err := marshalPayload(bifrostErrorPayload(providerResponseMemoryError(memory, state, bifrostErr)))
				if err == nil {
					state.Export.Event(encoded)
					clear(encoded)
				}
			}
			if wait.timedOut() && clientConnected {
				bifrostErr = requestTimeoutError()
				retainResponseFailure(state, bifrostErr)
			}
			sendClientError(bifrostErr)
		}
		// A run that reached no provider ends with its local failure, which
		// a departed caller does not need.
		sendLocalError := func(err error) {
			wait.stop()
			if cancelledLocally(err) {
				return
			}
			encoded, marshalErr := marshalPayload(localErrorResponse(err).payload)
			if marshalErr != nil {
				return
			}
			defer clear(encoded)
			state.Export.Event(encoded)
			if wait.timedOut() && clientConnected {
				failure := requestTimeoutError()
				retainResponseFailure(state, failure)
				sendClientError(failure)
			} else if clientConnected {
				_ = reader.sendErrorEvent(request, "", encoded)
			}
		}
		finishRequestTimeout := func() {
			bifrostErr := requestTimeoutError()
			state.BifrostError = bifrostErr
			sendStreamError(bifrostErr)
		}
		stopDelivery := func() {
			clientConnected = false
			clientClosed, deadlineDone, keepaliveC = nil, nil, nil
			finishDelivery()
		}
		finishClientTimeout := func() {
			wait.stop()
			failure := requestTimeoutError()
			retainResponseFailure(state, failure)
			sendClientError(failure)
			stopDelivery()
		}
		finishSuccess := func(pendingTerminal []byte) {
			defer func() { clear(pendingTerminal) }()
			wait.stop()
			if wait.timedOut() && clientConnected {
				finishClientTimeout()
			}
			if request.Err() == context.DeadlineExceeded {
				finishRequestTimeout()
				stopDelivery()
			}
			state.MarkProviderCompleted()
			if state.Adapter != nil && state.BifrostError == nil {
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
				streamProof.SetMetadata(stogas.FinalMetadata(outcome, state))
				output, err := s.proofs.FinishStream(request, streamProof)
				if err != nil || output == nil || len(output.JSON) == 0 {
					proofFailure := responseProofFailure()
					retainResponseFailure(state, proofFailure)
					sendClientError(proofFailure)
					return
				}
				state.Export.Metadata(output.JSON)
				sent, _ := reader.send(deliveryContext, frameSSEComment(proofhttp.SSECommentPrefix+string(output.JSON)))
				if !sent {
					return
				}
			}
			if len(pendingTerminal) > 0 {
				sent, _ := reader.send(deliveryContext, pendingTerminal)
				if !sent {
					return
				}
				pendingTerminal = nil // The delivery reader now owns the frame.
			}
			if sendDone {
				_ = reader.sendDone(deliveryContext)
			}
		}

		for {
			var chunk *schemas.BifrostStreamChunk
			select {
			case <-providerDone:
				providerDone = nil
				finishRequestTimeout()
				stopDelivery()
				continue
			case <-deadlineDone:
				finishClientTimeout()
				continue
			case started := <-pending:
				pending = nil
				switch {
				case started.panic != nil:
					run.failed(started.failure, started.ctx)
				case !started.called:
					run.stopped()
				case started.failure != nil:
					if delay, again := run.next(started.failure, started.ctx); again {
						pending = startProviderCall(run, delay, open)
						continue
					}
				default:
					run.commit()
					outcome, stream = started.ctx, started.response
					if stream == nil {
						finishSuccess(nil)
						return
					}
					continue
				}
				failure, attempt := run.end()
				if failure == nil {
					sendLocalError(run.local)
					return
				}
				outcome = attempt
				_, failure = ingestProviderResult(memory, request, state, nil, failure)
				sendStreamError(failure)
				return
			case <-keepaliveC:
				if clientConnected {
					sent, _ := reader.send(deliveryContext, frameSSEComment("STOGAS PROCESSING"))
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
				state.MarkClientStopped()
				stopDelivery()
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
			if state.Adapter != nil {
				if err := state.Adapter.IngestChunk(state, chunk); err != nil {
					state.MarkProviderCompleted()
					bifrostErr := stogas.UpstreamProtocolError(err)
					state.BifrostError = bifrostErr
					sendStreamError(bifrostErr)
					return
				}
				wait.observe(state.LastOutputAt)
				if wait.timedOut() && clientConnected {
					finishClientTimeout()
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

				extra := chatResponse.ExtraFields
				payload = publicResponsePayload(request, chatResponse, extra)
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
				payload = publicResponsePayload(request, normalized, extra)
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
			state.Export.Event(encoded)
			// Exports retain forced upstream usage even when the caller omits it.
			if chat := chunk.BifrostChatResponse; chat != nil && !includeChatUsage && chat.Usage != nil {
				clear(encoded)
				if len(chat.Choices) == 0 {
					if terminal {
						finishSuccess(nil)
						return
					}
					continue
				}
				filtered := *chat
				filtered.Usage = nil
				encoded, err = marshalPayload(publicResponsePayload(request, &filtered, filtered.ExtraFields))
				if err != nil {
					failure := responseEncodingFailure()
					state.MarkProviderCompleted()
					retainResponseFailure(state, failure)
					sendStreamError(failure)
					return
				}
			}
			frame := frameSSEEvent(streamEventName(includeEventName, eventName), encoded)
			clear(encoded)
			if inferenceStreamResponseLimitExceeded(responseBytes, len(frame)) {
				clear(frame)
				bifrostErr := stogas.UpstreamProtocolError(stogas.ErrProviderResponseTooLarge)
				state.MarkProviderCompleted()
				state.BifrostError = bifrostErr
				sendStreamError(bifrostErr)
				return
			}
			if !responseMemory.grow(len(frame)) {
				clear(frame)
				bifrostErr := streamMemoryCapacityError()
				state.MarkProviderCompleted()
				retainResponseFailure(state, bifrostErr)
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
			sent, deliveryCapacityExceeded := reader.send(deliveryContext, frame)
			if !sent {
				if deliveryCapacityExceeded {
					clear(frame)
					bifrostErr := streamMemoryCapacityError()
					state.MarkProviderCompleted()
					retainResponseFailure(state, bifrostErr)
					sendStreamError(bifrostErr)
					return
				}
				if wait.timedOut() {
					finishClientTimeout()
				} else if request.Err() != nil {
					finishRequestTimeout()
					stopDelivery()
				} else {
					state.MarkClientStopped()
					stopDelivery()
				}
				if terminal {
					finishSuccess(nil)
					return
				}
				continue
			}
			keepalive.Reset(responseKeepaliveInterval)
			if chunk.BifrostChatResponse != nil {
				state.ObserveChatStreamOutput(chunk.BifrostChatResponse)
			} else if chunk.BifrostResponsesStreamResponse != nil {
				state.ObserveResponsesStreamOutput(chunk.BifrostResponsesStreamResponse)
			}
			if terminal {
				finishSuccess(nil)
				return
			}
		}
	}()

	if deliveryFailure != nil {
		s.writeBifrostError(ctx, deliveryFailure)
		return nil
	}
	if deliveryStopped {
		return nil
	}
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

func providerResponseMemoryError(memory *requestMemoryLease, state *stogas.State, failure *schemas.BifrostError) *schemas.BifrostError {
	if memory == nil || !memory.responseFailed.Load() {
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

func requestTimeoutError() *schemas.BifrostError {
	statusCode := http.StatusGatewayTimeout
	errorType := schemas.RequestTimedOut
	code := "request_timeout"
	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &statusCode,
		Type:           &errorType,
		AllowFallbacks: schemas.Ptr(false),
		Error: &schemas.ErrorField{
			Type:    &errorType,
			Code:    &code,
			Message: "The request exceeded its time limit.",
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
	// The last loaded list keeps refusing sanctioned clients while requests drain.
	s.sanctionedNetworks.close()
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
