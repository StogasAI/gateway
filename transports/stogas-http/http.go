package stogashttp

import (
	"context"
	"time"

	"github.com/bytedance/sonic"
	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"github.com/valyala/fasthttp"
)

func (s *Server) health(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	_, _ = ctx.WriteString(`{"ok":true,"catalogVersion":"` + catalog.PublicCatalogVersion + `"}`)
}

func (s *Server) readiness(ctx *fasthttp.RequestCtx) {
	if s == nil || s.secure == nil {
		ctx.SetStatusCode(fasthttp.StatusNoContent)
		return
	}
	result := s.secure.Readiness()
	if result.Ready {
		ctx.SetStatusCode(fasthttp.StatusNoContent)
		return
	}
	ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
	ctx.SetContentType("application/json")
	_, _ = ctx.WriteString(`{"ok":false}`)
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
	credential, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return
	}

	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Body:   ctx.Request.Body(),
		Method: string(ctx.Method()),
		Path:   string(ctx.Path()),
	})
	if err != nil {
		s.writeCatalogError(ctx, err)
		return
	}

	adapter := stogas.AdapterFor(resolution.Provider)
	bifrostCtx, state, cancel, err := newRequestContext(ctx, resolution, credential, adapter)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "invalid_request_error"},
		})
		return
	}
	state.ReleaseMeasurement = stogas.ReleaseMeasurementForLog(s.config.Confidential.ReleaseMeasurement)
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
	bifrostReq, err := resolution.ToBifrost(bifrostCtx)
	if err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}

	if err := dryRunProviderRequestMarshal(bifrostCtx, bifrostReq); err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}
	processedRequestJSON, err := sonic.Marshal(bifrostReq)
	if err != nil {
		cancel()
		s.writeCatalogError(ctx, invalidProviderRequest())
		return
	}
	state.ProcessedRequestJSON = processedRequestJSON
	if err := adapter.EstimateHold(state); err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}

	if err := stogas.AuthorizeState(bifrostCtx, s.runtime.Billing(), state); err != nil {
		cancel()
		s.writeBillingError(ctx, err)
		return
	}

	switch resolution.RequestType {
	case schemas.ChatCompletionStreamRequest:
		stream, bifrostErr := s.runtime.Client().ChatCompletionStreamRequest(bifrostCtx, bifrostReq.ChatRequest)
		if bifrostErr != nil {
			_ = adapter.IngestResponse(state, nil, bifrostErr)
			stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
			cancel()
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostErr)
			return
		}
		s.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
		return
	case schemas.ResponsesStreamRequest:
		stream, bifrostErr := s.runtime.Client().ResponsesStreamRequest(bifrostCtx, bifrostReq.ResponsesRequest)
		if bifrostErr != nil {
			_ = adapter.IngestResponse(state, nil, bifrostErr)
			stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
			cancel()
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostErr)
			return
		}
		s.writeSSEStream(ctx, bifrostCtx, state, stream, false, true, cancel)
		return
	case schemas.ChatCompletionRequest:
		defer cancel()
		response, bifrostErr := s.runtime.Client().ChatCompletionRequest(bifrostCtx, bifrostReq.ChatRequest)
		stateResponse := &schemas.BifrostResponse{ChatResponse: response}
		_ = adapter.IngestResponse(state, stateResponse, bifrostErr)
		_ = adapter.SanitizeResponse(state)
		if response != nil {
			state.ObserveUnaryProviderLatency(response.ExtraFields)
		}
		state.MarkFirstByte()
		stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		if bifrostErr != nil {
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostErr)
			return
		}

		s.forwardProviderHeaders(ctx, bifrostCtx, response.ExtraFields)
		s.writeInferenceJSON(ctx, bifrostCtx, state, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
	case schemas.ResponsesRequest:
		defer cancel()
		response, bifrostErr := s.runtime.Client().ResponsesRequest(bifrostCtx, bifrostReq.ResponsesRequest)
		if response != nil {
			response = response.WithDefaults()
		}
		stateResponse := &schemas.BifrostResponse{ResponsesResponse: response}
		_ = adapter.IngestResponse(state, stateResponse, bifrostErr)
		_ = adapter.SanitizeResponse(state)
		if response != nil {
			state.ObserveUnaryProviderLatency(response.ExtraFields)
		}
		state.MarkFirstByte()
		stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		if bifrostErr != nil {
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostErr)
			return
		}

		s.forwardProviderHeaders(ctx, bifrostCtx, response.ExtraFields)
		s.writeInferenceJSON(ctx, bifrostCtx, state, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
	default:
		cancel()
		s.writeCatalogError(ctx, catalog.ErrUnsupportedRequest)
	}
}

func dryRunProviderRequestMarshal(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) error {
	if req == nil {
		return catalog.ErrUnsupportedRequest
	}
	switch {
	case req.ChatRequest != nil:
		switch req.ChatRequest.Provider {
		case schemas.OpenAI:
			converted := openaiprovider.ToOpenAIChatRequest(ctx, req.ChatRequest)
			if converted == nil {
				return invalidProviderRequest()
			}
			if _, err := sonic.Marshal(converted); err != nil {
				return invalidProviderRequest()
			}
		case schemas.Anthropic:
			converted, err := anthropicprovider.ToAnthropicChatRequest(ctx, req.ChatRequest)
			if err != nil || converted == nil {
				return invalidProviderRequest()
			}
			if _, err := sonic.Marshal(converted); err != nil {
				return invalidProviderRequest()
			}
		default:
			if _, err := sonic.Marshal(req.ChatRequest); err != nil {
				return invalidProviderRequest()
			}
		}
	case req.ResponsesRequest != nil:
		switch req.ResponsesRequest.Provider {
		case schemas.OpenAI:
			converted := openaiprovider.ToOpenAIResponsesRequest(req.ResponsesRequest)
			if converted == nil {
				return invalidProviderRequest()
			}
			if _, err := sonic.Marshal(converted); err != nil {
				return invalidProviderRequest()
			}
		case schemas.Anthropic:
			if _, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(ctx, req.ResponsesRequest, anthropicprovider.AnthropicRequestBuildConfig{
				Provider:    schemas.Anthropic,
				IsStreaming: req.RequestType == schemas.ResponsesStreamRequest,
			}); bifrostErr != nil {
				return invalidProviderRequest()
			}
		default:
			if _, err := sonic.Marshal(req.ResponsesRequest); err != nil {
				return invalidProviderRequest()
			}
		}
	default:
		return catalog.ErrUnsupportedRequest
	}
	return nil
}

func invalidProviderRequest() error {
	return catalog.APIError{StatusCode: fasthttp.StatusBadRequest, Type: catalog.ErrorTypeInvalidRequest, Message: "Invalid request for selected provider"}
}

func (s *Server) writeSSEStream(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, state *stogas.State, stream chan *schemas.BifrostStreamChunk, sendDone bool, includeEventName bool, cancel context.CancelFunc) {
	streamProof, proofErr := s.newStreamProof(state)
	if proofErr != nil {
		s.writeProofError(ctx)
		cancel()
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	reader := newSSEStreamReader()
	ctx.Response.SetBodyStream(reader, -1)

	go func() {
		defer reader.done()
		defer stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		defer cancel()

		metadata := newStreamMetadataAccumulator(bifrostCtx)
		clientConnected := true
		clientClosed := reader.closed()
		idleTimeout := streamIdleTimeout(state)
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

		for {
			var chunk *schemas.BifrostStreamChunk
			select {
			case <-clientClosed:
				clientConnected = false
				clientClosed = nil
				continue
			case <-idleC:
				bifrostErr := streamIdleTimeoutError()
				if state != nil {
					state.BifrostError = bifrostErr
				}
				if clientConnected {
					encoded, err := marshalPayload(bifrostErrorPayload(bifrostErr))
					if err == nil {
						_ = reader.sendEvent("", encoded)
					}
				}
				return
			case next, ok := <-stream:
				if !ok {
					if !clientConnected {
						return
					}
					if meta := metadata.metadata(bifrostCtx); len(meta) > 0 {
						encoded, err := marshalPayload(meta)
						if err != nil || !reader.sendEvent("stogas.meta", encoded) {
							return
						}
					}
					if streamProof != nil {
						output, err := s.proofs.FinishStream(bifrostCtx, streamProof)
						if err != nil {
							encoded, encodeErr := marshalPayload(map[string]any{
								"error": map[string]any{
									"message": "Failed to build confidential response proof",
									"type":    "internal_error",
								},
							})
							if encodeErr == nil {
								_ = reader.sendEvent("", encoded)
							}
							return
						}
						encoded, err := marshalPayload(output.Object)
						if err != nil || !reader.sendEvent(proofhttp.SSEEventName, encoded) {
							return
						}
					}

					if sendDone {
						_ = reader.sendDone()
					}
					return
				}
				chunk = next
			}

			resetIdleTimer()
			if chunk == nil {
				continue
			}
			if state != nil && state.Adapter != nil {
				_ = state.Adapter.IngestChunk(state, chunk)
			}

			if chunk.BifrostError != nil {
				if !clientConnected {
					return
				}
				payload := bifrostErrorPayload(chunk.BifrostError)
				encoded, err := marshalPayload(payload)
				if err != nil {
					return
				}
				_ = reader.sendEvent("", encoded)
				return
			}

			var (
				eventName string
				payload   any
			)

			switch {
			case chunk.BifrostChatResponse != nil:
				eventName = ""
				extra := chunk.BifrostChatResponse.ExtraFields
				if state != nil {
					state.ObserveProviderTTFB(extra.Latency)
				}
				metadata.add(extra)
				payload = publicResponsePayload(bifrostCtx, chunk.BifrostChatResponse, extra)
			case chunk.BifrostResponsesStreamResponse != nil:
				eventName = string(chunk.BifrostResponsesStreamResponse.Type)
				extra := chunk.BifrostResponsesStreamResponse.ExtraFields
				if state != nil {
					state.ObserveProviderTTFB(extra.Latency)
				}
				metadata.add(extra)
				payload = publicResponsePayload(bifrostCtx, chunk.BifrostResponsesStreamResponse.WithDefaults(), extra)
			default:
				continue
			}

			if !clientConnected {
				continue
			}
			encoded, err := marshalPayload(payload)
			if err != nil {
				return
			}
			if state != nil {
				state.MarkFirstByte()
			}

			if !reader.sendEvent(streamEventName(includeEventName, eventName), encoded) {
				clientConnected = false
				clientClosed = nil
				continue
			}
			if streamProof != nil {
				streamProof.WriteSentChunk(encoded)
			}
		}
	}()

	if headers, ok := bifrostCtx.Value(schemas.BifrostContextKeyProviderResponseHeaders).(map[string]string); ok {
		s.forwardProviderHeaders(ctx, bifrostCtx, schemas.BifrostResponseExtraFields{ProviderResponseHeaders: headers})
	}
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
	if s.runtime != nil {
		s.runtime.Close()
	}
	if s.secure != nil {
		s.secure.Close()
	}
	if s.server != nil {
		_ = s.server.Shutdown()
	}
	if s.logger != nil {
		s.logger.Info("gateway shutdown complete")
	}
}
