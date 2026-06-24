package stogashttp

import (
	"context"

	"github.com/bytedance/sonic"
	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/valyala/fasthttp"
)

func (s *Server) health(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	_, _ = ctx.WriteString(`{"ok":true,"catalogVersion":"` + catalog.PublicCatalogVersion + `"}`)
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
	if err := adapter.ResolveDeployment(state); err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}
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
	if len(state.UpstreamRequestHeaders) > 0 {
		bifrostCtx.SetValue(schemas.BifrostContextKeyExtraHeaders, state.UpstreamRequestHeaders)
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
		stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		if bifrostErr != nil {
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostErr)
			return
		}

		s.forwardProviderHeaders(ctx, bifrostCtx, response.ExtraFields)
		s.writeJSON(ctx, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
	case schemas.ResponsesRequest:
		defer cancel()
		response, bifrostErr := s.runtime.Client().ResponsesRequest(bifrostCtx, bifrostReq.ResponsesRequest)
		if response != nil {
			response = response.WithDefaults()
		}
		stateResponse := &schemas.BifrostResponse{ResponsesResponse: response}
		_ = adapter.IngestResponse(state, stateResponse, bifrostErr)
		_ = adapter.SanitizeResponse(state)
		stogas.FinalizeState(context.WithoutCancel(bifrostCtx), s.runtime.Billing(), state)
		if bifrostErr != nil {
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostErr)
			return
		}

		s.forwardProviderHeaders(ctx, bifrostCtx, response.ExtraFields)
		s.writeJSON(ctx, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
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

		for {
			var chunk *schemas.BifrostStreamChunk
			select {
			case <-reader.closed():
				return
			case next, ok := <-stream:
				if !ok {
					if meta := metadata.metadata(bifrostCtx); len(meta) > 0 {
						encoded, err := marshalPayload(meta)
						if err != nil || !reader.sendEvent("stogas.meta", encoded) {
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

			if chunk == nil {
				continue
			}
			if state != nil && state.Adapter != nil {
				_ = state.Adapter.IngestChunk(state, chunk)
			}

			if chunk.BifrostError != nil {
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
				metadata.add(extra)
				payload = publicResponsePayload(bifrostCtx, chunk.BifrostChatResponse, extra)
			case chunk.BifrostResponsesStreamResponse != nil:
				eventName = string(chunk.BifrostResponsesStreamResponse.Type)
				extra := chunk.BifrostResponsesStreamResponse.ExtraFields
				metadata.add(extra)
				payload = publicResponsePayload(bifrostCtx, chunk.BifrostResponsesStreamResponse.WithDefaults(), extra)
			default:
				continue
			}

			encoded, err := marshalPayload(payload)
			if err != nil {
				return
			}

			if !reader.sendEvent(streamEventName(includeEventName, eventName), encoded) {
				return
			}
		}
	}()

	if headers, ok := bifrostCtx.Value(schemas.BifrostContextKeyProviderResponseHeaders).(map[string]string); ok {
		s.forwardProviderHeaders(ctx, bifrostCtx, schemas.BifrostResponseExtraFields{ProviderResponseHeaders: headers})
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
	if s.server != nil {
		_ = s.server.Shutdown()
	}
	if s.logger != nil {
		s.logger.Info("gateway shutdown complete")
	}
}
