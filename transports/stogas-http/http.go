package stogashttp

import (
	"context"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/valyala/fasthttp"
)

func (s *Server) health(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	_, _ = ctx.WriteString(`{"ok":true}`)
}

func (s *Server) catalogHealth(ctx *fasthttp.RequestCtx) {
	payload, ok := catalog.PublicCatalogPayload()
	if !ok {
		s.writeCatalogError(ctx, catalog.ErrCatalogUnavailable)
		return
	}
	s.writeJSON(ctx, fasthttp.StatusOK, map[string]any{
		"ok":          true,
		"hash":        payload.Hash,
		"schema":      payload.Schema,
		"models":      len(payload.Graph.Models),
		"deployments": len(payload.Graph.Deployments),
		"providers":   len(payload.Graph.Providers),
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

	bifrostCtx, cancel, err := newRequestContext(ctx, resolution)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "invalid_request_error"},
		})
		return
	}
	stogas.SetAPIKey(bifrostCtx, credential.Raw, credential.Claims)

	bifrostReq, err := resolution.ToBifrost(bifrostCtx)
	if err != nil {
		cancel()
		s.writeCatalogError(ctx, err)
		return
	}

	switch resolution.RequestType {
	case schemas.ChatCompletionStreamRequest:
		stream, bifrostErr := s.runtime.Client().ChatCompletionStreamRequest(bifrostCtx, bifrostReq.ChatRequest)
		if bifrostErr != nil {
			cancel()
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
			return
		}
		s.writeSSEStream(ctx, bifrostCtx, stream, true, false, cancel)
		return
	case schemas.ResponsesStreamRequest:
		stream, bifrostErr := s.runtime.Client().ResponsesStreamRequest(bifrostCtx, bifrostReq.ResponsesRequest)
		if bifrostErr != nil {
			cancel()
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
			return
		}
		s.writeSSEStream(ctx, bifrostCtx, stream, false, true, cancel)
		return
	case schemas.ChatCompletionRequest:
		defer cancel()
		response, bifrostErr := s.runtime.Client().ChatCompletionRequest(bifrostCtx, bifrostReq.ChatRequest)
		if bifrostErr != nil {
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
			return
		}

		s.forwardProviderHeaders(ctx, response.ExtraFields)
		s.writeJSON(ctx, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response.ExtraFields.RawResponse, response, response.ExtraFields))
	case schemas.ResponsesRequest:
		defer cancel()
		response, bifrostErr := s.runtime.Client().ResponsesRequest(bifrostCtx, bifrostReq.ResponsesRequest)
		if bifrostErr != nil {
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
			return
		}

		s.forwardProviderHeaders(ctx, response.ExtraFields)
		s.writeJSON(ctx, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response.ExtraFields.RawResponse, response.WithDefaults(), response.ExtraFields))
	default:
		cancel()
		s.writeCatalogError(ctx, catalog.ErrUnsupportedRequest)
	}
}

func (s *Server) writeSSEStream(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, stream chan *schemas.BifrostStreamChunk, sendDone bool, includeEventName bool, cancel context.CancelFunc) {
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	reader := newSSEStreamReader()
	ctx.Response.SetBodyStream(reader, -1)

	go func() {
		defer reader.done()
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

			if chunk.BifrostError != nil {
				payload := bifrostErrorPayload(bifrostCtx, chunk.BifrostError)
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
				payload = publicResponsePayload(bifrostCtx, extra.RawResponse, chunk.BifrostChatResponse, extra)
			case chunk.BifrostResponsesStreamResponse != nil:
				eventName = string(chunk.BifrostResponsesStreamResponse.Type)
				extra := chunk.BifrostResponsesStreamResponse.ExtraFields
				metadata.add(extra)
				payload = publicResponsePayload(bifrostCtx, extra.RawResponse, chunk.BifrostResponsesStreamResponse.WithDefaults(), extra)
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
		s.forwardProviderHeaders(ctx, schemas.BifrostResponseExtraFields{ProviderResponseHeaders: headers})
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
