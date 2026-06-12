package stogashttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/valyala/fasthttp"
)

type requestWithSettableExtraParams interface {
	SetExtraParams(params map[string]interface{})
}

var textParamsKnownFields = map[string]bool{
	"prompt":            true,
	"model":             true,
	"fallbacks":         true,
	"best_of":           true,
	"echo":              true,
	"frequency_penalty": true,
	"logit_bias":        true,
	"logprobs":          true,
	"max_tokens":        true,
	"n":                 true,
	"presence_penalty":  true,
	"seed":              true,
	"stop":              true,
	"suffix":            true,
	"temperature":       true,
	"top_p":             true,
	"user":              true,
}

var chatParamsKnownFields = map[string]bool{
	"model":                  true,
	"messages":               true,
	"fallbacks":              true,
	"stream":                 true,
	"frequency_penalty":      true,
	"logit_bias":             true,
	"logprobs":               true,
	"max_tokens":             true,
	"max_completion_tokens":  true,
	"metadata":               true,
	"modalities":             true,
	"parallel_tool_calls":    true,
	"prediction":             true,
	"presence_penalty":       true,
	"prompt_cache_key":       true,
	"prompt_cache_retention": true,
	"reasoning":              true,
	"reasoning_display":      true,
	"response_format":        true,
	"safety_identifier":      true,
	"seed":                   true,
	"service_tier":           true,
	"stream_options":         true,
	"stop":                   true,
	"store":                  true,
	"temperature":            true,
	"tool_choice":            true,
	"tools":                  true,
	"top_logprobs":           true,
	"user":                   true,
	"verbosity":              true,
	"web_search_options":     true,
	"reasoning_effort":       true,
	"reasoning_max_tokens":   true,
}

var responsesParamsKnownFields = map[string]bool{
	"model":                  true,
	"input":                  true,
	"fallbacks":              true,
	"stream":                 true,
	"background":             true,
	"conversation":           true,
	"frequency_penalty":      true,
	"include":                true,
	"instructions":           true,
	"max_output_tokens":      true,
	"max_tool_calls":         true,
	"metadata":               true,
	"parallel_tool_calls":    true,
	"presence_penalty":       true,
	"previous_response_id":   true,
	"prompt_cache_key":       true,
	"prompt_cache_retention": true,
	"reasoning":              true,
	"safety_identifier":      true,
	"service_tier":           true,
	"stream_options":         true,
	"store":                  true,
	"temperature":            true,
	"text":                   true,
	"top_logprobs":           true,
	"top_p":                  true,
	"tool_choice":            true,
	"tools":                  true,
	"truncation":             true,
	"user":                   true,
}

func (s *Server) health(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	_, _ = ctx.WriteString(`{"ok":true}`)
}

func (s *Server) textCompletion(ctx *fasthttp.RequestCtx) {
	rawAPIKey, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return
	}

	var request openaiprovider.OpenAITextCompletionRequest
	if err := sonic.Unmarshal(ctx.Request.Body(), &request); err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Invalid JSON body", "type": "invalid_request_error"},
		})
		return
	}
	provider, model := schemas.ParseModelString(request.Model, schemas.OpenAI)
	deployment, ok := catalogModelDeploymentFor(provider, model)
	if !ok {
		s.writeCatalogModelError(ctx)
		return
	}
	request.Model = deployment.model
	if err := setExtraParams(ctx.Request.Body(), textParamsKnownFields, &request, provider, model, stogasRoute("text")); err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Invalid JSON body", "type": "invalid_request_error"},
		})
		return
	}

	requestType := schemas.TextCompletionRequest
	if request.IsStreamingRequested() {
		requestType = schemas.TextCompletionStreamRequest
	}
	bifrostCtx, cancel, err := newRequestContext(ctx, requestType)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "invalid_request_error"},
		})
		return
	}
	stogas.SetAPIKey(bifrostCtx, rawAPIKey)

	requestBody := request.ToBifrostTextCompletionRequest(bifrostCtx)
	if requestBody == nil {
		cancel()
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Invalid text completion request", "type": "invalid_request_error"},
		})
		return
	}
	requestBody.Fallbacks = normalizeFallbacks(request.Fallbacks)
	if !resolveCatalogModel(requestBody.Provider, requestBody.Model) {
		cancel()
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Model is not available", "type": "invalid_request_error"},
		})
		return
	}

	if request.IsStreamingRequested() {
		stream, bifrostErr := s.runtime.Client().TextCompletionStreamRequest(bifrostCtx, requestBody)
		if bifrostErr != nil {
			cancel()
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
			return
		}
		s.writeSSEStream(ctx, bifrostCtx, stream, true, false, cancel)
		return
	}

	defer cancel()
	response, bifrostErr := s.runtime.Client().TextCompletionRequest(bifrostCtx, requestBody)
	if bifrostErr != nil {
		s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
		s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
		return
	}

	s.forwardProviderHeaders(ctx, response.ExtraFields)
	s.writeJSON(ctx, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response.ExtraFields.RawResponse, response, response.ExtraFields))
}

func (s *Server) chatCompletion(ctx *fasthttp.RequestCtx) {
	rawAPIKey, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return
	}

	var request openaiprovider.OpenAIChatRequest
	if err := sonic.Unmarshal(ctx.Request.Body(), &request); err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Invalid JSON body", "type": "invalid_request_error"},
		})
		return
	}
	provider, model := schemas.ParseModelString(request.Model, schemas.OpenAI)
	deployment, ok := catalogModelDeploymentFor(provider, model)
	if !ok || !applyCatalogModelDeployment(&request.Model, &request.ChatParameters.ServiceTier, deployment) {
		s.writeCatalogModelError(ctx)
		return
	}
	if err := setExtraParams(ctx.Request.Body(), chatParamsKnownFields, &request, provider, model, stogasRouteChat); err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Invalid JSON body", "type": "invalid_request_error"},
		})
		return
	}
	mapLegacyChatMaxTokens(&request)

	requestType := schemas.ChatCompletionRequest
	if request.IsStreamingRequested() {
		requestType = schemas.ChatCompletionStreamRequest
	}
	bifrostCtx, cancel, err := newRequestContext(ctx, requestType)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "invalid_request_error"},
		})
		return
	}
	stogas.SetAPIKey(bifrostCtx, rawAPIKey)

	requestBody := request.ToBifrostChatRequest(bifrostCtx)
	if requestBody == nil {
		cancel()
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Invalid chat completion request", "type": "invalid_request_error"},
		})
		return
	}
	requestBody.Fallbacks = normalizeFallbacks(request.Fallbacks)
	if !resolveCatalogModel(requestBody.Provider, requestBody.Model) {
		cancel()
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Model is not available", "type": "invalid_request_error"},
		})
		return
	}

	if request.IsStreamingRequested() {
		stream, bifrostErr := s.runtime.Client().ChatCompletionStreamRequest(bifrostCtx, requestBody)
		if bifrostErr != nil {
			cancel()
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
			return
		}
		s.writeSSEStream(ctx, bifrostCtx, stream, true, false, cancel)
		return
	}

	defer cancel()
	response, bifrostErr := s.runtime.Client().ChatCompletionRequest(bifrostCtx, requestBody)
	if bifrostErr != nil {
		s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
		s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
		return
	}

	s.forwardProviderHeaders(ctx, response.ExtraFields)
	s.writeJSON(ctx, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response.ExtraFields.RawResponse, response, response.ExtraFields))
}

func (s *Server) responses(ctx *fasthttp.RequestCtx) {
	rawAPIKey, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return
	}

	var request openaiprovider.OpenAIResponsesRequest
	if err := sonic.Unmarshal(ctx.Request.Body(), &request); err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Invalid JSON body", "type": "invalid_request_error"},
		})
		return
	}
	provider, model := schemas.ParseModelString(request.Model, schemas.OpenAI)
	deployment, ok := catalogModelDeploymentFor(provider, model)
	if !ok || !applyCatalogModelDeployment(&request.Model, &request.ResponsesParameters.ServiceTier, deployment) {
		s.writeCatalogModelError(ctx)
		return
	}
	if err := setExtraParams(ctx.Request.Body(), responsesParamsKnownFields, &request, provider, model, stogasRouteResponses); err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Invalid JSON body", "type": "invalid_request_error"},
		})
		return
	}

	requestType := schemas.ResponsesRequest
	if request.IsStreamingRequested() {
		requestType = schemas.ResponsesStreamRequest
	}
	bifrostCtx, cancel, err := newRequestContext(ctx, requestType)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "invalid_request_error"},
		})
		return
	}
	stogas.SetAPIKey(bifrostCtx, rawAPIKey)

	requestBody := request.ToBifrostResponsesRequest(bifrostCtx)
	if requestBody == nil {
		cancel()
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Invalid responses request", "type": "invalid_request_error"},
		})
		return
	}
	requestBody.Fallbacks = normalizeFallbacks(request.Fallbacks)
	if !resolveCatalogModel(requestBody.Provider, requestBody.Model) {
		cancel()
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Model is not available", "type": "invalid_request_error"},
		})
		return
	}

	if request.IsStreamingRequested() {
		stream, bifrostErr := s.runtime.Client().ResponsesStreamRequest(bifrostCtx, requestBody)
		if bifrostErr != nil {
			cancel()
			s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
			s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
			return
		}
		s.writeSSEStream(ctx, bifrostCtx, stream, false, true, cancel)
		return
	}

	defer cancel()
	response, bifrostErr := s.runtime.Client().ResponsesRequest(bifrostCtx, requestBody)
	if bifrostErr != nil {
		s.forwardProviderHeadersFromContext(ctx, bifrostCtx)
		s.writeBifrostError(ctx, bifrostCtx, bifrostErr)
		return
	}

	s.forwardProviderHeaders(ctx, response.ExtraFields)
	s.writeJSON(ctx, fasthttp.StatusOK, publicResponsePayload(bifrostCtx, response.ExtraFields.RawResponse, response.WithDefaults(), response.ExtraFields))
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
					if meta := metadata.metadata(bifrostCtx); len(meta) > 0 && !rawResponsePassthrough(bifrostCtx) {
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
			case chunk.BifrostTextCompletionResponse != nil:
				eventName = ""
				extra := chunk.BifrostTextCompletionResponse.ExtraFields
				metadata.add(extra)
				payload = publicResponsePayload(bifrostCtx, extra.RawResponse, chunk.BifrostTextCompletionResponse, extra)
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

func setExtraParams(body []byte, knownFields map[string]bool, req requestWithSettableExtraParams, provider schemas.ModelProvider, model string, route stogasRoute) error {
	extraParams, err := extractExtraParams(body, knownFields)
	if err != nil {
		return err
	}
	req.SetExtraParams(filterCatalogExtraParams(provider, model, route, extraParams))
	return nil
}

func extractExtraParams(data []byte, knownFields map[string]bool) (map[string]interface{}, error) {
	var rawData map[string]json.RawMessage
	if err := sonic.Unmarshal(data, &rawData); err != nil {
		return nil, err
	}

	extraParams := make(map[string]interface{})
	for key, value := range rawData {
		if knownFields[key] {
			continue
		}
		var decoded any
		if err := sonic.Unmarshal(value, &decoded); err != nil {
			continue
		}
		extraParams[key] = decoded
	}

	return extraParams, nil
}

func mapLegacyChatMaxTokens(request *openaiprovider.OpenAIChatRequest) {
	if request.ChatParameters.MaxCompletionTokens != nil {
		return
	}
	if request.MaxTokens != nil {
		request.ChatParameters.MaxCompletionTokens = request.MaxTokens
		return
	}
	if request.ExtraParams == nil {
		return
	}
	maxTokensVal, exists := request.ExtraParams["max_tokens"]
	if !exists {
		return
	}
	switch value := maxTokensVal.(type) {
	case float64:
		maxTokens := int(value)
		request.ChatParameters.MaxCompletionTokens = &maxTokens
		delete(request.ExtraParams, "max_tokens")
		request.ChatParameters.ExtraParams = request.ExtraParams
	case int:
		request.ChatParameters.MaxCompletionTokens = &value
		delete(request.ExtraParams, "max_tokens")
		request.ChatParameters.ExtraParams = request.ExtraParams
	}
}

func (s *Server) forwardProviderHeadersFromContext(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext) {
	if headers, ok := bifrostCtx.Value(schemas.BifrostContextKeyProviderResponseHeaders).(map[string]string); ok {
		s.forwardProviderHeaders(ctx, schemas.BifrostResponseExtraFields{ProviderResponseHeaders: headers})
	}
}

func normalizeFallbacks(fallbacks []string) []schemas.Fallback {
	if len(fallbacks) == 0 {
		return nil
	}
	normalized := make([]schemas.Fallback, 0, len(fallbacks))
	for _, fallback := range fallbacks {
		if strings.TrimSpace(fallback) == "" {
			continue
		}
		provider, model := schemas.ParseModelString(fallback, schemas.OpenAI)
		if model == "" {
			continue
		}
		normalized = append(normalized, schemas.Fallback{Provider: provider, Model: model})
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func authorizationToken(raw []byte) string {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return ""
	}
	parts := strings.Fields(value)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return value
}

func apiKeyToken(ctx *fasthttp.RequestCtx) string {
	if token := authorizationToken(ctx.Request.Header.Peek("Authorization")); token != "" {
		return token
	}
	for _, header := range []string{"api-key", "x-api-key", "x-goog-api-key"} {
		if token := strings.TrimSpace(string(ctx.Request.Header.Peek(header))); token != "" {
			return token
		}
	}
	return ""
}

func (s *Server) writeBifrostError(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, bifrostErr *schemas.BifrostError) {
	statusCode := fasthttp.StatusInternalServerError
	if bifrostErr != nil && bifrostErr.StatusCode != nil && *bifrostErr.StatusCode > 0 {
		statusCode = *bifrostErr.StatusCode
	}
	s.writeError(ctx, statusCode, bifrostErrorPayload(bifrostCtx, bifrostErr))
}

func bifrostErrorPayload(bifrostCtx *schemas.BifrostContext, bifrostErr *schemas.BifrostError) any {
	if bifrostErr == nil {
		return map[string]any{"error": map[string]any{"message": "Internal server error", "type": "internal_error"}}
	}
	if rawResponsePassthrough(bifrostCtx) && bifrostErr.ExtraFields.RawResponse != nil {
		return bifrostErr.ExtraFields.RawResponse
	}
	message := "Internal server error"
	errorType := "internal_error"
	var code any
	if bifrostErr.Error != nil {
		if bifrostErr.Error.Message != "" {
			message = bifrostErr.Error.Message
		}
		if bifrostErr.Error.Type != nil && *bifrostErr.Error.Type != "" {
			errorType = *bifrostErr.Error.Type
		}
		if bifrostErr.Error.Code != nil && *bifrostErr.Error.Code != "" {
			code = *bifrostErr.Error.Code
		}
		return map[string]any{
			"error": map[string]any{
				"code":    code,
				"message": message,
				"param":   bifrostErr.Error.Param,
				"type":    errorType,
			},
		}
	}
	return map[string]any{"error": map[string]any{"message": message, "type": errorType}}
}

func (s *Server) writeJSON(ctx *fasthttp.RequestCtx, statusCode int, payload any) {
	data, err := marshalPayload(payload)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusInternalServerError, map[string]any{
			"error": map[string]any{"message": "Failed to encode response", "type": "internal_error"},
		})
		return
	}
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")
	_, _ = ctx.Write(data)
}

func (s *Server) requireAPIKey(ctx *fasthttp.RequestCtx) (string, bool) {
	token := apiKeyToken(ctx)
	if token != "" {
		return token, true
	}
	s.writeError(ctx, fasthttp.StatusUnauthorized, map[string]any{
		"error": map[string]any{"message": "Missing API key", "type": "authentication_error"},
	})
	return "", false
}

func (s *Server) requireInferenceEnvelope(ctx *fasthttp.RequestCtx) (string, bool) {
	rawAPIKey, ok := s.requireInferenceHeaders(ctx)
	if !ok {
		return "", false
	}
	if len(ctx.Request.Body()) == 0 {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Request body is required", "type": "invalid_request_error"},
		})
		return "", false
	}
	return rawAPIKey, true
}

func (s *Server) requireInferenceHeaders(ctx *fasthttp.RequestCtx) (string, bool) {
	rawAPIKey, ok := s.requireAPIKey(ctx)
	if !ok {
		return "", false
	}
	if s.runtime != nil {
		if err := s.runtime.ValidateAPIKeyFormat(rawAPIKey); err != nil {
			s.writeError(ctx, fasthttp.StatusUnauthorized, map[string]any{
				"error": map[string]any{"message": "Invalid API key", "type": "authentication_error"},
			})
			return "", false
		}
	}
	if !isJSONContentType(ctx.Request.Header.ContentType()) {
		s.writeError(ctx, fasthttp.StatusUnsupportedMediaType, map[string]any{
			"error": map[string]any{"message": "Content-Type must be application/json", "type": "invalid_request_error"},
		})
		return "", false
	}
	return rawAPIKey, true
}

func isJSONContentType(raw []byte) bool {
	contentType := strings.ToLower(strings.TrimSpace(string(raw)))
	mediaType, _, _ := strings.Cut(contentType, ";")
	return strings.TrimSpace(mediaType) == "application/json"
}

func marshalPayload(payload any) ([]byte, error) {
	switch typed := payload.(type) {
	case []byte:
		return typed, nil
	case string:
		return []byte(typed), nil
	default:
		return sonic.Marshal(payload)
	}
}

func (s *Server) writeError(ctx *fasthttp.RequestCtx, statusCode int, payload any) {
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")
	data, err := sonic.Marshal(payload)
	if err != nil {
		ctx.Response.SetBodyString(`{"error":{"message":"Failed to encode error","type":"internal_error"}}`)
		return
	}
	_, _ = ctx.Write(data)
}

func (s *Server) writeCatalogModelError(ctx *fasthttp.RequestCtx) {
	s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
		"error": map[string]any{"message": "Model is not available", "type": "invalid_request_error"},
	})
}

func (s *Server) forwardProviderHeaders(ctx *fasthttp.RequestCtx, extra schemas.BifrostResponseExtraFields) {
	headers := filterCatalogProviderResponseHeaders(extra.Provider, extra.OriginalModelRequested, extra.ProviderResponseHeaders)
	for key, value := range safeProviderResponseHeaders(headers) {
		ctx.Response.Header.Set(key, value)
	}
}

var unsafeProviderResponseHeaders = map[string]bool{
	"connection":                true,
	"content-encoding":          true,
	"content-length":            true,
	"content-security-policy":   true,
	"cookie":                    true,
	"keep-alive":                true,
	"location":                  true,
	"proxy-authenticate":        true,
	"proxy-authorization":       true,
	"set-cookie":                true,
	"set-cookie2":               true,
	"strict-transport-security": true,
	"te":                        true,
	"trailer":                   true,
	"transfer-encoding":         true,
	"upgrade":                   true,
	"x-accel-buffering":         true,
	"x-content-type-options":    true,
	"x-frame-options":           true,
}

func isSafeProviderResponseHeader(header string) bool {
	normalized := strings.ToLower(strings.TrimSpace(header))
	if normalized == "" {
		return false
	}
	if unsafeProviderResponseHeaders[normalized] {
		return false
	}
	if strings.HasPrefix(normalized, "access-control-") {
		return false
	}
	if strings.HasPrefix(normalized, "cf-") {
		return false
	}
	if strings.HasPrefix(normalized, "sec-") {
		return false
	}
	return true
}

func safeProviderResponseHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	filtered := make(map[string]string)
	for name, value := range headers {
		trimmed := strings.TrimSpace(name)
		if isSafeProviderResponseHeader(trimmed) {
			filtered[trimmed] = value
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func securityHeaders(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("X-Frame-Options", "DENY")
		ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
		ctx.Response.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		ctx.Response.Header.Set("Content-Security-Policy", "frame-ancestors 'none'")
		ctx.Response.Header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" || ctx.IsTLS() {
			ctx.Response.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next(ctx)
	}
}

func cors(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
		ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		ctx.Response.Header.Set("Access-Control-Max-Age", "86400")
		ctx.Response.Header.Set("Access-Control-Expose-Headers", "*")

		allowedHeaders := string(ctx.Request.Header.Peek("Access-Control-Request-Headers"))
		if strings.TrimSpace(allowedHeaders) == "" {
			allowedHeaders = strings.Join([]string{
				"Authorization",
				"Content-Type",
				"X-Requested-With",
				"X-Stogas-Upstream-API-Key",
				stogasHeaderReturnExtraFields,
				stogasHeaderReturnRawRequest,
				stogasHeaderReturnRawResponse,
				"api-key",
				"x-api-key",
				"x-goog-api-key",
			}, ", ")
		}
		ctx.Response.Header.Set("Access-Control-Allow-Headers", allowedHeaders)
		ctx.Response.Header.Set("Vary", "Access-Control-Request-Headers")

		if string(ctx.Method()) == fasthttp.MethodOptions {
			ctx.SetStatusCode(fasthttp.StatusNoContent)
			return
		}

		next(ctx)
	}
}

func (s *Server) requestDecompression(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if len(ctx.Request.Header.ContentEncoding()) == 0 {
			next(ctx)
			return
		}
		if isInferencePath(ctx.Path()) {
			if _, ok := s.requireInferenceHeaders(ctx); !ok {
				return
			}
		}

		maxRequestBodyBytes := s.config.MaxRequestBodyMiB * 1024 * 1024
		body, err := ctx.Request.BodyUncompressedWithLimit(maxRequestBodyBytes)
		if errors.Is(err, fasthttp.ErrBodyTooLarge) {
			s.writeError(ctx, fasthttp.StatusRequestEntityTooLarge, map[string]any{
				"error": map[string]any{"message": fmt.Sprintf("Decompressed request body exceeds max allowed size of %d bytes", maxRequestBodyBytes), "type": "invalid_request_error"},
			})
			return
		}
		if err != nil {
			s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
				"error": map[string]any{"message": fmt.Sprintf("Invalid compressed request body: %v", err), "type": "invalid_request_error"},
			})
			return
		}

		if len(body) > maxRequestBodyBytes {
			s.writeError(ctx, fasthttp.StatusRequestEntityTooLarge, map[string]any{
				"error": map[string]any{"message": fmt.Sprintf("Decompressed request body exceeds max allowed size of %d bytes", maxRequestBodyBytes), "type": "invalid_request_error"},
			})
			return
		}

		ctx.Request.SetBodyRaw(body)
		ctx.Request.Header.Del(fasthttp.HeaderContentEncoding)
		ctx.Request.Header.Del(fasthttp.HeaderContentLength)
		next(ctx)
	}
}

func isInferencePath(path []byte) bool {
	switch string(path) {
	case "/v1/chat/completions", "/v1/responses":
		return true
	default:
		return false
	}
}

func chain(handler fasthttp.RequestHandler, middlewares ...func(fasthttp.RequestHandler) fasthttp.RequestHandler) fasthttp.RequestHandler {
	wrapped := handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		wrapped = middlewares[i](wrapped)
	}
	return wrapped
}

func (s *Server) notFound(ctx *fasthttp.RequestCtx) {
	s.writeError(ctx, fasthttp.StatusNotFound, map[string]any{
		"error": map[string]any{"message": fmt.Sprintf("Route not found: %s", ctx.Path()), "type": "invalid_request_error"},
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
