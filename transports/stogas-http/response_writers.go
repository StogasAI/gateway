package stogashttp

import (
	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/valyala/fasthttp"
)

func (s *Server) forwardProviderHeadersFromContext(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext) {
	if headers, ok := bifrostCtx.Value(schemas.BifrostContextKeyProviderResponseHeaders).(map[string]string); ok {
		s.forwardProviderHeaders(ctx, schemas.BifrostResponseExtraFields{ProviderResponseHeaders: headers})
	}
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
	if hash := catalog.CatalogHash(); hash != "" {
		ctx.Response.Header.Set("X-Stogas-Catalog-Hash", hash)
	}
	_, _ = ctx.Write(data)
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

func (s *Server) writeCatalogError(ctx *fasthttp.RequestCtx, err error) {
	apiErr := catalog.PublicError(err)
	s.writeError(ctx, apiErr.StatusCode, map[string]any{
		"error": map[string]any{"message": apiErr.Message, "type": apiErr.Type},
	})
}

func (s *Server) forwardProviderHeaders(ctx *fasthttp.RequestCtx, extra schemas.BifrostResponseExtraFields) {
	headers := catalog.FilterProviderResponseHeaders(extra.Provider, extra.OriginalModelRequested, extra.ProviderResponseHeaders)
	for key, value := range safeProviderResponseHeaders(headers) {
		ctx.Response.Header.Set(key, value)
	}
}
