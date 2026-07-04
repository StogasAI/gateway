package stogashttp

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/valyala/fasthttp"
)

var allowedProviderResponseHeaders = map[string]bool{
	"openai-processing-ms": true,
	"openai-version":       true,
	"request-id":           true,
	"x-request-id":         true,
}

func isSafeProviderResponseHeader(header string) bool {
	normalized := strings.ToLower(strings.TrimSpace(header))
	if normalized == "" {
		return false
	}
	return allowedProviderResponseHeaders[normalized]
}

func safeProviderResponseHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	filtered := make(map[string]string)
	for name, value := range headers {
		trimmed := strings.TrimSpace(name)
		if isSafeProviderResponseHeader(trimmed) && safeProviderResponseHeaderValue(value) {
			filtered[trimmed] = value
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func safeProviderResponseHeaderValue(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
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
		ctx.Response.Header.Set("Access-Control-Allow-Headers", catalog.AllClientHeadersValue())

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
	_, ok := catalog.RouteForPath(string(path))
	return ok
}

func chain(handler fasthttp.RequestHandler, middlewares ...func(fasthttp.RequestHandler) fasthttp.RequestHandler) fasthttp.RequestHandler {
	wrapped := handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		wrapped = middlewares[i](wrapped)
	}
	return wrapped
}
