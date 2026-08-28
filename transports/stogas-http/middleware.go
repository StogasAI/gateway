package stogashttp

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/e2ee"
	"github.com/valyala/fasthttp"
)

const requestMemoryLeaseContextKey = "stogas.request-memory-lease"

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
		ctx.Response.Header.Set("Access-Control-Allow-Headers", corsAllowedHeaders(ctx))

		if string(ctx.Method()) == fasthttp.MethodOptions {
			if ctx.Request.IsBodyStream() {
				ctx.SetConnectionClose()
			}
			ctx.SetStatusCode(fasthttp.StatusNoContent)
			return
		}

		next(ctx)
	}
}

func corsAllowedHeaders(ctx *fasthttp.RequestCtx) string {
	requested := strings.TrimSpace(string(ctx.Request.Header.Peek("Access-Control-Request-Headers")))
	if requested == "" {
		return catalog.AllClientHeadersValue()
	}
	names := make([]string, 0, strings.Count(requested, ",")+1)
	seen := make(map[string]bool, cap(names))
	for _, raw := range strings.Split(requested, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if !validHTTPFieldName(name) || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) == 0 {
		return catalog.AllClientHeadersValue()
	}
	ctx.Response.Header.Add("Vary", "Access-Control-Request-Headers")
	return strings.Join(names, ", ")
}

func validHTTPFieldName(name string) bool {
	if name == "" {
		return false
	}
	for index := range len(name) {
		char := name[index]
		if (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(char)) {
			continue
		}
		return false
	}
	return true
}

func (s *Server) requestBodyAdmission(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !isInferencePath(ctx.Path()) {
			if ctx.Request.IsBodyStream() {
				ctx.SetConnectionClose()
			}
			next(ctx)
			return
		}
		if string(ctx.Method()) != fasthttp.MethodPost {
			if ctx.Request.IsBodyStream() {
				ctx.SetConnectionClose()
			}
			next(ctx)
			return
		}
		if !isEncryptedInferenceRequest(ctx) {
			if _, ok := s.requireInferenceHeaders(ctx); !ok {
				if ctx.Request.IsBodyStream() {
					ctx.SetConnectionClose()
				}
				return
			}
		}

		maxRequestBodyBytes := s.config.MaxRequestBodyMiB * 1024 * 1024
		contentLength := ctx.Request.Header.ContentLength()
		if contentLength > maxRequestBodyBytes {
			ctx.SetConnectionClose()
			s.writeRequestBodyTooLarge(ctx, maxRequestBodyBytes)
			return
		}
		reservationBytes := contentLength
		if reservationBytes < 0 || len(ctx.Request.Header.ContentEncoding()) > 0 {
			reservationBytes = maxRequestBodyBytes
		}
		if s.memory == nil {
			s.memory = newRequestMemoryAdmission()
		}
		lease, admitted := s.memory.acquire(reservationBytes)
		if !admitted {
			ctx.SetConnectionClose()
			s.writeRequestMemoryCapacity(ctx)
			return
		}
		defer func() {
			if !lease.transferred {
				lease.release()
			}
		}()

		body, err := readRequestBodyWithLimit(ctx, maxRequestBodyBytes)
		if errors.Is(err, fasthttp.ErrBodyTooLarge) {
			ctx.SetConnectionClose()
			s.writeRequestBodyTooLarge(ctx, maxRequestBodyBytes)
			return
		}
		if err != nil {
			ctx.SetConnectionClose()
			s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
				"error": map[string]any{"message": "Invalid request body", "type": "invalid_request_error"},
			})
			return
		}
		if len(ctx.Request.Header.ContentEncoding()) == 0 && !lease.resize(len(body)) {
			ctx.SetConnectionClose()
			s.writeRequestMemoryCapacity(ctx)
			return
		}
		ctx.SetUserValue(requestMemoryLeaseContextKey, lease)
		next(ctx)
	}
}

func readRequestBodyWithLimit(ctx *fasthttp.RequestCtx, maxBytes int) ([]byte, error) {
	if !ctx.Request.IsBodyStream() {
		body := ctx.Request.Body()
		if len(body) > maxBytes {
			return nil, fasthttp.ErrBodyTooLarge
		}
		return body, nil
	}
	reader := ctx.RequestBodyStream()
	body, err := io.ReadAll(io.LimitReader(reader, int64(maxBytes)+1))
	closeErr := ctx.Request.CloseBodyStream()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(body) > maxBytes {
		return nil, fasthttp.ErrBodyTooLarge
	}
	ctx.Request.SetBodyRaw(body)
	return body, nil
}

func requestMemoryLeaseForInference(ctx *fasthttp.RequestCtx) *requestMemoryLease {
	lease, _ := ctx.UserValue(requestMemoryLeaseContextKey).(*requestMemoryLease)
	if lease == nil || lease.transferred {
		return nil
	}
	lease.transferred = true
	return lease
}

func resizeRequestMemoryLease(ctx *fasthttp.RequestCtx, bodyBytes int) bool {
	lease, _ := ctx.UserValue(requestMemoryLeaseContextKey).(*requestMemoryLease)
	return lease == nil || lease.resize(bodyBytes)
}

func (s *Server) writeRequestBodyTooLarge(ctx *fasthttp.RequestCtx, maxRequestBodyBytes int) {
	s.writeError(ctx, fasthttp.StatusRequestEntityTooLarge, map[string]any{
		"error": map[string]any{"message": fmt.Sprintf("Decompressed request body exceeds max allowed size of %d bytes", maxRequestBodyBytes), "type": "invalid_request_error"},
	})
}

func (s *Server) writeRequestMemoryCapacity(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Retry-After", "1")
	s.writeError(ctx, fasthttp.StatusServiceUnavailable, map[string]any{
		"error": map[string]any{"message": "Gateway is at request memory capacity", "type": "service_unavailable"},
	})
}

func (s *Server) requestDecompression(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if len(ctx.Request.Header.ContentEncoding()) == 0 {
			next(ctx)
			return
		}
		if isInferencePath(ctx.Path()) && !isEncryptedInferenceRequest(ctx) {
			if _, ok := s.requireInferenceHeaders(ctx); !ok {
				return
			}
		}

		maxRequestBodyBytes := s.config.MaxRequestBodyMiB * 1024 * 1024
		body, err := ctx.Request.BodyUncompressedWithLimit(maxRequestBodyBytes)
		if errors.Is(err, fasthttp.ErrBodyTooLarge) {
			s.writeRequestBodyTooLarge(ctx, maxRequestBodyBytes)
			return
		}
		if err != nil {
			s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
				"error": map[string]any{"message": fmt.Sprintf("Invalid compressed request body: %v", err), "type": "invalid_request_error"},
			})
			return
		}

		if len(body) > maxRequestBodyBytes {
			s.writeRequestBodyTooLarge(ctx, maxRequestBodyBytes)
			return
		}
		if !resizeRequestMemoryLease(ctx, len(body)) {
			s.writeRequestMemoryCapacity(ctx)
			return
		}

		ctx.Request.SetBodyRaw(body)
		ctx.Request.Header.Del(fasthttp.HeaderContentEncoding)
		ctx.Request.Header.Del(fasthttp.HeaderContentLength)
		next(ctx)
	}
}

// isEncryptedInferenceRequest selects E2EE handling before body
// admission. Credentials and application content negotiation are authenticated
// inside the envelope, so normal header validation waits until decryption.
func isEncryptedInferenceRequest(ctx *fasthttp.RequestCtx) bool {
	values := ctx.Request.Header.PeekAll(fasthttp.HeaderContentType)
	return len(values) == 1 && isContentType(values[0], e2ee.ContentType)
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
