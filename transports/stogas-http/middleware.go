package stogashttp

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

var errRequestBodyTooLarge = errors.New("request body too large")
var errRequestMemoryCapacity = errors.New("request memory capacity exhausted")

func securityHeaders(next requestHandler) requestHandler {
	return func(ctx *requestContext) {
		ctx.writer.Header().Set("X-Frame-Options", "DENY")
		ctx.writer.Header().Set("X-Content-Type-Options", "nosniff")
		ctx.writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		ctx.writer.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		ctx.writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if string(ctx.request.Header.Get("X-Forwarded-Proto")) == "https" || (ctx.request.TLS != nil) {
			ctx.writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next(ctx)
	}
}

func cors(next requestHandler) requestHandler {
	return func(ctx *requestContext) {
		ctx.writer.Header().Set("Access-Control-Allow-Origin", "*")
		ctx.writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		ctx.writer.Header().Set("Access-Control-Max-Age", "86400")
		ctx.writer.Header().Set("Access-Control-Expose-Headers", "*")
		ctx.writer.Header().Set("Access-Control-Allow-Headers", corsAllowedHeaders(ctx))

		if ctx.request.Method == http.MethodOptions {
			closeUnreadRequest(ctx)
			ctx.writer.WriteHeader(http.StatusNoContent)
			return
		}

		next(ctx)
	}
}

func corsAllowedHeaders(ctx *requestContext) string {
	requested := strings.TrimSpace(string(ctx.request.Header.Get("Access-Control-Request-Headers")))
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
	ctx.writer.Header().Add("Vary", "Access-Control-Request-Headers")
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

func closeUnreadRequest(ctx *requestContext) {
	// Do not make HTTP/1 drain a rejected upload before returning its error.
	// HTTP/2 closes only this request stream when the handler returns.
	if ctx.request.ProtoMajor < 2 {
		ctx.writer.Header().Set("Connection", "close")
	}
}

func (s *Server) requestBodyAdmission(next requestHandler) requestHandler {
	if s.memory == nil {
		s.memory = newRequestMemoryAdmission()
	}
	return func(ctx *requestContext) {
		if !isGatewayRequestPath(ctx.request.URL.Path) || ctx.request.Method != http.MethodPost {
			closeUnreadRequest(ctx)
			next(ctx)
			return
		}
		if _, ok := s.requireInferenceHeaders(ctx); !ok {
			closeUnreadRequest(ctx)
			return
		}
		maxBytes := s.config.MaxRequestBodyMiB * 1024 * 1024
		if ctx.request.ContentLength > int64(maxBytes) {
			closeUnreadRequest(ctx)
			s.writeRequestBodyTooLarge(ctx, maxBytes)
			return
		}
		lease, admitted := ctx.memory, true
		if lease == nil {
			lease, admitted = s.memory.acquire(0)
		}
		if !admitted {
			closeUnreadRequest(ctx)
			s.writeRequestMemoryCapacity(ctx)
			return
		}
		ctx.memory = lease
		defer func() {
			if !lease.transferred {
				clear(ctx.body)
				ctx.body = nil
				lease.release()
			}
		}()
		body, err := readAdmittedBody(ctx.request.Body, maxBytes, lease, 0, ctx.request.ContentLength)
		_ = ctx.request.Body.Close()
		if err != nil {
			closeUnreadRequest(ctx)
			s.writeBodyReadError(ctx, err, maxBytes)
			return
		}
		ctx.body = body
		next(ctx)
	}
}

func (s *Server) publicAdmission(next requestHandler) requestHandler {
	return func(ctx *requestContext) {
		if isGatewayRequestPath(ctx.request.URL.Path) && ctx.request.Method == http.MethodPost && !s.requireAdmission(ctx) {
			return
		}
		next(ctx)
	}
}

// Reserve before allocating. Growth includes the old and new allocations until
// copying ends. An upload never waits for memory while retaining a partial body.
func readAdmittedBody(reader io.Reader, maxBytes int, lease *requestMemoryLease, retained int, sizeHint int64) ([]byte, error) {
	var body []byte
	keep := false
	defer func() {
		if !keep {
			clear(body)
		}
	}()
	finish := func() ([]byte, error) {
		// Unknown-length uploads can end partway through a doubled buffer. Copy
		// only when it reduces the lifetime reservation, and only if both copies
		// fit now. Compaction must never reject an otherwise valid upload.
		if requestMemoryWeight(len(body), 0) < requestMemoryWeight(cap(body), 0) && lease.resize(retained+cap(body)+len(body)) {
			compact := make([]byte, len(body))
			copy(compact, body)
			clear(body)
			body = compact
			if !lease.resize(retained + cap(body)) {
				panic("shrinking a live body lease failed")
			}
		}
		keep = true
		return body, nil
	}
	for {
		if len(body) == maxBytes {
			var extra [1]byte
			n, err := io.ReadFull(reader, extra[:])
			if n != 0 {
				return nil, errRequestBodyTooLarge
			}
			if errors.Is(err, io.EOF) {
				return finish()
			}
			return nil, err
		}
		if len(body) == cap(body) {
			var extra [1]byte
			var read int
			if len(body) > 0 {
				var err error
				read, err = io.ReadFull(reader, extra[:])
				if errors.Is(err, io.EOF) {
					return finish()
				}
				if err != nil {
					return nil, err
				}
			}
			capacity := min(maxBytes, max(32<<10, cap(body)*2))
			if sizeHint > int64(cap(body)) && sizeHint < int64(capacity) {
				capacity = int(sizeHint)
			}
			if !lease.resize(retained + cap(body) + capacity) {
				return nil, errRequestMemoryCapacity
			}
			grown := make([]byte, len(body), capacity)
			copy(grown, body)
			clear(body)
			body = grown
			if !lease.resize(retained + cap(body)) {
				panic("shrinking a live body lease failed")
			}
			body = append(body, extra[:read]...)
		}
		n, err := reader.Read(body[len(body):cap(body)])
		body = body[:len(body)+n]
		if errors.Is(err, io.EOF) {
			return finish()
		}
		if err != nil {
			clear(body)
			return nil, err
		}
	}
}

func requestMemoryLeaseForInference(ctx *requestContext) *requestMemoryLease {
	lease := ctx.memory
	if lease == nil || lease.transferred {
		return nil
	}
	lease.transferred = true
	return lease
}

func (s *Server) writeBodyReadError(ctx *requestContext, err error, maxBytes int) {
	switch {
	case errors.Is(err, errRequestBodyTooLarge):
		s.writeRequestBodyTooLarge(ctx, maxBytes)
	case errors.Is(err, errRequestMemoryCapacity):
		s.writeRequestMemoryCapacity(ctx)
	default:
		message := "Invalid request body"
		if ctx.request.Header.Get("Content-Encoding") != "" {
			message = "Invalid compressed request body"
		}
		s.writeError(ctx, http.StatusBadRequest, map[string]any{"error": map[string]any{"message": message, "type": "invalid_request_error"}})
	}
}

func (s *Server) writeRequestBodyTooLarge(ctx *requestContext, maxBytes int) {
	s.writeError(ctx, http.StatusRequestEntityTooLarge, map[string]any{"error": map[string]any{"message": fmt.Sprintf("Decompressed request body exceeds max allowed size of %d bytes", maxBytes), "type": "invalid_request_error"}})
}

func (s *Server) writeRequestMemoryCapacity(ctx *requestContext) {
	ctx.writer.Header().Set("Retry-After", "1")
	s.writeError(ctx, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"message": "Gateway capacity is temporarily exhausted. Retry the request later.", "type": "service_unavailable", "code": "gateway_capacity_exceeded"}})
}

func (s *Server) requestDecompression(next requestHandler) requestHandler {
	return func(ctx *requestContext) {
		encoding := strings.ToLower(strings.TrimSpace(ctx.request.Header.Get("Content-Encoding")))
		if encoding == "" {
			next(ctx)
			return
		}
		if isGatewayRequestPath(ctx.request.URL.Path) {
			if _, ok := s.requireInferenceHeaders(ctx); !ok {
				return
			}
		}
		maxBytes := s.config.MaxRequestBodyMiB * 1024 * 1024
		body, err := decompressRequestBody(ctx.body, encoding, maxBytes, ctx.memory)
		if err != nil {
			s.writeBodyReadError(ctx, err, maxBytes)
			return
		}

		clear(ctx.body)
		ctx.body = body
		_ = ctx.memory.resize(cap(body))
		ctx.request.Header.Del("Content-Encoding")
		ctx.request.Header.Del("Content-Length")
		next(ctx)
	}
}

func isInferencePath(path string) bool {
	_, ok := catalog.RouteForPath(path)
	return ok
}

func chain(handler requestHandler, middlewares ...func(requestHandler) requestHandler) requestHandler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

func isGatewayRequestPath(path string) bool {
	return path == policyValidationPath || isInferencePath(path)
}
