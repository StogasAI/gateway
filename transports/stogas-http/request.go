package stogashttp

import (
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/valyala/fasthttp"
)

type apiCredential struct {
	Claims *billing.APIKeyClaims
	Raw    string
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

func apiKeyToken(ctx *fasthttp.RequestCtx, route catalog.Route) string {
	for _, header := range catalog.AuthHeaderNames(route) {
		if token := authorizationToken(ctx.Request.Header.Peek(header)); token != "" {
			return token
		}
	}
	return ""
}

func (s *Server) requireAPIKey(ctx *fasthttp.RequestCtx) (apiCredential, bool) {
	route, ok := catalog.RouteForPath(string(ctx.Path()))
	if !ok {
		s.writeError(ctx, fasthttp.StatusNotFound, map[string]any{
			"error": map[string]any{"message": "Not found", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	token := apiKeyToken(ctx, route)
	if token == "" {
		s.writeError(ctx, fasthttp.StatusUnauthorized, map[string]any{
			"error": map[string]any{"message": "Missing API key", "type": "authentication_error"},
		})
		return apiCredential{}, false
	}
	if s.runtime == nil {
		return apiCredential{Raw: token}, true
	}
	claims, err := s.runtime.ParseAPIKey(token)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusUnauthorized, map[string]any{
			"error": map[string]any{"message": "Invalid API key", "type": "authentication_error"},
		})
		return apiCredential{}, false
	}
	return apiCredential{Raw: token, Claims: claims}, true
}

func (s *Server) requireInferenceEnvelope(ctx *fasthttp.RequestCtx) (apiCredential, bool) {
	credential, ok := s.requireInferenceHeaders(ctx)
	if !ok {
		return apiCredential{}, false
	}
	if len(ctx.Request.Body()) == 0 {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Request body is required", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	return credential, true
}

func (s *Server) requireInferenceHeaders(ctx *fasthttp.RequestCtx) (apiCredential, bool) {
	credential, ok := s.requireAPIKey(ctx)
	if !ok {
		return apiCredential{}, false
	}
	if !isJSONContentType(ctx.Request.Header.ContentType()) {
		s.writeError(ctx, fasthttp.StatusUnsupportedMediaType, map[string]any{
			"error": map[string]any{"message": "Content-Type must be application/json", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	return credential, true
}

func isJSONContentType(raw []byte) bool {
	contentType := strings.ToLower(strings.TrimSpace(string(raw)))
	mediaType, _, _ := strings.Cut(contentType, ";")
	return strings.TrimSpace(mediaType) == "application/json"
}
