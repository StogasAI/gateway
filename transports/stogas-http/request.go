package stogashttp

import (
	"errors"
	"mime"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"net/http"
)

type apiCredential struct {
	EncryptionKeys customerkey.Keys
	Claims         *billing.APIKeyClaims
	Dashboard      *billing.DashboardCredential
	Raw            string
}

var (
	errMalformedAPIKeyHeader   = errors.New("malformed API key header")
	errConflictingAPIKeyHeader = errors.New("conflicting API key headers")
)

func authorizationToken(raw string) (string, bool) {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", false
	}
	parts := strings.Fields(value)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1], validCredentialValue(parts[1])
	}
	return "", false
}

func apiKeyToken(ctx *requestContext, route catalog.Route) (string, error) {
	var (
		token            string
		malformed        bool
		headerValueCount int
	)
	for _, header := range catalog.AuthHeaderNames(route) {
		for _, raw := range ctx.request.Header.Values(header) {
			headerValueCount++
			var (
				next string
				ok   bool
			)
			if strings.EqualFold(header, "Authorization") {
				next, ok = authorizationToken(raw)
			} else {
				next = strings.TrimSpace(string(raw))
				ok = validCredentialValue(next)
			}
			if !ok {
				malformed = true
				continue
			}
			if token == "" {
				token = next
				continue
			}
			if next != token {
				return "", errConflictingAPIKeyHeader
			}
		}
	}
	if malformed {
		if headerValueCount > 1 {
			return "", errConflictingAPIKeyHeader
		}
		return "", errMalformedAPIKeyHeader
	}
	return token, nil
}

func validCredentialValue(value string) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func (s *Server) requireAPIKey(ctx *requestContext) (apiCredential, bool) {
	route, ok := catalog.RouteForPath(ctx.request.URL.Path)
	if ctx.request.URL.Path == policyValidationPath {
		route, ok = catalog.RouteChat, true
	}
	if !ok {
		s.writeError(ctx, http.StatusNotFound, map[string]any{
			"error": map[string]any{"message": "Not found", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	token, err := apiKeyToken(ctx, route)
	if errors.Is(err, errConflictingAPIKeyHeader) {
		s.writeError(ctx, http.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Conflicting API key headers", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	if err != nil {
		s.writeError(ctx, http.StatusUnauthorized, map[string]any{
			"error": map[string]any{"message": "Invalid API key header", "type": "authentication_error"},
		})
		return apiCredential{}, false
	}
	if token == "" {
		s.writeError(ctx, http.StatusUnauthorized, map[string]any{
			"error": map[string]any{"message": "Missing API key", "type": "authentication_error"},
		})
		return apiCredential{}, false
	}

	if s.runtime == nil {
		return apiCredential{Raw: token}, true
	}
	if ctx.encrypted && billing.IsDashboardCredential(token) {
		dashboard, dashboardErr := s.runtime.ParseDashboardCredential(token)
		if dashboard != nil {
			ctx.dashboard = dashboard
		}
		if dashboard != nil && dashboard.Claims != nil {
			ctx.claims = dashboard.Claims
		}
		if dashboardErr != nil {
			s.writeBillingError(ctx, dashboardErr)
			return apiCredential{}, false
		}
		clearInferenceCredentials(ctx)
		return apiCredential{Dashboard: dashboard}, true
	}
	claims, err := s.runtime.ParseAPIKey(token)
	if claims != nil {
		ctx.claims = claims
	}
	if err != nil {
		s.writeBillingError(ctx, err)
		return apiCredential{}, false
	}
	return apiCredential{Raw: token, Claims: claims}, true
}

func (s *Server) requireInferenceEnvelope(ctx *requestContext) (apiCredential, bool) {
	credential, ok := s.requireInferenceHeaders(ctx)
	if !ok {
		return apiCredential{}, false
	}
	if len(ctx.body) == 0 {
		s.writeError(ctx, http.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Request body is required", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	return credential, true
}

func (s *Server) requireInferenceHeaders(ctx *requestContext) (apiCredential, bool) {
	if ctx.credential != nil {
		return *ctx.credential, true
	}
	credential, ok := s.requireAPIKey(ctx)
	if !ok {
		return apiCredential{}, false
	}
	contentTypes := ctx.request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !isJSONContentType(contentTypes[0]) {
		s.writeError(ctx, http.StatusUnsupportedMediaType, map[string]any{
			"error": map[string]any{"message": "Content-Type must be application/json", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	if !validContentEncodingHeaders(ctx.request.Header.Values("Content-Encoding")) {
		s.writeError(ctx, http.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Content-Encoding is invalid or ambiguous", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	if unsupported := unsupportedInferenceHeader(ctx); unsupported != "" {
		s.writeError(ctx, http.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Unsupported request header: " + unsupported, "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	if !validateAcceptHeaders(ctx.request.Header.Values("Accept")) {
		s.writeError(ctx, http.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Accept must be application/json or text/event-stream", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	ctx.credential = &credential
	return credential, true
}

func isJSONContentType(raw string) bool {
	return isContentType(raw, "application/json")
}

func isContentType(raw string, expected string) bool {
	mediaType, parameters, err := mime.ParseMediaType(string(raw))
	if err != nil || !strings.EqualFold(mediaType, expected) {
		return false
	}
	for name, value := range parameters {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func unsupportedInferenceHeader(ctx *requestContext) string {
	unsupported := ""
	for key := range ctx.request.Header {
		normalized := strings.ToLower(strings.TrimSpace(string(key)))
		if normalized == "" || !internalOrProviderControlHeader(normalized) {
			continue
		}
		unsupported = normalized
		break
	}
	return unsupported
}

func internalOrProviderControlHeader(name string) bool {
	return strings.HasPrefix(name, "x-bf-") || strings.HasPrefix(name, "x-stogas-")
}

func validateAcceptHeader(raw string) bool {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return true
	}
	for _, item := range strings.Split(value, ",") {
		mediaType, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(item)), ";")
		switch strings.TrimSpace(mediaType) {
		case "application/json", "text/event-stream", "*/*":
			continue
		default:
			return false
		}
	}
	return true
}

func validateAcceptHeaders(values []string) bool {
	for _, value := range values {
		if !validateAcceptHeader(value) {
			return false
		}
	}
	return true
}

func validContentEncodingHeaders(values []string) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(string(values[0]))) {
	case "gzip", "deflate", "br", "zstd":
		return true
	default:
		return false
	}
}

func clearInferenceCredentials(ctx *requestContext) {
	for _, route := range []catalog.Route{catalog.RouteChat, catalog.RouteResponses} {
		for _, header := range catalog.AuthHeaderNames(route) {
			ctx.request.Header.Del(header)
		}
	}
}
