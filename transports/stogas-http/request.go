package stogashttp

import (
	"errors"
	"fmt"
	"mime"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/valyala/fasthttp"
)

type apiCredential struct {
	Claims    *billing.APIKeyClaims
	Dashboard *billing.DashboardCredential
	Raw       string
	Upstream  *upstreamCredentialInput
}

type upstreamCredentialInput struct {
	Provider string
	APIKey   string
}

const inferenceCredentialContextKey = "stogas.inference_credential"
const inferenceRouteContextKey = "stogas.inference_route"

var (
	errMalformedAPIKeyHeader   = errors.New("malformed API key header")
	errConflictingAPIKeyHeader = errors.New("conflicting API key headers")
)

func authorizationToken(raw []byte) (string, bool) {
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

func apiKeyToken(ctx *fasthttp.RequestCtx, route catalog.Route) (string, error) {
	var (
		token            string
		malformed        bool
		headerValueCount int
	)
	for _, header := range catalog.AuthHeaderNames(route) {
		for _, raw := range ctx.Request.Header.PeekAll(header) {
			headerValueCount++
			var (
				next string
				ok   bool
			)
			if strings.EqualFold(header, fasthttp.HeaderAuthorization) {
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

func (s *Server) requireAPIKey(ctx *fasthttp.RequestCtx) (apiCredential, bool) {
	route, ok := catalog.RouteForPath(string(ctx.Path()))
	if !ok {
		s.writeError(ctx, fasthttp.StatusNotFound, map[string]any{
			"error": map[string]any{"message": "Not found", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	token, err := apiKeyToken(ctx, route)
	if errors.Is(err, errConflictingAPIKeyHeader) {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Conflicting API key headers", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	if err != nil {
		s.writeError(ctx, fasthttp.StatusUnauthorized, map[string]any{
			"error": map[string]any{"message": "Invalid API key header", "type": "authentication_error"},
		})
		return apiCredential{}, false
	}
	if token == "" {
		s.writeError(ctx, fasthttp.StatusUnauthorized, map[string]any{
			"error": map[string]any{"message": "Missing API key", "type": "authentication_error"},
		})
		return apiCredential{}, false
	}
	ctx.SetUserValue(inferenceRouteContextKey, route)
	if s.runtime == nil {
		return apiCredential{Raw: token}, true
	}
	if encryptedSession(ctx) != nil && billing.IsDashboardCredential(token) {
		dashboard, dashboardErr := s.runtime.ParseDashboardCredential(token)
		if dashboardErr != nil {
			s.writeBillingError(ctx, dashboardErr)
			return apiCredential{}, false
		}
		clearInferenceCredentials(ctx)
		return apiCredential{Dashboard: dashboard}, true
	}
	claims, err := s.runtime.ParseAPIKey(token)
	if err != nil {
		s.writeBillingError(ctx, err)
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
	if cached, ok := ctx.UserValue(inferenceCredentialContextKey).(apiCredential); ok {
		return cached, true
	}
	upstream, upstreamErr := takeUpstreamCredential(ctx)
	credential, ok := s.requireAPIKey(ctx)
	if !ok {
		return apiCredential{}, false
	}
	contentTypes := ctx.Request.Header.PeekAll(fasthttp.HeaderContentType)
	if len(contentTypes) != 1 || !isJSONContentType(contentTypes[0]) {
		s.writeError(ctx, fasthttp.StatusUnsupportedMediaType, map[string]any{
			"error": map[string]any{"message": "Content-Type must be application/json", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	if !validContentEncodingHeaders(ctx.Request.Header.PeekAll(fasthttp.HeaderContentEncoding)) {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Content-Encoding is invalid or ambiguous", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	if unsupported := unsupportedInferenceHeader(ctx); unsupported != "" {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Unsupported request header: " + unsupported, "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	if !validateAcceptHeaders(ctx.Request.Header.PeekAll(fasthttp.HeaderAccept)) {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": "Accept must be application/json or text/event-stream", "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	if upstreamErr != nil {
		s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": upstreamErr.Error(), "type": "invalid_request_error"},
		})
		return apiCredential{}, false
	}
	credential.Upstream = upstream
	ctx.SetUserValue(inferenceCredentialContextKey, credential)
	return credential, true
}

func isJSONContentType(raw []byte) bool {
	mediaType, parameters, err := mime.ParseMediaType(string(raw))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return false
	}
	for name, value := range parameters {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func unsupportedInferenceHeader(ctx *fasthttp.RequestCtx) string {
	unsupported := ""
	for key := range ctx.Request.Header.All() {
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
	return strings.HasPrefix(name, "x-bf-") ||
		(strings.HasPrefix(name, "x-stogas-") &&
			name != "x-stogas-extra-fields" &&
			name != "x-stogas-upstream-api-key" &&
			name != "x-stogas-upstream-provider")
}

func takeUpstreamCredential(ctx *fasthttp.RequestCtx) (*upstreamCredentialInput, error) {
	apiKey, apiKeyOK := consistentHeaderValue(ctx.Request.Header.PeekAll("X-Stogas-Upstream-API-Key"), false)
	provider, providerOK := consistentHeaderValue(ctx.Request.Header.PeekAll("X-Stogas-Upstream-Provider"), true)
	ctx.Request.Header.Del("X-Stogas-Upstream-API-Key")
	ctx.Request.Header.Del("X-Stogas-Upstream-Provider")
	if !apiKeyOK || !providerOK {
		return nil, fmt.Errorf("conflicting upstream credential headers")
	}
	if apiKey == "" {
		if provider != "" {
			return nil, fmt.Errorf("X-Stogas-Upstream-API-Key is required with upstream credential metadata")
		}
		return nil, nil
	}
	if !validCredentialValue(apiKey) {
		return nil, fmt.Errorf("X-Stogas-Upstream-API-Key is invalid")
	}
	if provider == "" {
		return nil, fmt.Errorf("X-Stogas-Upstream-Provider is required with a pass-through credential")
	}
	if len(provider) > 64 || strings.ContainsAny(provider, "\x00\r\n") {
		return nil, fmt.Errorf("X-Stogas-Upstream-Provider is invalid")
	}
	switch provider {
	case "anthropic", "chutes", "openai":
	case "azure":
		return nil, fmt.Errorf("unsupported Azure pass-through credentials")
	default:
		return nil, fmt.Errorf("X-Stogas-Upstream-Provider is invalid")
	}
	return &upstreamCredentialInput{Provider: provider, APIKey: apiKey}, nil
}

func consistentHeaderValue(values [][]byte, trim bool) (string, bool) {
	value := ""
	for _, raw := range values {
		next := string(raw)
		if trim {
			next = strings.TrimSpace(next)
		}
		if next == "" {
			continue
		}
		if value == "" {
			value = next
			continue
		}
		if next != value {
			return "", false
		}
	}
	return value, true
}

func validateAcceptHeader(raw []byte) bool {
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

func validateAcceptHeaders(values [][]byte) bool {
	for _, value := range values {
		if !validateAcceptHeader(value) {
			return false
		}
	}
	return true
}

func validContentEncodingHeaders(values [][]byte) bool {
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
