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
	Upstream  upstreamCredentialInputs
}

type upstreamCredentialInputs struct {
	Anthropic string
	Chutes    string
	OpenAI    string
}

func (inputs upstreamCredentialInputs) only(provider string) upstreamCredentialInputs {
	switch provider {
	case "anthropic":
		return upstreamCredentialInputs{Anthropic: inputs.Anthropic}
	case "chutes":
		return upstreamCredentialInputs{Chutes: inputs.Chutes}
	case "openai":
		return upstreamCredentialInputs{OpenAI: inputs.OpenAI}
	default:
		return upstreamCredentialInputs{}
	}
}

func (inputs upstreamCredentialInputs) get(provider string) string {
	switch provider {
	case "anthropic":
		return inputs.Anthropic
	case "chutes":
		return inputs.Chutes
	case "openai":
		return inputs.OpenAI
	default:
		return ""
	}
}

const (
	upstreamAnthropicHeader = "X-Stogas-Upstream-Anthropic-API-Key"
	upstreamChutesHeader    = "X-Stogas-Upstream-Chutes-API-Key"
	upstreamOpenAIHeader    = "X-Stogas-Upstream-OpenAI-API-Key"
)

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
	upstream, upstreamErr := takeUpstreamCredentials(ctx)
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
	return isContentType(raw, "application/json")
}

func isContentType(raw []byte, expected string) bool {
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
			name != strings.ToLower(upstreamAnthropicHeader) &&
			name != strings.ToLower(upstreamChutesHeader) &&
			name != strings.ToLower(upstreamOpenAIHeader))
}

func takeUpstreamCredentials(ctx *fasthttp.RequestCtx) (upstreamCredentialInputs, error) {
	legacyAPIKey := ctx.Request.Header.PeekAll("X-Stogas-Upstream-API-Key")
	legacyProvider := ctx.Request.Header.PeekAll("X-Stogas-Upstream-Provider")
	ctx.Request.Header.Del("X-Stogas-Upstream-API-Key")
	ctx.Request.Header.Del("X-Stogas-Upstream-Provider")

	values := make([]string, 3)
	headers := [...]string{upstreamAnthropicHeader, upstreamChutesHeader, upstreamOpenAIHeader}
	var parseErr error
	for index, header := range headers {
		values[index], parseErr = takeUpstreamCredentialHeader(ctx, header)
		if parseErr != nil {
			for _, remaining := range headers[index+1:] {
				ctx.Request.Header.Del(remaining)
			}
			return upstreamCredentialInputs{}, parseErr
		}
	}
	if len(legacyAPIKey) != 0 || len(legacyProvider) != 0 {
		return upstreamCredentialInputs{}, fmt.Errorf("generic upstream credential headers are unsupported; use a provider-specific upstream API key header")
	}
	return upstreamCredentialInputs{
		Anthropic: values[0],
		Chutes:    values[1],
		OpenAI:    values[2],
	}, nil
}

func takeUpstreamCredentialHeader(ctx *fasthttp.RequestCtx, header string) (string, error) {
	values := ctx.Request.Header.PeekAll(header)
	ctx.Request.Header.Del(header)
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("%s must appear at most once", header)
	}
	value := string(values[0])
	if !validCredentialValue(value) {
		return "", fmt.Errorf("%s is invalid", header)
	}
	return value, nil
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
