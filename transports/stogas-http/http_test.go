package stogashttp

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/valyala/fasthttp"
)

func TestNewRequestContextAlwaysGeneratesRequestID(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("x-request-id", "client-controlled")

	bifrostCtx, cancel, err := newRequestContext(ctx, schemas.ChatCompletionRequest)
	if err != nil {
		t.Fatalf("newRequestContext returned error: %v", err)
	}
	defer cancel()

	requestID, ok := bifrostCtx.Value(schemas.BifrostContextKeyRequestID).(string)
	if !ok || requestID == "" {
		t.Fatalf("expected generated request ID, got %q", requestID)
	}
	if requestID == "client-controlled" {
		t.Fatal("expected server-generated request ID to ignore inbound x-request-id")
	}
	if _, err := uuid.Parse(requestID); err != nil {
		t.Fatalf("expected UUID request ID, got %q: %v", requestID, err)
	}
}

func TestRequestDecompressionGzip(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.SetBody(gzipBody(t, `{"model":"gpt-5"}`))

	called := false
	server.requestDecompression(func(ctx *fasthttp.RequestCtx) {
		called = true
		if got := string(ctx.Request.Body()); got != `{"model":"gpt-5"}` {
			t.Fatalf("expected decompressed body, got %q", got)
		}
		if encoding := string(ctx.Request.Header.ContentEncoding()); encoding != "" {
			t.Fatalf("expected content encoding to be removed, got %q", encoding)
		}
	})(ctx)

	if !called {
		t.Fatal("expected next handler to be called")
	}
}

func TestRequestDecompressionRejectsInvalidCompressedBody(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.SetBodyString("not gzip")

	server.requestDecompression(func(ctx *fasthttp.RequestCtx) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("expected 400, got %d", ctx.Response.StatusCode())
	}
	if !strings.Contains(string(ctx.Response.Body()), "Invalid compressed request body") {
		t.Fatalf("expected invalid compression error, got %s", ctx.Response.Body())
	}
}

func TestRequestDecompressionEnforcesDecompressedSize(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.SetBody(gzipBody(t, strings.Repeat("a", 1024*1024+1)))

	server.requestDecompression(func(ctx *fasthttp.RequestCtx) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", ctx.Response.StatusCode())
	}
}

func TestSecurityHeaders(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("X-Forwarded-Proto", "https")

	securityHeaders(func(ctx *fasthttp.RequestCtx) {})(ctx)

	expected := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "frame-ancestors 'none'",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}
	for header, value := range expected {
		if got := string(ctx.Response.Header.Peek(header)); got != value {
			t.Fatalf("expected %s=%q, got %q", header, value, got)
		}
	}
}

func TestProviderResponseHeaderSafetyBlocksCookieAndControlHeaders(t *testing.T) {
	blocked := []string{
		"Set-Cookie",
		" set-cookie ",
		"Connection",
		"Transfer-Encoding",
		"Content-Length",
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"Access-Control-Allow-Origin",
		"Sec-Fetch-Site",
		"Cf-Cache-Status",
	}

	for _, header := range blocked {
		t.Run(header, func(t *testing.T) {
			if isSafeProviderResponseHeader(header) {
				t.Fatalf("expected %q to be blocked", header)
			}
		})
	}
}

func TestProviderResponseHeaderSafetyAllowsOrdinaryProviderMetadata(t *testing.T) {
	allowed := []string{
		"OpenAI-Processing-Ms",
		"X-Request-Id",
		"Anthropic-Organization-Id",
	}

	for _, header := range allowed {
		t.Run(header, func(t *testing.T) {
			if !isSafeProviderResponseHeader(header) {
				t.Fatalf("expected %q to be allowed by permanent safety filter", header)
			}
		})
	}
}

func TestSafeProviderResponseHeadersFiltersMixedMap(t *testing.T) {
	got := safeProviderResponseHeaders(map[string]string{
		" OpenAI-Processing-Ms ":      "41",
		"Access-Control-Allow-Origin": "https://evil.example",
		"Set-Cookie":                  "session=attacker",
		"X-Request-Id":                "provider-request-id",
	})

	if got == nil {
		t.Fatal("expected safe headers to be retained")
	}
	if _, ok := got["Set-Cookie"]; ok {
		t.Fatal("expected Set-Cookie to be filtered")
	}
	if _, ok := got["Access-Control-Allow-Origin"]; ok {
		t.Fatal("expected CORS headers to be filtered")
	}
	if got["OpenAI-Processing-Ms"] != "41" {
		t.Fatalf("expected trimmed provider metadata header to be retained, got %#v", got)
	}
	if got["X-Request-Id"] != "provider-request-id" {
		t.Fatalf("expected ordinary metadata header to be retained, got %#v", got)
	}
}

func TestCorsAllowsAnyOrigin(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodOptions)
	ctx.Request.Header.Set("Origin", "https://example.com")
	ctx.Request.Header.Set("Access-Control-Request-Headers", "authorization,content-type")

	called := false
	cors(func(ctx *fasthttp.RequestCtx) { called = true })(ctx)

	if called {
		t.Fatal("preflight should not call next handler")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusNoContent {
		t.Fatalf("expected 204, got %d", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "*" {
		t.Fatalf("expected wildcard CORS origin, got %q", got)
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Headers")); got != "authorization,content-type" {
		t.Fatalf("expected requested headers to be allowed, got %q", got)
	}
}

func TestAPIKeyTokenAcceptsGatewayAuthAliases(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name:    "authorization bearer",
			headers: map[string]string{"Authorization": "Bearer sk-sto-bearer"},
			want:    "sk-sto-bearer",
		},
		{
			name:    "authorization raw token",
			headers: map[string]string{"Authorization": "sk-sto-raw"},
			want:    "sk-sto-raw",
		},
		{
			name:    "api-key",
			headers: map[string]string{"api-key": "sk-sto-api-key"},
			want:    "sk-sto-api-key",
		},
		{
			name:    "x-api-key",
			headers: map[string]string{"x-api-key": "sk-sto-x-api-key"},
			want:    "sk-sto-x-api-key",
		},
		{
			name:    "x-goog-api-key",
			headers: map[string]string{"x-goog-api-key": "sk-sto-google"},
			want:    "sk-sto-google",
		},
		{
			name: "authorization takes precedence",
			headers: map[string]string{
				"Authorization": "Bearer sk-sto-primary",
				"x-api-key":     "sk-sto-secondary",
			},
			want: "sk-sto-primary",
		},
		{
			name:    "missing",
			headers: map[string]string{},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			for key, value := range tt.headers {
				ctx.Request.Header.Set(key, value)
			}

			if got := apiKeyToken(ctx); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestPublicResponsePayloadRemovesExtraFields(t *testing.T) {
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()

	response := &schemas.BifrostChatResponse{
		ID:      "chatcmpl_test",
		Object:  "chat.completion",
		Model:   "gpt-5",
		Choices: []schemas.BifrostResponseChoice{},
		ExtraFields: schemas.BifrostResponseExtraFields{
			Provider:       schemas.OpenAI,
			ModelRequested: "gpt-5",
			Latency:        12,
		},
	}

	payload := publicResponsePayload(bifrostCtx, nil, response, response.ExtraFields)
	object, ok := payload.(map[string]any)
	if !ok {
		t.Fatalf("expected object payload, got %T", payload)
	}
	if _, exists := object["extra_fields"]; exists {
		t.Fatal("default public payload should not include Bifrost extra_fields")
	}
	if _, exists := object["stogas"]; exists {
		t.Fatal("default public payload should not include Stogas metadata")
	}
}

func TestPublicResponsePayloadIncludesRequestedStogasMetadata(t *testing.T) {
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	bifrostCtx.SetValue(stogasReturnExtraFieldsKey, map[string]bool{
		"provider":        true,
		"model_requested": true,
		"latency":         true,
	})

	response := &schemas.BifrostChatResponse{
		ID:      "chatcmpl_test",
		Object:  "chat.completion",
		Model:   "gpt-5",
		Choices: []schemas.BifrostResponseChoice{},
		ExtraFields: schemas.BifrostResponseExtraFields{
			Provider:        schemas.OpenAI,
			ModelRequested:  "openai/gpt-5",
			ModelDeployment: "gpt-5",
			Latency:         12,
		},
	}

	payload := publicResponsePayload(bifrostCtx, nil, response, response.ExtraFields)
	object, ok := payload.(map[string]any)
	if !ok {
		t.Fatalf("expected object payload, got %T", payload)
	}
	metadata, ok := object["stogas"].(map[string]any)
	if !ok {
		t.Fatalf("expected stogas metadata, got %#v", object["stogas"])
	}
	if metadata["provider"] != schemas.OpenAI {
		t.Fatalf("expected requested provider metadata, got %#v", metadata)
	}
	if metadata["model_requested"] != "openai/gpt-5" {
		t.Fatalf("expected requested model metadata, got %#v", metadata)
	}
	if _, exists := metadata["model_deployment"]; exists {
		t.Fatalf("did not expect unrequested model_deployment metadata, got %#v", metadata)
	}
}

func TestPublicResponsePayloadRawPassthrough(t *testing.T) {
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	bifrostCtx.SetValue(stogasRawResponsePassthroughKey, true)

	raw := map[string]any{"id": "raw_provider_response"}
	payload := publicResponsePayload(bifrostCtx, raw, map[string]any{"id": "bifrost_response"}, schemas.BifrostResponseExtraFields{})
	object, ok := payload.(map[string]any)
	if !ok {
		t.Fatalf("expected raw object, got %T", payload)
	}
	if object["id"] != "raw_provider_response" {
		t.Fatalf("expected raw response passthrough, got %#v", object)
	}
}

func TestServerDisablesStreamRequestBody(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	server.routes()

	if server.server.StreamRequestBody {
		t.Fatal("Stogas HTTP server should not stream request bodies")
	}
}

func gzipBody(t *testing.T, body string) []byte {
	t.Helper()

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(body)); err != nil {
		t.Fatalf("failed to write gzip body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}
	return compressed.Bytes()
}
