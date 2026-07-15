package stogashttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"github.com/maximhq/bifrost/transports/stogas/confidential/quote"
	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	"github.com/valyala/fasthttp"
)

func TestNewRequestContextAlwaysGeneratesRequestID(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("x-request-id", "client-controlled")

	bifrostCtx, _, cancel, err := newRequestContext(ctx, testResolution(), apiCredential{Raw: "sk-test"}, stogas.AdapterFor(schemas.OpenAI))
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
	state, ok := stogas.StateFrom(bifrostCtx)
	if !ok || state.RawAPIKey != "sk-test" || state.Resolution == nil {
		t.Fatalf("expected request state with credential and resolution, got %#v", state)
	}
	deadline, ok := bifrostCtx.Deadline()
	if !ok {
		t.Fatal("expected gateway request lifetime deadline")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > chatRequestLifetime {
		t.Fatalf("chat request lifetime remaining = %s, want within %s", remaining, chatRequestLifetime)
	}
}

func TestNewRequestContextDoesNotExposeClientHeadersToBifrost(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "Bearer sk-secret")
	ctx.Request.Header.Set("X-OpenAI-Agents-SDK", "client-controlled")

	bifrostCtx, _, cancel, err := newRequestContext(ctx, testResolution(), apiCredential{Raw: "sk-test"}, stogas.AdapterFor(schemas.OpenAI))
	if err != nil {
		t.Fatalf("newRequestContext returned error: %v", err)
	}
	defer cancel()

	if headers, ok := bifrostCtx.Value(schemas.BifrostContextKeyRequestHeaders).(map[string]string); ok && len(headers) > 0 {
		t.Fatalf("Stogas inference context must not expose raw client headers to Bifrost, got %#v", headers)
	}
}

func testResolution() *catalog.ResolvedRequest {
	return &catalog.ResolvedRequest{
		Route:       catalog.RouteChat,
		RequestType: schemas.ChatCompletionRequest,
		Provider:    schemas.OpenAI,
		Model:       "gpt-5.5",
	}
}

func TestNewRequestContextUsesResponsesLifetime(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	resolution := testResolution()
	resolution.Route = catalog.RouteResponses
	resolution.RequestType = schemas.ResponsesStreamRequest

	bifrostCtx, _, cancel, err := newRequestContext(ctx, resolution, apiCredential{Raw: "sk-test"}, stogas.AdapterFor(schemas.OpenAI))
	if err != nil {
		t.Fatalf("newRequestContext returned error: %v", err)
	}
	defer cancel()

	deadline, ok := bifrostCtx.Deadline()
	if !ok {
		t.Fatal("expected gateway request lifetime deadline")
	}
	if remaining := time.Until(deadline); remaining <= chatRequestLifetime || remaining > billing.GatewayRequestLifetime {
		t.Fatalf("responses request lifetime remaining = %s, want between %s and %s", remaining, chatRequestLifetime, billing.GatewayRequestLifetime)
	}
	state, ok := stogas.StateFrom(bifrostCtx)
	if !ok || state.RequestLifetime != billing.GatewayRequestLifetime {
		t.Fatalf("expected response request state lifetime %s, got %#v", billing.GatewayRequestLifetime, state)
	}
}

func mustCatalogPath(t *testing.T, route catalog.Route) string {
	t.Helper()
	path, ok := catalog.PathForRoute(route)
	if !ok {
		t.Fatalf("missing catalog path for route %s", route)
	}
	return path
}

func TestPrivateReadinessProbeIsHealthyWhenConfidentialRuntimeIsDisabled(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	if err := server.routes(); err != nil {
		t.Fatal(err)
	}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/ready")

	server.readinessServer.Handler(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusNoContent {
		t.Fatalf("expected 204 readiness, got %d", ctx.Response.StatusCode())
	}
	if len(ctx.Response.Body()) != 0 {
		t.Fatalf("readiness probe should not return a body on success, got %q", ctx.Response.Body())
	}
}

func TestPrivateReadinessProbeFailsClosedForIncompleteConfidentialRuntime(t *testing.T) {
	server := &Server{
		config: stogas.Config{MaxRequestBodyMiB: 1},
		secure: &confidentialruntime.Runtime{EntropyReady: true},
	}
	if err := server.routes(); err != nil {
		t.Fatal(err)
	}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/ready")

	server.readinessServer.Handler(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusServiceUnavailable {
		t.Fatalf("expected 503 readiness, got %d", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Body()); got != `{"ok":false}` {
		t.Fatalf("readiness probe should not leak private reasons, got %q", got)
	}
}

func TestReadinessRouteIsPrivateAndExclusive(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	if err := server.routes(); err != nil {
		t.Fatal(err)
	}

	public := &fasthttp.RequestCtx{}
	public.Request.Header.SetMethod(fasthttp.MethodGet)
	public.Request.SetRequestURI("/ready")
	server.server.Handler(public)
	if public.Response.StatusCode() != fasthttp.StatusNotFound {
		t.Fatalf("public GET /ready status = %d, want 404", public.Response.StatusCode())
	}

	for _, request := range []struct {
		method string
		path   string
	}{
		{method: fasthttp.MethodGet, path: "/v1/models"},
		{method: fasthttp.MethodPost, path: "/ready"},
	} {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(request.method)
		ctx.Request.SetRequestURI(request.path)
		server.readinessServer.Handler(ctx)
		if ctx.Response.StatusCode() == fasthttp.StatusNoContent {
			t.Fatalf("private %s %s unexpectedly served readiness", request.method, request.path)
		}
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

func TestRequestDecompressionChecksAPIKeyBeforeCompressedBody(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/v1/chat/completions")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.Header.Set("Content-Type", "text/plain")
	ctx.Request.SetBodyString("not gzip")

	server.requestDecompression(func(ctx *fasthttp.RequestCtx) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Fatalf("expected 401 before decompression, got %d", ctx.Response.StatusCode())
	}
}

func TestRequestDecompressionChecksContentTypeBeforeCompressedBody(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/v1/responses")
	ctx.Request.Header.Set("Authorization", "Bearer test-key")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.Header.Set("Content-Type", "text/plain")
	ctx.Request.SetBodyString("not gzip")

	server.requestDecompression(func(ctx *fasthttp.RequestCtx) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 before decompression, got %d", ctx.Response.StatusCode())
	}
}

func TestRequestDecompressionCachesInferenceCredential(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteChat))
	ctx.Request.Header.Set("Authorization", "Bearer test-key")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody(gzipBody(t, `{}`))

	called := false
	server.requestDecompression(func(ctx *fasthttp.RequestCtx) {
		called = true
		ctx.Request.Header.Set("Content-Type", "text/plain")
		credential, ok := server.requireInferenceEnvelope(ctx)
		if !ok {
			t.Fatalf("expected cached inference credential to pass, got status %d body %s", ctx.Response.StatusCode(), ctx.Response.Body())
		}
		if credential.Raw != "test-key" {
			t.Fatalf("expected cached token, got %q", credential.Raw)
		}
	})(ctx)

	if !called {
		t.Fatal("expected next handler to be called")
	}
}

func TestWriteInferenceJSONAddsConfidentialProofHeaders(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("p", 128)))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{proofs: &proofhttp.Service{
		Quotes: staticProofQuotes{snapshot: testProofSnapshot(t, publicKey)},
		Signer: privateKey,
	}}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	state := &stogas.State{
		Resolution: &catalog.ResolvedRequest{
			Route:    catalog.RouteResponses,
			Provider: schemas.OpenAI,
			Model:    "gpt-5-nano",
			Deployment: catalog.Deployment{
				ID:                  "deployment-node",
				ModelID:             "model-node",
				ProviderEndpointIDs: []string{"provider-endpoint-node"},
			},
		},
		ProcessedRequestJSON: []byte(`{"processed":true}`),
	}

	server.writeInferenceJSON(ctx, bifrostCtx, state, fasthttp.StatusOK, map[string]any{"ok": true})

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if got := string(ctx.Response.Header.Peek(proofhttp.HeaderQuote)); got != base64.RawURLEncoding.EncodeToString([]byte("quote")) {
		t.Fatalf("unexpected quote header: %q", got)
	}
	nodeIDs := string(ctx.Response.Header.Peek(proofhttp.HeaderResolvedCatalogNodeID))
	if !strings.Contains(nodeIDs, "deployment:deployment-node") || !strings.Contains(nodeIDs, "provider_endpoint:provider-endpoint-node") {
		t.Fatalf("proof did not bind resolved catalog chain: %q", nodeIDs)
	}
	processedHash := string(ctx.Response.Header.Peek(proofhttp.HeaderProcessedHash))
	signature := string(ctx.Response.Header.Peek(proofhttp.HeaderProcessedSignature))
	if processedHash == "" || !proof.Verify(publicKey, processedHash, signature) {
		t.Fatalf("proof signature did not verify: hash=%q signature=%q", processedHash, signature)
	}
}

func TestWriteInferenceJSONFailsClosedWhenProofCannotBeBuilt(t *testing.T) {
	server := &Server{proofs: &proofhttp.Service{}}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	state := &stogas.State{
		Resolution:           testResolution(),
		ProcessedRequestJSON: []byte(`{"processed":true}`),
	}

	server.writeInferenceJSON(ctx, bifrostCtx, state, fasthttp.StatusOK, map[string]any{"ok": true})

	if ctx.Response.StatusCode() != fasthttp.StatusInternalServerError {
		t.Fatalf("expected proof failure to return 500, got %d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if !strings.Contains(string(ctx.Response.Body()), "Failed to build confidential response proof") {
		t.Fatalf("unexpected proof failure body: %s", ctx.Response.Body())
	}
}

type staticProofQuotes struct {
	snapshot *quote.Snapshot
}

func (s staticProofQuotes) Current(ctx context.Context) (*quote.Snapshot, error) {
	return s.snapshot, nil
}

func testProofSnapshot(t *testing.T, publicKey ed25519.PublicKey) *quote.Snapshot {
	t.Helper()
	payload, err := reportdata.NewPayload(reportdata.Payload{
		CatalogHash:        strings.Repeat("b", 64),
		TLSSPKISHA256:      strings.Repeat("c", 64),
		ActiveCertSHA256:   strings.Repeat("d", 64),
		AcceptedCertSHA256: []string{strings.Repeat("d", 64)},
		HPKEPublicKey:      "aHBrZQ",
		Ed25519PublicKey:   base64.RawURLEncoding.EncodeToString(publicKey),
		Drand: reportdata.Drand{
			Round:      1,
			Randomness: strings.Repeat("e", 64),
			Signature:  strings.Repeat("f", 96),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := reportdata.HashHex(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &quote.Snapshot{
		Payload:       payload,
		ReportDataHex: hash,
		Quote:         []byte("quote"),
		GeneratedAt:   time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
	}
}

func TestRequireInferenceEnvelopeChecksAPIKeyBeforeBodyValidation(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteChat))
	ctx.Request.Header.Set("Content-Type", "text/plain")
	ctx.Request.SetBodyString("{}")

	if _, ok := server.requireInferenceEnvelope(ctx); ok {
		t.Fatal("expected missing API key to fail")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Fatalf("expected auth to be checked before content type, got %d", ctx.Response.StatusCode())
	}
}

func TestRequireInferenceEnvelopeRejectsNonJSONContentType(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteChat))
	ctx.Request.Header.Set("Authorization", "Bearer test-key")
	ctx.Request.Header.Set("Content-Type", "text/plain")
	ctx.Request.SetBodyString("{}")

	if _, ok := server.requireInferenceEnvelope(ctx); ok {
		t.Fatal("expected unsupported content type to fail")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", ctx.Response.StatusCode())
	}
}

func TestRequireInferenceEnvelopeAcceptsJSONContentTypeWithParameters(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteChat))
	ctx.Request.Header.Set("Authorization", "Bearer test-key")
	ctx.Request.Header.Set("Content-Type", "application/json; charset=utf-8")
	ctx.Request.SetBodyString("{}")

	if _, ok := server.requireInferenceEnvelope(ctx); !ok {
		t.Fatalf("expected JSON envelope to pass, got status %d body %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

func TestRequireInferenceEnvelopeRejectsEmptyBody(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteChat))
	ctx.Request.Header.Set("Authorization", "Bearer test-key")
	ctx.Request.Header.Set("Content-Type", "application/json")

	if _, ok := server.requireInferenceEnvelope(ctx); ok {
		t.Fatal("expected empty body to fail")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("expected 400, got %d", ctx.Response.StatusCode())
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
		"Anthropic-Organization-Id",
		"Server",
		"X-RateLimit-Limit-Requests",
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
		"OpenAI-Version",
		"Request-Id",
		"X-Request-Id",
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
		"Anthropic-Organization-Id":   "org-secret",
		"Set-Cookie":                  "session=attacker",
		"X-Request-Id":                "provider-request-id",
		"X-RateLimit-Limit-Requests":  "100",
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
	if _, ok := got["Anthropic-Organization-Id"]; ok {
		t.Fatal("expected Anthropic organization headers to be filtered")
	}
	if _, ok := got["X-RateLimit-Limit-Requests"]; ok {
		t.Fatal("expected provider rate-limit headers to be filtered")
	}
	if got["OpenAI-Processing-Ms"] != "41" {
		t.Fatalf("expected trimmed provider metadata header to be retained, got %#v", got)
	}
	if got["X-Request-Id"] != "provider-request-id" {
		t.Fatalf("expected ordinary metadata header to be retained, got %#v", got)
	}
}

func TestSafeProviderResponseHeadersFiltersUnsafeValues(t *testing.T) {
	got := safeProviderResponseHeaders(map[string]string{
		"X-Request-Id":   "provider-request-id",
		"Request-Id":     "line\r\nset-cookie: attacker=true",
		"OpenAI-Version": "2026-01-01\x00hidden",
		"OpenAI-Processing-Ms": string([]byte{
			0xff,
		}),
	})

	if got == nil {
		t.Fatal("expected safe header to be retained")
	}
	if got["X-Request-Id"] != "provider-request-id" {
		t.Fatalf("expected safe request id to be retained, got %#v", got)
	}
	if _, ok := got["Request-Id"]; ok {
		t.Fatalf("expected CRLF header value to be filtered, got %#v", got)
	}
	if _, ok := got["OpenAI-Version"]; ok {
		t.Fatalf("expected NUL header value to be filtered, got %#v", got)
	}
	if _, ok := got["OpenAI-Processing-Ms"]; ok {
		t.Fatalf("expected invalid UTF-8 header value to be filtered, got %#v", got)
	}
}

func TestPublicBifrostErrorMapsConversionErrorWithoutStatusToBadRequest(t *testing.T) {
	status, payload := publicBifrostError(testBifrostError(0, "failed to marshal request: missing required field messages", "", ""))

	if status != fasthttp.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
	errorObject := publicErrorObject(t, payload)
	if errorObject["type"] != "invalid_request_error" {
		t.Fatalf("expected invalid_request_error, got %#v", errorObject)
	}
	if errorObject["message"] != "Invalid request" {
		t.Fatalf("expected scrubbed invalid request message, got %#v", errorObject)
	}
}

func TestPublicBifrostErrorHidesUnknownMissingStatusError(t *testing.T) {
	status, payload := publicBifrostError(testBifrostError(0, "panic: database DSN leaked", "", ""))

	if status != fasthttp.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", status)
	}
	errorObject := publicErrorObject(t, payload)
	if errorObject["type"] != "internal_error" {
		t.Fatalf("expected internal_error, got %#v", errorObject)
	}
	if errorObject["message"] != "Internal server error" {
		t.Fatalf("expected generic internal error message, got %#v", errorObject)
	}
}

func TestPublicBifrostErrorMapsMissingStatusNetworkFailureToServiceUnavailable(t *testing.T) {
	status, payload := publicBifrostError(testBifrostError(0, "provider do request failed: dial tcp: connection refused", "", ""))

	if status != fasthttp.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", status)
	}
	errorObject := publicErrorObject(t, payload)
	if errorObject["type"] != "gateway_error" {
		t.Fatalf("expected gateway_error, got %#v", errorObject)
	}
	if errorObject["message"] != "Upstream provider is unavailable" {
		t.Fatalf("expected generic upstream unavailable message, got %#v", errorObject)
	}
}

func TestPublicBifrostErrorHidesProviderCredentialAndQuotaFailures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		msg    string
		code   string
	}{
		{name: "provider auth", status: fasthttp.StatusUnauthorized, msg: "OpenAI API key is invalid", code: "invalid_api_key"},
		{name: "provider quota", status: fasthttp.StatusPaymentRequired, msg: "upstream account quota exceeded", code: "insufficient_quota"},
		{name: "provider permission", status: fasthttp.StatusForbidden, msg: "organization policy disabled provider access", code: "permission_denied"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, payload := publicBifrostError(testBifrostError(tt.status, tt.msg, "", tt.code))

			if status != fasthttp.StatusServiceUnavailable {
				t.Fatalf("expected 503, got %d", status)
			}
			errorObject := publicErrorObject(t, payload)
			if errorObject["type"] != "gateway_error" {
				t.Fatalf("expected gateway_error, got %#v", errorObject)
			}
			if errorObject["message"] != "Upstream provider is unavailable" {
				t.Fatalf("expected generic upstream unavailable message, got %#v", errorObject)
			}
			if errorObject["code"] != nil {
				t.Fatalf("expected provider code to be hidden, got %#v", errorObject["code"])
			}
		})
	}
}

func TestPublicBifrostErrorMapsProviderRateLimitAndTimeout(t *testing.T) {
	for _, tt := range []struct {
		name        string
		status      int
		msg         string
		wantStatus  int
		wantType    string
		wantMessage string
	}{
		{name: "provider rate limit", status: fasthttp.StatusTooManyRequests, msg: "provider rate_limit exceeded", wantStatus: fasthttp.StatusTooManyRequests, wantType: "rate_limit_error", wantMessage: "provider rate_limit exceeded"},
		{name: "provider timeout", status: fasthttp.StatusGatewayTimeout, msg: "upstream timed out", wantStatus: fasthttp.StatusGatewayTimeout, wantType: schemas.RequestTimedOut, wantMessage: "Upstream request timed out"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, payload := publicBifrostError(testBifrostError(tt.status, tt.msg, "", ""))

			if status != tt.wantStatus {
				t.Fatalf("expected %d, got %d", tt.wantStatus, status)
			}
			errorObject := publicErrorObject(t, payload)
			if errorObject["type"] != tt.wantType {
				t.Fatalf("expected %s, got %#v", tt.wantType, errorObject)
			}
			if errorObject["message"] != tt.wantMessage {
				t.Fatalf("expected %q, got %#v", tt.wantMessage, errorObject)
			}
		})
	}
}

func TestPublicBifrostErrorPreservesSafeClientProviderError(t *testing.T) {
	status, payload := publicBifrostError(testBifrostError(fasthttp.StatusBadRequest, "messages.0.content is required", "invalid_request_error", "missing_required_parameter"))

	if status != fasthttp.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
	errorObject := publicErrorObject(t, payload)
	if errorObject["type"] != "invalid_request_error" {
		t.Fatalf("expected invalid_request_error, got %#v", errorObject)
	}
	if errorObject["message"] != "messages.0.content is required" {
		t.Fatalf("expected provider validation message, got %#v", errorObject)
	}
	if errorObject["code"] != "missing_required_parameter" {
		t.Fatalf("expected provider error code, got %#v", errorObject)
	}
}

func TestPublicBifrostErrorMapsProviderOverload(t *testing.T) {
	status, payload := publicBifrostError(testBifrostError(529, "overloaded", "", ""))

	if status != 529 {
		t.Fatalf("expected 529, got %d", status)
	}
	errorObject := publicErrorObject(t, payload)
	if errorObject["type"] != "overloaded_error" {
		t.Fatalf("expected overloaded_error, got %#v", errorObject)
	}
	if errorObject["message"] != "Upstream provider is overloaded" {
		t.Fatalf("expected overload message, got %#v", errorObject)
	}
}

func TestPublicBifrostErrorMapsRequestTooLarge(t *testing.T) {
	status, payload := publicBifrostError(testBifrostError(fasthttp.StatusRequestEntityTooLarge, "request exceeds maximum size", "", ""))

	if status != fasthttp.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", status)
	}
	errorObject := publicErrorObject(t, payload)
	if errorObject["type"] != "request_too_large" {
		t.Fatalf("expected request_too_large, got %#v", errorObject)
	}
	if errorObject["message"] != "request exceeds maximum size" {
		t.Fatalf("expected safe provider size message, got %#v", errorObject)
	}
}

func TestPublicBifrostErrorMapsRequestCancelled(t *testing.T) {
	status, payload := publicBifrostError(testBifrostError(0, "client cancelled before provider response", schemas.RequestCancelled, ""))

	if status != 499 {
		t.Fatalf("expected 499, got %d", status)
	}
	errorObject := publicErrorObject(t, payload)
	if errorObject["type"] != schemas.RequestCancelled {
		t.Fatalf("expected request_cancelled, got %#v", errorObject)
	}
	if errorObject["message"] != "client cancelled before provider response" {
		t.Fatalf("expected safe cancellation message, got %#v", errorObject)
	}
}

func TestPublicBifrostErrorHidesProviderServerDetails(t *testing.T) {
	status, payload := publicBifrostError(testBifrostError(fasthttp.StatusInternalServerError, "provider stack trace: token=secret", "api_error", ""))

	if status != fasthttp.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", status)
	}
	errorObject := publicErrorObject(t, payload)
	if errorObject["type"] != "gateway_error" {
		t.Fatalf("expected gateway_error, got %#v", errorObject)
	}
	if errorObject["message"] != "Upstream provider error" {
		t.Fatalf("expected scrubbed provider error message, got %#v", errorObject)
	}
}

func testBifrostError(status int, message string, errorType string, code string) *schemas.BifrostError {
	var statusPtr *int
	if status > 0 {
		statusPtr = &status
	}
	var typePtr *string
	if errorType != "" {
		typePtr = &errorType
	}
	var codePtr *string
	if code != "" {
		codePtr = &code
	}
	return &schemas.BifrostError{
		StatusCode: statusPtr,
		Error: &schemas.ErrorField{
			Type:    typePtr,
			Code:    codePtr,
			Message: message,
		},
	}
}

func publicErrorObject(t *testing.T, payload any) map[string]any {
	t.Helper()
	object := publicPayloadObject(t, payload)
	errorObject, ok := object["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %#v", object)
	}
	return errorObject
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
	allowedHeaders := string(ctx.Response.Header.Peek("Access-Control-Allow-Headers"))
	for _, expected := range []string{
		"authorization",
		"content-type",
		"api-key",
		"x-api-key",
		"x-goog-api-key",
		"accept-language",
		"x-stainless-retry-count",
		"x-stainless-timeout",
	} {
		if !strings.Contains(strings.ToLower(allowedHeaders), expected) {
			t.Fatalf("expected CORS headers to include %q, got %q", expected, allowedHeaders)
		}
	}
}

func TestAPIKeyTokenAcceptsCatalogAuthAliases(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
		wantOK  bool
	}{
		{
			name:    "authorization bearer",
			headers: map[string]string{"Authorization": "Bearer sk-sto-bearer"},
			want:    "sk-sto-bearer",
			wantOK:  true,
		},
		{
			name:    "authorization raw token",
			headers: map[string]string{"Authorization": "sk-sto-raw"},
			want:    "sk-sto-raw",
			wantOK:  true,
		},
		{
			name:    "api-key",
			headers: map[string]string{"api-key": "sk-sto-api-key"},
			want:    "sk-sto-api-key",
			wantOK:  true,
		},
		{
			name:    "x-api-key",
			headers: map[string]string{"x-api-key": "sk-sto-x-api-key"},
			want:    "sk-sto-x-api-key",
			wantOK:  true,
		},
		{
			name:    "x-goog-api-key",
			headers: map[string]string{"x-goog-api-key": "sk-sto-google"},
			want:    "sk-sto-google",
			wantOK:  true,
		},
		{
			name: "same token aliases",
			headers: map[string]string{
				"Authorization": "Bearer sk-sto-same",
				"x-api-key":     "sk-sto-same",
			},
			want:   "sk-sto-same",
			wantOK: true,
		},
		{
			name: "conflicting aliases",
			headers: map[string]string{
				"Authorization": "Bearer sk-sto-primary",
				"x-api-key":     "sk-sto-secondary",
			},
			want:   "",
			wantOK: false,
		},
		{
			name:    "missing",
			headers: map[string]string{},
			want:    "",
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			for key, value := range tt.headers {
				ctx.Request.Header.Set(key, value)
			}

			got, ok := apiKeyToken(ctx, catalog.RouteChat)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("expected token=%q ok=%v, got token=%q ok=%v", tt.want, tt.wantOK, got, ok)
			}
		})
	}
}

func TestInferenceHeadersRejectConflictingAuthAliases(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/v1/chat/completions")
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.Header.Set("Authorization", "Bearer sk-test-primary")
	ctx.Request.Header.Set("X-API-Key", "sk-test-secondary")
	ctx.Request.Header.Set("Content-Type", "application/json")

	server := &Server{}
	if _, ok := server.requireInferenceHeaders(ctx); ok {
		t.Fatal("expected conflicting API key aliases to be rejected")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("expected 400 conflicting API key response, got %d", ctx.Response.StatusCode())
	}
	if !strings.Contains(string(ctx.Response.Body()), "Conflicting API key headers") {
		t.Fatalf("expected conflict message, got %s", string(ctx.Response.Body()))
	}
}

func TestInferenceHeadersIgnoreBenignSDKAndTracingHeaders(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/v1/responses")
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.Header.Set("Authorization", "Bearer sk-test")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Accept", "text/event-stream")
	ctx.Request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	ctx.Request.Header.Set("Origin", "https://app.stogas.ai")
	ctx.Request.Header.Set("OpenAI-Organization", "org_client")
	ctx.Request.Header.Set("OpenAI-Project", "proj_client")
	ctx.Request.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
	ctx.Request.Header.Set("X-Datadog-Trace-Id", "123")
	ctx.Request.Header.Set("X-Request-ID", "client-controlled")
	ctx.Request.Header.Set("X-Stainless-Arch", "x64")
	ctx.Request.Header.Set("X-Stainless-Lang", "js")
	ctx.Request.Header.Set("X-Stainless-Package-Version", "6.0.0")
	ctx.Request.Header.Set("X-Stainless-Retry-Count", "0")
	ctx.Request.Header.Set("X-Stainless-Runtime", "node")
	ctx.Request.Header.Set("X-Stainless-Runtime-Version", "24.0.0")
	ctx.Request.Header.Set("X-Stainless-Timeout", "600")

	server := &Server{}
	if _, ok := server.requireInferenceHeaders(ctx); !ok {
		t.Fatalf("expected benign compatibility headers to be ignored, got status %d body %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}
}

func TestInferenceHeadersRejectInternalControlHeaders(t *testing.T) {
	tests := []string{
		"X-BF-Direct-Key",
		"X-BF-EH-Authorization",
		"X-BF-EH-OpenAI-Organization",
		"X-Stogas-Internal-Mode",
	}

	for _, header := range tests {
		t.Run(header, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.SetRequestURI("/v1/responses")
			ctx.Request.Header.SetMethod(fasthttp.MethodPost)
			ctx.Request.Header.Set("Authorization", "Bearer sk-test")
			ctx.Request.Header.Set("Content-Type", "application/json")
			ctx.Request.Header.Set(header, "client-controlled")

			server := &Server{}
			if _, ok := server.requireInferenceHeaders(ctx); ok {
				t.Fatalf("expected %s to be rejected", header)
			}
			if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
				t.Fatalf("expected 400 unsupported header response, got %d", ctx.Response.StatusCode())
			}
			if !strings.Contains(string(ctx.Response.Body()), strings.ToLower(header)) {
				t.Fatalf("expected rejected header in response, got %s", string(ctx.Response.Body()))
			}
		})
	}
}

func TestInferenceHeadersValidateAcceptValues(t *testing.T) {
	tests := []struct {
		accept string
		ok     bool
	}{
		{"", true},
		{"application/json", true},
		{"text/event-stream", true},
		{"application/json, text/event-stream", true},
		{"*/*", true},
		{"text/html", false},
	}

	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.SetRequestURI("/v1/responses")
			ctx.Request.Header.SetMethod(fasthttp.MethodPost)
			ctx.Request.Header.Set("Authorization", "Bearer sk-test")
			ctx.Request.Header.Set("Content-Type", "application/json")
			if tt.accept != "" {
				ctx.Request.Header.Set("Accept", tt.accept)
			}

			_, ok := (&Server{}).requireInferenceHeaders(ctx)
			if ok != tt.ok {
				t.Fatalf("expected ok=%v for Accept %q, got %v with status %d", tt.ok, tt.accept, ok, ctx.Response.StatusCode())
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
			Provider:               schemas.OpenAI,
			OriginalModelRequested: "gpt-5",
			Latency:                12,
		},
	}

	object := publicPayloadObject(t, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
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
			Provider:               schemas.OpenAI,
			OriginalModelRequested: "openai/gpt-5",
			ResolvedModelUsed:      "gpt-5",
			Latency:                12,
		},
	}

	object := publicPayloadObject(t, publicResponsePayload(bifrostCtx, response, response.ExtraFields))
	metadata, ok := object["stogas"].(map[string]any)
	if !ok {
		t.Fatalf("expected stogas metadata, got %#v", object["stogas"])
	}
	if metadata["provider"] != string(schemas.OpenAI) {
		t.Fatalf("expected requested provider metadata, got %#v", metadata)
	}
	if metadata["model_requested"] != "openai/gpt-5" {
		t.Fatalf("expected requested model metadata, got %#v", metadata)
	}
	if _, exists := metadata["model_deployment"]; exists {
		t.Fatalf("did not expect unrequested model_deployment metadata, got %#v", metadata)
	}
}

func TestPublicResponseProviderHeaderMetadataUsesSanitizedState(t *testing.T) {
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	bifrostCtx.SetValue(stogasReturnExtraFieldsKey, map[string]bool{"provider_response_headers": true})
	stogas.SetState(bifrostCtx, &stogas.State{
		ProviderResponseHeaders: map[string]string{
			"X-Request-Id": "adapter-sanitized",
		},
	})

	extra := schemas.BifrostResponseExtraFields{
		ProviderResponseHeaders: map[string]string{
			"X-Request-Id": "raw-extra",
		},
	}
	object := publicPayloadObject(t, publicResponsePayload(bifrostCtx, map[string]any{"id": "bifrost_response"}, extra))
	metadata, ok := object["stogas"].(map[string]any)
	if !ok {
		t.Fatalf("expected stogas metadata, got %#v", object)
	}
	headers, ok := metadata["provider_response_headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected provider response headers metadata, got %#v", metadata["provider_response_headers"])
	}
	if headers["X-Request-Id"] != "adapter-sanitized" {
		t.Fatalf("expected sanitized state provider headers to win, got %#v", headers)
	}
}

func TestPublicResponsePayloadRawResponseMetadata(t *testing.T) {
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	bifrostCtx.SetValue(stogasReturnExtraFieldsKey, map[string]bool{"raw_response": true})

	raw := map[string]any{"id": "raw_provider_response"}
	object := publicPayloadObject(t, publicResponsePayload(bifrostCtx, map[string]any{"id": "bifrost_response"}, schemas.BifrostResponseExtraFields{RawResponse: raw}))
	if object["id"] != "bifrost_response" {
		t.Fatalf("expected normalized response to remain primary, got %#v", object)
	}
	metadata, ok := object["stogas"].(map[string]any)
	if !ok || metadata["raw_response"] == nil {
		t.Fatalf("expected raw response metadata, got %#v", object)
	}
}

func TestPublicResponsePayloadRedactsRawRequestSecrets(t *testing.T) {
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	bifrostCtx.SetValue(stogasReturnExtraFieldsKey, map[string]bool{"raw_request": true})

	raw := map[string]any{
		"mcp_servers": []any{map[string]any{
			"authorization_token": "secret",
			"name":                "remote",
		}},
		"tools": []any{map[string]any{
			"authorization": "secret",
			"server_label":  "remote",
		}},
		"headers": map[string]any{
			"X-Goog-Api-Key": "secret",
			"Accept":         "application/json",
		},
		"nested": map[string]any{
			"accessToken":        "secret",
			"api-key":            "secret",
			"apiKey":             "secret",
			"api_key":            "secret",
			"authorizationToken": "secret",
			"bearer_token":       "secret",
			"client_secret":      "secret",
			"password":           "secret",
			"secretKey":          "secret",
			"token":              "secret",
			"token_count":        float64(42),
			"apikey_hint":        "last4",
			"ordinary_name":      "kept",
		},
	}
	object := publicPayloadObject(t, publicResponsePayload(bifrostCtx, map[string]any{"id": "bifrost_response"}, schemas.BifrostResponseExtraFields{RawRequest: raw}))
	metadata, ok := object["stogas"].(map[string]any)
	if !ok {
		t.Fatalf("expected stogas metadata, got %#v", object)
	}
	redacted, ok := metadata["raw_request"].(map[string]any)
	if !ok {
		t.Fatalf("expected raw request object, got %#v", metadata["raw_request"])
	}
	servers := redacted["mcp_servers"].([]any)
	server := servers[0].(map[string]any)
	if server["authorization_token"] != "<redacted>" || server["name"] != "remote" {
		t.Fatalf("unexpected redacted mcp server %#v", server)
	}
	tools := redacted["tools"].([]any)
	tool := tools[0].(map[string]any)
	if tool["authorization"] != "<redacted>" || tool["server_label"] != "remote" {
		t.Fatalf("unexpected redacted mcp tool %#v", tool)
	}
	headers := redacted["headers"].(map[string]any)
	if headers["X-Goog-Api-Key"] != "<redacted>" || headers["Accept"] != "application/json" {
		t.Fatalf("unexpected redacted headers %#v", headers)
	}
	nested := redacted["nested"].(map[string]any)
	for _, key := range []string{"accessToken", "api-key", "apiKey", "api_key", "authorizationToken", "bearer_token", "client_secret", "password", "secretKey", "token"} {
		if nested[key] != "<redacted>" {
			t.Fatalf("expected nested %s redaction, got %#v", key, nested)
		}
	}
	if nested["token_count"] != float64(42) || nested["apikey_hint"] != "last4" || nested["ordinary_name"] != "kept" {
		t.Fatalf("redacted non-secret fields unexpectedly: %#v", nested)
	}
}

func publicPayloadObject(t *testing.T, payload any) map[string]any {
	t.Helper()
	data, err := marshalPayload(payload)
	if err != nil {
		t.Fatalf("marshal public payload: %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("decode public payload %s: %v", string(data), err)
	}
	return object
}

func TestServerConnectionPolicy(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	server.routes()

	if server.server.Concurrency != 2048 {
		t.Fatalf("Concurrency = %d, want 2048", server.server.Concurrency)
	}
	if server.server.ReadTimeout != 30*time.Second {
		t.Fatalf("ReadTimeout = %s, want 30s", server.server.ReadTimeout)
	}
	if server.server.IdleTimeout != 60*time.Second {
		t.Fatalf("IdleTimeout = %s, want 60s", server.server.IdleTimeout)
	}
	if server.server.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout = %s, want unlimited", server.server.WriteTimeout)
	}
	if !server.server.TCPKeepalive || server.server.TCPKeepalivePeriod != 30*time.Second {
		t.Fatalf("TCP keepalive = %t period=%s, want enabled with 30s period", server.server.TCPKeepalive, server.server.TCPKeepalivePeriod)
	}
	if server.server.ReadBufferSize != 16*1024 {
		t.Fatalf("ReadBufferSize = %d, want 16384", server.server.ReadBufferSize)
	}
	if server.server.StreamRequestBody {
		t.Fatal("Stogas HTTP server should not stream request bodies")
	}
}

func TestShutdownDrainsHTTPBeforeClosingRuntimeDependencies(t *testing.T) {
	source, err := os.ReadFile("http.go")
	if err != nil {
		t.Fatalf("read HTTP transport source: %v", err)
	}
	shutdown := string(source)
	shutdownIndex := strings.Index(shutdown, "func (s *Server) shutdown()")
	if shutdownIndex < 0 {
		t.Fatal("shutdown lifecycle function missing")
	}
	shutdown = shutdown[shutdownIndex:]
	readinessIndex := strings.Index(shutdown, "s.readinessServer.Shutdown()")
	httpIndex := strings.Index(shutdown, "s.server.Shutdown()")
	runtimeIndex := strings.Index(shutdown, "s.runtime.Close()")
	secureIndex := strings.Index(shutdown, "s.secure.Close()")
	if readinessIndex < 0 || httpIndex < 0 || runtimeIndex < 0 || secureIndex < 0 {
		t.Fatalf("shutdown lifecycle calls missing: readiness=%d HTTP=%d runtime=%d secure=%d", readinessIndex, httpIndex, runtimeIndex, secureIndex)
	}
	if readinessIndex > runtimeIndex || readinessIndex > secureIndex || httpIndex > runtimeIndex || httpIndex > secureIndex {
		t.Fatal("both HTTP servers must stop accepting and drain before runtime dependencies close")
	}
}

func TestWriteSSEStreamUsesManagedDirectReader(t *testing.T) {
	source, err := os.ReadFile("http.go")
	if err != nil {
		t.Fatalf("failed to read Stogas HTTP transport source: %v", err)
	}
	text := string(source)

	forbidden := []string{"SetBodyStreamWriter", ".Hijack(", "fasthttputil.NewPipeConns", "fasthttp.NewStreamReader"}
	for _, token := range forbidden {
		if strings.Contains(text, token) {
			t.Fatalf("Stogas SSE streaming must not use %s", token)
		}
	}
	if !strings.Contains(text, "newSSEStreamReader()") || !strings.Contains(text, "SetBodyStream(reader, -1)") {
		t.Fatal("Stogas SSE streaming must use the local SSE stream reader with fasthttp SetBodyStream")
	}
}

func TestInferenceAuthorizesAfterBifrostRequestIsMaterialized(t *testing.T) {
	source, err := os.ReadFile("http.go")
	if err != nil {
		t.Fatalf("failed to read Stogas HTTP transport source: %v", err)
	}
	text := string(source)

	resolveIndex := strings.Index(text, "catalog.ResolveRequest")
	validateIndex := strings.Index(text, "adapter.ValidateRequest(state)")
	toBifrostIndex := strings.Index(text, "resolution.ToBifrost(bifrostCtx)")
	dryRunIndex := strings.Index(text, "dryRunProviderRequestMarshal(bifrostCtx, bifrostReq)")
	authorizeIndex := strings.Index(text, "stogas.AuthorizeState(bifrostCtx")
	if resolveIndex < 0 || validateIndex < 0 || toBifrostIndex < 0 || dryRunIndex < 0 || authorizeIndex < 0 {
		t.Fatalf("expected inference source to include catalog resolution, validation, ToBifrost, dry run, and AuthorizeState, got ResolveRequest=%d Validate=%d ToBifrost=%d dryRun=%d AuthorizeState=%d", resolveIndex, validateIndex, toBifrostIndex, dryRunIndex, authorizeIndex)
	}
	if validateIndex < resolveIndex {
		t.Fatal("request validation must happen after catalog resolution")
	}
	if authorizeIndex < toBifrostIndex {
		t.Fatal("DB hold authorization must happen after the Bifrost request is materialized")
	}
	if authorizeIndex < dryRunIndex {
		t.Fatal("DB hold authorization must happen after provider request marshal dry-run")
	}
}

func TestInferenceDoesNotEnableBifrostExtraHeaders(t *testing.T) {
	source, err := os.ReadFile("http.go")
	if err != nil {
		t.Fatalf("failed to read Stogas HTTP transport source: %v", err)
	}
	if strings.Contains(string(source), "BifrostContextKeyExtraHeaders") {
		t.Fatal("Stogas must not bridge client or state headers into Bifrost extra headers")
	}
}

func TestDryRunProviderRequestMarshalCoversPublicProvidersAndRoutes(t *testing.T) {
	text := "hello"
	maxTokens := 16
	chatContent := &schemas.ChatMessageContent{ContentStr: &text}
	responseRole := schemas.ResponsesInputMessageRoleUser
	responseContent := &schemas.ResponsesMessageContent{ContentStr: &text}

	tests := []struct {
		name string
		req  *schemas.BifrostRequest
	}{
		{
			name: "openai chat completions",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: schemas.OpenAI,
					Model:    "gpt-5-nano",
					Input: []schemas.ChatMessage{{
						Role:    schemas.ChatMessageRoleUser,
						Content: chatContent,
					}},
					Params: &schemas.ChatParameters{MaxCompletionTokens: &maxTokens},
				},
			},
		},
		{
			name: "anthropic chat completions",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: schemas.Anthropic,
					Model:    "claude-sonnet-4-6",
					Input: []schemas.ChatMessage{{
						Role:    schemas.ChatMessageRoleUser,
						Content: chatContent,
					}},
					Params: &schemas.ChatParameters{MaxCompletionTokens: &maxTokens},
				},
			},
		},
		{
			name: "openai responses",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ResponsesRequest,
				ResponsesRequest: &schemas.BifrostResponsesRequest{
					Provider: schemas.OpenAI,
					Model:    "gpt-5-nano",
					Input: []schemas.ResponsesMessage{{
						Role:    &responseRole,
						Content: responseContent,
					}},
					Params: &schemas.ResponsesParameters{MaxOutputTokens: &maxTokens},
				},
			},
		},
		{
			name: "anthropic responses",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ResponsesRequest,
				ResponsesRequest: &schemas.BifrostResponsesRequest{
					Provider: schemas.Anthropic,
					Model:    "claude-sonnet-4-6",
					Input: []schemas.ResponsesMessage{{
						Role:    &responseRole,
						Content: responseContent,
					}},
					Params: &schemas.ResponsesParameters{MaxOutputTokens: &maxTokens},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
			defer cancel()

			if err := dryRunProviderRequestMarshal(bifrostCtx, tt.req); err != nil {
				t.Fatalf("dryRunProviderRequestMarshal returned error: %v", err)
			}
		})
	}
}

func TestWriteSSEStreamEmitsOpenAIFramesFromBodyStream(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)

	server.writeSSEStream(ctx, bifrostCtx, nil, stream, true, false, cancel)
	defer ctx.Response.CloseBodyStream()

	if !ctx.Response.IsBodyStream() {
		t.Fatal("expected SSE response to use fasthttp body streaming")
	}

	go func() {
		stream <- &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				ID:      "chatcmpl_stream_test",
				Object:  "chat.completion.chunk",
				Model:   "gpt-4o-mini",
				Choices: []schemas.BifrostResponseChoice{},
			},
		}
		close(stream)
	}()

	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	payload := requireSSEDataPayload(t, body, "chatcmpl_stream_test")
	if payload["object"] != "chat.completion.chunk" {
		t.Fatalf("expected streamed chat chunk object, got %v in %q", payload["object"], body)
	}
	if !strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("expected OpenAI done marker, got %q", body)
	}
	if strings.Contains(body, "extra_fields") {
		t.Fatalf("streamed public payload leaked extra_fields: %q", body)
	}
}

func TestWriteSSEStreamEmitsFinalConfidentialProof(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("s", 128)))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{proofs: &proofhttp.Service{
		Quotes: staticProofQuotes{snapshot: testProofSnapshot(t, publicKey)},
		Signer: privateKey,
	}}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Resolution: &catalog.ResolvedRequest{
			Route:    catalog.RouteChat,
			Provider: schemas.OpenAI,
			Model:    "gpt-5.5",
			Deployment: catalog.Deployment{
				ID:                  "stream-deployment",
				ModelID:             "stream-model",
				ProviderEndpointIDs: []string{"stream-provider-endpoint"},
			},
		},
		ProcessedRequestJSON: []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`),
	}

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	defer ctx.Response.CloseBodyStream()

	if got := string(ctx.Response.Header.Peek(proofhttp.HeaderQuote)); got != "" {
		t.Fatalf("streaming proof must not be sent as an initial header, got quote header %q", got)
	}

	go func() {
		content := "hello"
		stream <- &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				ID:     "chatcmpl_stream_proof",
				Object: "chat.completion.chunk",
				Model:  "gpt-5.5",
				Choices: []schemas.BifrostResponseChoice{{
					Index: 0,
					ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
						Delta: &schemas.ChatStreamResponseChoiceDelta{Content: &content},
					},
				}},
			},
		}
		close(stream)
	}()

	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	chunkJSON := requireSSEDataFrame(t, body, "chatcmpl_stream_proof")
	proofJSON := requireSSEEventData(t, body, proofhttp.SSEEventName)
	if proofIndex, doneIndex := strings.Index(body, "event: "+proofhttp.SSEEventName+"\n"), strings.Index(body, "data: [DONE]\n\n"); proofIndex < 0 || doneIndex < 0 || proofIndex > doneIndex {
		t.Fatalf("expected final proof before [DONE], got %q", body)
	}

	var proofObject map[string]any
	if err := json.Unmarshal([]byte(proofJSON), &proofObject); err != nil {
		t.Fatalf("failed to parse proof event: %v", err)
	}
	if proofObject["quote"] != base64.RawURLEncoding.EncodeToString([]byte("quote")) {
		t.Fatalf("unexpected proof quote: %#v", proofObject["quote"])
	}
	reportData, ok := proofObject["report_data"].(map[string]any)
	if !ok || reportData["ed25519_public_key"] != base64.RawURLEncoding.EncodeToString(publicKey) {
		t.Fatalf("proof report data did not expose the bound signer key: %#v", proofObject["report_data"])
	}
	nodeIDs := stringSliceFromJSON(t, proofObject["resolved_catalog_node_ids"])
	if !containsString(nodeIDs, "deployment:stream-deployment") || !containsString(nodeIDs, "provider_endpoint:stream-provider-endpoint") {
		t.Fatalf("proof did not bind resolved catalog node ids: %#v", nodeIDs)
	}
	processedHash, _ := proofObject["processed_hash"].(string)
	signature, _ := proofObject["processed_signature"].(string)
	if !proof.VerifyStreamingInput(publicKey, proof.StreamingInput{
		ProcessedRequestJSON: state.ProcessedRequestJSON,
		CatalogNodeIDs:       state.Resolution.CatalogNodeIDs(),
	}, [][]byte{[]byte(chunkJSON)}, processedHash, signature) {
		t.Fatalf("streaming proof did not verify: hash=%q signature=%q body=%q", processedHash, signature, body)
	}
}

func TestWriteSSEStreamDrainsUpstreamAfterBodyStreamClose(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Adapter: stogas.DefaultAdapter{}}
	cancelled := make(chan struct{})
	var once sync.Once

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, func() {
		once.Do(func() { close(cancelled) })
	})

	closer, ok := ctx.Response.BodyStream().(io.Closer)
	if !ok {
		t.Fatal("expected response body stream to be closeable")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("closing body stream failed: %v", err)
	}

	select {
	case <-cancelled:
		t.Fatal("body stream close must not cancel upstream before final usage can be drained")
	default:
	}

	stream <- &schemas.BifrostStreamChunk{
		BifrostChatResponse: &schemas.BifrostChatResponse{
			ID:     "chatcmpl_final_usage",
			Object: "chat.completion.chunk",
			Model:  "gpt-4o-mini",
			Usage: &schemas.BifrostLLMUsage{
				PromptTokens:     17,
				CompletionTokens: 23,
				TotalTokens:      40,
			},
		},
	}
	close(stream)

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("expected upstream cancellation after stream drain completes")
	}
	signals, ok := state.Signals.(*stogas.StandardSignals)
	if !ok || signals.PromptTokens() != 17 || signals.CompletionTokens() != 23 {
		t.Fatalf("expected final usage to be ingested after client disconnect, got %#v", state.Signals)
	}
}

func TestWriteSSEStreamDrainsUpstreamAfterBlockedSendClose(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Adapter: stogas.DefaultAdapter{}}
	cancelled := make(chan struct{})
	var once sync.Once

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, func() {
		once.Do(func() { close(cancelled) })
	})

	closer, ok := ctx.Response.BodyStream().(io.Closer)
	if !ok {
		t.Fatal("expected response body stream to be closeable")
	}

	firstSent := make(chan struct{})
	go func() {
		stream <- &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				ID:      "chatcmpl_first",
				Object:  "chat.completion.chunk",
				Model:   "gpt-4o-mini",
				Choices: []schemas.BifrostResponseChoice{},
			},
		}
		close(firstSent)
	}()
	select {
	case <-firstSent:
	case <-time.After(time.Second):
		t.Fatal("timed out sending first stream chunk")
	}

	secondSent := make(chan struct{})
	go func() {
		stream <- &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				ID:      "chatcmpl_second",
				Object:  "chat.completion.chunk",
				Model:   "gpt-4o-mini",
				Choices: []schemas.BifrostResponseChoice{},
			},
		}
		close(secondSent)
	}()
	select {
	case <-secondSent:
	case <-time.After(time.Second):
		t.Fatal("timed out sending second stream chunk")
	}

	if err := closer.Close(); err != nil {
		t.Fatalf("closing body stream failed: %v", err)
	}
	select {
	case <-cancelled:
		t.Fatal("blocked SSE send close must not cancel upstream before final usage can be drained")
	default:
	}

	select {
	case stream <- &schemas.BifrostStreamChunk{
		BifrostChatResponse: &schemas.BifrostChatResponse{
			ID:     "chatcmpl_final_usage",
			Object: "chat.completion.chunk",
			Model:  "gpt-4o-mini",
			Usage: &schemas.BifrostLLMUsage{
				PromptTokens:     31,
				CompletionTokens: 37,
				TotalTokens:      68,
			},
		},
	}:
	case <-time.After(time.Second):
		t.Fatal("stream goroutine stopped draining after blocked SSE send close")
	}
	close(stream)

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("expected upstream cancellation after stream drain completes")
	}
	signals, ok := state.Signals.(*stogas.StandardSignals)
	if !ok || signals.PromptTokens() != 31 || signals.CompletionTokens() != 37 {
		t.Fatalf("expected final usage to be ingested after blocked send close, got %#v", state.Signals)
	}
}

func TestWriteSSEStreamTimesOutIdleChatStream(t *testing.T) {
	previousTimeout := chatStreamIdleTimeout
	chatStreamIdleTimeout = 10 * time.Millisecond
	defer func() { chatStreamIdleTimeout = previousTimeout }()

	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Adapter: stogas.DefaultAdapter{}, Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}}
	cancelled := make(chan struct{})
	var once sync.Once

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, func() {
		once.Do(func() { close(cancelled) })
	})

	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("expected idle chat stream timeout to cancel upstream")
	}
	payload := requireSSEErrorPayload(t, body)
	if payload["type"] != schemas.RequestTimedOut {
		t.Fatalf("expected request_timed_out stream error, got %#v in %q", payload, body)
	}
	if payload["message"] != "Upstream request timed out" {
		t.Fatalf("expected sanitized timeout message, got %#v", payload)
	}
	if state.BifrostError == nil || state.BifrostError.Type == nil || *state.BifrostError.Type != schemas.RequestTimedOut {
		t.Fatalf("expected idle timeout to mark request state for billing/logging, got %#v", state.BifrostError)
	}
}

func TestWriteSSEStreamDoesNotApplyChatIdleTimeoutToResponses(t *testing.T) {
	previousTimeout := chatStreamIdleTimeout
	chatStreamIdleTimeout = 10 * time.Millisecond
	defer func() { chatStreamIdleTimeout = previousTimeout }()

	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Adapter: stogas.DefaultAdapter{}, Resolution: &catalog.ResolvedRequest{Route: catalog.RouteResponses}}
	cancelled := make(chan struct{})
	var once sync.Once

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, func() {
		once.Do(func() { close(cancelled) })
	})

	go func() {
		time.Sleep(30 * time.Millisecond)
		stream <- &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				ID:      "responses_quiet_stream_allowed",
				Object:  "chat.completion.chunk",
				Model:   "gpt-5.5",
				Choices: []schemas.BifrostResponseChoice{},
			},
		}
		close(stream)
	}()

	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("expected stream completion to cancel upstream")
	}
	if strings.Contains(body, schemas.RequestTimedOut) {
		t.Fatalf("Responses streams must not inherit chat idle timeout, got %q", body)
	}
	payload := requireSSEDataPayload(t, body, "responses_quiet_stream_allowed")
	if payload["id"] != "responses_quiet_stream_allowed" {
		t.Fatalf("expected delayed Responses-route stream chunk, got %#v", payload)
	}
}

func readResponseBodyStream(t *testing.T, reader io.Reader) string {
	t.Helper()

	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		body, err := io.ReadAll(reader)
		done <- result{body: body, err: err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("failed to read response body stream: %v", result.err)
		}
		return string(result.body)
	case <-time.After(time.Second):
		t.Fatal("timed out reading response body stream")
		return ""
	}
}

func requireSSEDataPayload(t *testing.T, body string, id string) map[string]any {
	t.Helper()

	data := requireSSEDataFrame(t, body, id)
	var payload map[string]any
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		t.Fatalf("failed to parse SSE JSON data %q: %v", data, err)
	}
	return payload
}

func requireSSEDataFrame(t *testing.T, body string, id string) string {
	t.Helper()

	for _, frame := range strings.Split(body, "\n\n") {
		data, ok := strings.CutPrefix(strings.TrimSpace(frame), "data: ")
		if !ok || data == "[DONE]" {
			continue
		}

		var payload map[string]any
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatalf("failed to parse SSE JSON frame %q: %v", frame, err)
		}
		if payload["id"] == id {
			return data
		}
	}

	t.Fatalf("expected SSE data frame with id %q, got %q", id, body)
	return ""
}

func requireSSEEventData(t *testing.T, body string, eventName string) string {
	t.Helper()

	for _, frame := range strings.Split(body, "\n\n") {
		lines := strings.Split(strings.TrimSpace(frame), "\n")
		if len(lines) != 2 || lines[0] != "event: "+eventName {
			continue
		}
		data, ok := strings.CutPrefix(lines[1], "data: ")
		if !ok {
			t.Fatalf("expected data line in SSE event frame %q", frame)
		}
		return data
	}

	t.Fatalf("expected SSE event %q, got %q", eventName, body)
	return ""
}

func stringSliceFromJSON(t *testing.T, value any) []string {
	t.Helper()

	items, ok := value.([]any)
	if !ok {
		t.Fatalf("expected JSON array, got %#v", value)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("expected JSON string array item, got %#v", item)
		}
		out = append(out, text)
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func requireSSEErrorPayload(t *testing.T, body string) map[string]any {
	t.Helper()

	for _, frame := range strings.Split(body, "\n\n") {
		data, ok := strings.CutPrefix(strings.TrimSpace(frame), "data: ")
		if !ok || data == "[DONE]" {
			continue
		}

		var payload map[string]any
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatalf("failed to parse SSE JSON frame %q: %v", frame, err)
		}
		errorObject, ok := payload["error"].(map[string]any)
		if ok {
			return errorObject
		}
	}

	t.Fatalf("expected SSE error frame, got %q", body)
	return nil
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
