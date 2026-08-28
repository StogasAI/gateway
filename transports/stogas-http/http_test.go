package stogashttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
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

	bifrostCtx, _, cancel, err := newRequestContext(ctx, testResolution(), apiCredential{Raw: "sk-test"}, stogas.AdapterFor(schemas.OpenAI), "")
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
	if remaining := time.Until(deadline); remaining <= 0 || remaining > billing.GatewayRequestLifetime {
		t.Fatalf("request lifetime remaining = %s, want within %s", remaining, billing.GatewayRequestLifetime)
	}
}

func TestNewRequestContextDoesNotExposeClientHeadersToBifrost(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "Bearer sk-secret")
	ctx.Request.Header.Set("X-OpenAI-Agents-SDK", "client-controlled")

	bifrostCtx, _, cancel, err := newRequestContext(ctx, testResolution(), apiCredential{Raw: "sk-test"}, stogas.AdapterFor(schemas.OpenAI), "")
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

func mustResolvedRequest(t *testing.T, path, body string) *catalog.ResolvedRequest {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: fasthttp.MethodPost,
		Path:   path,
		Body:   []byte(body),
	})
	if err != nil {
		t.Fatalf("resolve catalog request: %v", err)
	}
	return resolution
}

func TestNewRequestContextUsesSharedInferenceLifetime(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	resolution := testResolution()
	resolution.Route = catalog.RouteResponses
	resolution.RequestType = schemas.ResponsesStreamRequest

	bifrostCtx, _, cancel, err := newRequestContext(ctx, resolution, apiCredential{Raw: "sk-test"}, stogas.AdapterFor(schemas.OpenAI), "")
	if err != nil {
		t.Fatalf("newRequestContext returned error: %v", err)
	}
	defer cancel()

	deadline, ok := bifrostCtx.Deadline()
	if !ok {
		t.Fatal("expected gateway request lifetime deadline")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > billing.GatewayRequestLifetime {
		t.Fatalf("responses request lifetime remaining = %s, want within %s", remaining, billing.GatewayRequestLifetime)
	}
	state, ok := stogas.StateFrom(bifrostCtx)
	if !ok || state.RequestLifetime != billing.GatewayRequestLifetime {
		t.Fatalf("expected response request state lifetime %s, got %#v", billing.GatewayRequestLifetime, state)
	}
}

func TestProviderStreamIdleTimeoutUsesRequestLifetime(t *testing.T) {
	for _, test := range []struct {
		name  string
		route catalog.Route
	}{
		{
			name:  "Chat Completions",
			route: catalog.RouteChat,
		},
		{
			name:  "Responses",
			route: catalog.RouteResponses,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := schemas.NewBifrostContext(t.Context(), schemas.NoDeadline)
			state := &stogas.State{
				RequestLifetime: billing.GatewayRequestLifetime,
				Resolution:      &catalog.ResolvedRequest{Route: test.route},
			}
			configureProviderStreamIdleTimeout(ctx, state)
			got, ok := ctx.Value(schemas.BifrostContextKeyStreamIdleTimeout).(time.Duration)
			if !ok || got != billing.GatewayRequestLifetime {
				t.Fatalf("provider stream idle timeout = %s, want %s", got, billing.GatewayRequestLifetime)
			}
		})
	}
}

func mustCatalogPath(t *testing.T, route catalog.Route) string {
	t.Helper()
	for _, path := range catalog.InferencePaths() {
		if candidate, ok := catalog.RouteForPath(path); ok && candidate == route {
			return path
		}
	}
	t.Fatalf("missing catalog path for route %s", route)
	return ""
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

func TestInferenceAttemptsWorkWhenPrivateReadinessIsUnhealthy(t *testing.T) {
	server := &Server{
		config: stogas.Config{MaxRequestBodyMiB: 1},
		secure: &confidentialruntime.Runtime{EntropyReady: true},
	}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.Header.Set("Authorization", "Bearer sk-test")
	ctx.Request.Header.SetContentType("application/json")
	ctx.Request.SetRequestURI("/v1/chat/completions")

	server.inference(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("expected request processing to reach body validation, got %d", ctx.Response.StatusCode())
	}
	if !strings.Contains(string(ctx.Response.Body()), "Request body is required") {
		t.Fatalf("unexpected inference response %q", ctx.Response.Body())
	}
}

func TestPrivateDiagnosticsV1ExposeActionableReasons(t *testing.T) {
	server := &Server{
		config: stogas.Config{MaxRequestBodyMiB: 1},
		secure: &confidentialruntime.Runtime{EntropyReady: true},
	}
	if err := server.routes(); err != nil {
		t.Fatal(err)
	}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/diagnostics/v1")

	server.readinessServer.Handler(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected 200 diagnostics, got %d", ctx.Response.StatusCode())
	}
	var payload struct {
		Control *confidentialruntime.ControlDiagnostics `json:"control"`
		Node    privateNodeDiagnostics                  `json:"node"`
		Ready   bool                                    `json:"ready"`
		Reasons []string                                `json:"reasons"`
		Schema  string                                  `json:"schema"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &payload); err != nil {
		t.Fatalf("decode readiness details: %v", err)
	}
	if payload.Ready || len(payload.Reasons) == 0 {
		t.Fatalf("expected actionable non-ready reasons, got %#v", payload)
	}
	if payload.Schema != "stogas.node-diagnostics.v1" {
		t.Fatalf("unexpected diagnostics schema %q", payload.Schema)
	}
	if payload.Control != nil {
		t.Fatalf("runtime without a Control loop should report null diagnostics, got %#v", payload.Control)
	}
	if payload.Node.GeneratedAt.IsZero() || payload.Node.Process.NumCPU < 1 || payload.Node.Process.GOMAXPROCS < 1 {
		t.Fatalf("private node diagnostics are incomplete: %#v", payload.Node)
	}
	if payload.Node.Listeners.Public.MaximumConnections != serverConcurrency ||
		payload.Node.Listeners.Private.MaximumConnections != readinessConcurrency {
		t.Fatalf("listener diagnostics are incomplete: %#v", payload.Node.Listeners)
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
	publicDetails := &fasthttp.RequestCtx{}
	publicDetails.Request.Header.SetMethod(fasthttp.MethodGet)
	publicDetails.Request.SetRequestURI("/diagnostics/v1")
	server.server.Handler(publicDetails)
	if publicDetails.Response.StatusCode() != fasthttp.StatusNotFound {
		t.Fatalf("public GET /diagnostics/v1 status = %d, want 404", publicDetails.Response.StatusCode())
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

func TestRequestBodyAdmissionAuthenticatesBeforeReadingStream(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}, memory: &requestMemoryAdmission{}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteChat))
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.Header.SetContentType("application/json")
	reader := &countingRequestReader{reader: strings.NewReader(`{"model":"gpt-5"}`)}
	ctx.Request.SetBodyStream(reader, reader.reader.Len())

	server.requestBodyAdmission(func(*fasthttp.RequestCtx) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if reader.reads != 0 {
		t.Fatalf("unauthenticated request body was read %d times", reader.reads)
	}
	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", ctx.Response.StatusCode())
	}
	if !ctx.Response.Header.ConnectionClose() {
		t.Fatal("rejected streamed request must close its connection")
	}
	if used := server.memory.reserved.Load(); used != 0 {
		t.Fatalf("rejected request retained %d memory bytes", used)
	}
}

func TestRequestBodyAdmissionBoundsAndTransfersStreamLease(t *testing.T) {
	body := `{"model":"gpt-5","messages":[{"role":"user","content":"hello"}]}`
	for _, test := range []struct {
		name     string
		bodySize int
	}{
		{name: "fixed length", bodySize: len(body)},
		{name: "chunked", bodySize: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}, memory: &requestMemoryAdmission{}}
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteChat))
			ctx.Request.Header.SetMethod(fasthttp.MethodPost)
			ctx.Request.Header.Set("Authorization", "Bearer test-key")
			ctx.Request.Header.SetContentType("application/json")
			ctx.Request.SetBodyStream(strings.NewReader(body), test.bodySize)

			called := false
			server.requestBodyAdmission(func(ctx *fasthttp.RequestCtx) {
				called = true
				if ctx.Request.IsBodyStream() {
					t.Fatal("admitted body remained a stream")
				}
				if got := string(ctx.Request.Body()); got != body {
					t.Fatalf("body = %q, want %q", got, body)
				}
				lease := requestMemoryLeaseForInference(ctx)
				if lease == nil {
					t.Fatal("request memory lease was not transferred")
				}
				lease.release()
			})(ctx)

			if !called {
				t.Fatal("next handler was not called")
			}
			if used := server.memory.reserved.Load(); used != 0 {
				t.Fatalf("completed request retained %d memory bytes", used)
			}
		})
	}
}

func TestRequestBodyAdmissionRejectsDeclaredOversizeWithoutReading(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}, memory: &requestMemoryAdmission{}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteResponses))
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.Header.Set("Authorization", "Bearer test-key")
	ctx.Request.Header.SetContentType("application/json")
	reader := &countingRequestReader{reader: strings.NewReader("x")}
	ctx.Request.SetBodyStream(reader, 1024*1024+1)

	server.requestBodyAdmission(func(*fasthttp.RequestCtx) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if reader.reads != 0 {
		t.Fatalf("oversized request body was read %d times", reader.reads)
	}
	if ctx.Response.StatusCode() != fasthttp.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", ctx.Response.StatusCode())
	}
	if !ctx.Response.Header.ConnectionClose() {
		t.Fatal("oversized streamed request must close its connection")
	}
}

func TestCompressedBodyKeepsMaximumReservationUntilBoundedDecompression(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}, memory: &requestMemoryAdmission{}}
	compressed := gzipBody(t, `{"model":"gpt-5"}`)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteChat))
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.Header.Set("Authorization", "Bearer test-key")
	ctx.Request.Header.SetContentType("application/json")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.SetBodyStream(bytes.NewReader(compressed), len(compressed))

	server.requestBodyAdmission(func(ctx *fasthttp.RequestCtx) {
		if got, want := server.memory.reserved.Load(), int64(5*1024*1024); got != want {
			t.Fatalf("pre-decompression reservation = %d, want %d", got, want)
		}
		server.requestDecompression(func(ctx *fasthttp.RequestCtx) {
			if got, want := server.memory.reserved.Load(), minimumRequestWeightBytes; got != want {
				t.Fatalf("post-decompression reservation = %d, want %d", got, want)
			}
			lease := requestMemoryLeaseForInference(ctx)
			if lease == nil {
				t.Fatal("request memory lease was not transferred")
			}
			lease.release()
		})(ctx)
	})(ctx)

	if used := server.memory.reserved.Load(); used != 0 {
		t.Fatalf("completed compressed request retained %d memory bytes", used)
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

func TestWriteInferenceJSONAddsSignedStogasReceipt(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("p", 128)))
	if err != nil {
		t.Fatal(err)
	}
	server, material := encryptedTestServer(t)
	server.proofs = &proofhttp.Service{
		Quotes: staticProofQuotes{snapshot: testProofSnapshot(t, publicKey)},
		Signer: privateKey,
	}
	ctx, clientSession := encryptedRequestContext(t, server, material)
	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	bifrostCtx.SetValue(stogasReceiptKey, true)
	state := &stogas.State{
		Resolution: mustResolvedRequest(t, "/v1/chat/completions", `{"model":"gpt-5.5"}`),
		RequestID:  clientSession.RequestID,
		NodeID:     strings.Repeat("3", 64),
		FinalEvent: &billing.RequestEvent{
			CreatedAt:          "2026-08-24T12:34:56.789Z",
			BilledCostUSDAtoms: "0",
		},
	}

	server.writeInferenceJSON(ctx, bifrostCtx, state, fasthttp.StatusOK, map[string]any{"ok": true})

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var response struct {
		OK     bool         `json:"ok"`
		Stogas proof.Object `json:"stogas"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Stogas.CreatedAt != state.FinalEvent.CreatedAt {
		t.Fatalf("unexpected Stogas response: %#v", response)
	}
	unsignedResponse, err := marshalPayload(map[string]any{"ok": true})
	if err != nil {
		t.Fatal(err)
	}
	metadata := proofMetadata(state, encryptedSession(ctx).TranscriptSHA256())
	if !proof.VerifyInput(publicKey, proof.Input{
		RequestBody:  ctx.Request.Body(),
		ResponseBody: unsignedResponse,
		Metadata:     metadata,
	}, response.Stogas.Proof.Signature) {
		t.Fatal("proof did not bind the E2EE request transcript")
	}
	metadata.E2EETranscriptSHA256 = ""
	if proof.VerifyInput(publicKey, proof.Input{
		RequestBody:  ctx.Request.Body(),
		ResponseBody: unsignedResponse,
		Metadata:     metadata,
	}, response.Stogas.Proof.Signature) {
		t.Fatal("E2EE proof verified without its request transcript")
	}
}

func TestWriteInferenceJSONFailsClosedWhenProofCannotBeBuilt(t *testing.T) {
	server := &Server{proofs: &proofhttp.Service{}}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	bifrostCtx.SetValue(stogasReceiptKey, true)
	state := &stogas.State{Resolution: testResolution()}

	server.writeInferenceJSON(ctx, bifrostCtx, state, fasthttp.StatusOK, map[string]any{"ok": true})

	if ctx.Response.StatusCode() != fasthttp.StatusInternalServerError {
		t.Fatalf("expected proof failure to return 500, got %d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if !strings.Contains(string(ctx.Response.Body()), "Failed to build confidential response proof") {
		t.Fatalf("unexpected proof failure body: %s", ctx.Response.Body())
	}
	if !strings.Contains(string(ctx.Response.Body()), responseProofErrorCode) {
		t.Fatalf("proof failure did not include its stable code: %s", ctx.Response.Body())
	}
}

func TestWriteSSEStreamCompletesDrainTrackingWhenProofCannotBeBuilt(t *testing.T) {
	server := &Server{proofs: &proofhttp.Service{}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/v1/chat/completions")
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	bifrostCtx.SetValue(stogasReceiptKey, true)
	completed := make(chan struct{})
	state := &stogas.State{Resolution: testResolution()}

	server.writeSSEStream(
		ctx,
		bifrostCtx,
		state,
		make(chan *schemas.BifrostStreamChunk),
		true,
		false,
		cancel,
		func() { close(completed) },
	)

	if ctx.Response.StatusCode() != fasthttp.StatusInternalServerError {
		t.Fatalf("expected proof failure to return 500, got %d", ctx.Response.StatusCode())
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("proof failure left request drain tracking active")
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
		TLSSPKISHA256:      strings.Repeat("c", 64),
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

func TestRequireInferenceEnvelopeRejectsAmbiguousJSONContentTypeParameters(t *testing.T) {
	for name, contentType := range map[string]string{
		"duplicate charset":   `application/json; charset=utf-8; charset=us-ascii`,
		"invalid syntax":      `application/json; charset`,
		"unsupported charset": `application/json; charset=iso-8859-1`,
		"unknown parameter":   `application/json; boundary=request`,
	} {
		t.Run(name, func(t *testing.T) {
			server := &Server{}
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.SetRequestURI(mustCatalogPath(t, catalog.RouteChat))
			ctx.Request.Header.Set("Authorization", "Bearer test-key")
			ctx.Request.Header.Set("Content-Type", contentType)
			ctx.Request.SetBodyString("{}")

			if _, ok := server.requireInferenceEnvelope(ctx); ok {
				t.Fatalf("ambiguous Content-Type %q was accepted", contentType)
			}
			if ctx.Response.StatusCode() != fasthttp.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", ctx.Response.StatusCode())
			}
		})
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

func TestPublicBifrostErrorClassifiesProviderDependencyFailures(t *testing.T) {
	for _, tt := range []struct {
		name        string
		status      int
		msg         string
		code        string
		wantCode    string
		wantMessage string
	}{
		{name: "provider auth", status: fasthttp.StatusUnauthorized, msg: "OpenAI API key is invalid", code: "invalid_api_key", wantCode: "upstream_authentication_failed", wantMessage: "The configured provider credential was rejected"},
		{name: "provider quota", status: fasthttp.StatusPaymentRequired, msg: "upstream account quota exceeded", code: "insufficient_quota", wantCode: "upstream_quota_exceeded", wantMessage: "The configured provider account has insufficient quota"},
		{name: "provider quota code overrides rate-limit status", status: fasthttp.StatusTooManyRequests, msg: "quota exhausted", code: "insufficient_quota", wantCode: "upstream_quota_exceeded", wantMessage: "The configured provider account has insufficient quota"},
		{name: "provider permission", status: fasthttp.StatusForbidden, msg: "organization policy disabled provider access", code: "permission_denied", wantCode: "upstream_access_denied", wantMessage: "The configured provider credential cannot access the requested model"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, payload := publicBifrostError(testBifrostError(tt.status, tt.msg, "", tt.code))

			if status != fasthttp.StatusBadGateway {
				t.Fatalf("expected 502, got %d", status)
			}
			errorObject := publicErrorObject(t, payload)
			if errorObject["type"] != "gateway_error" {
				t.Fatalf("expected gateway_error, got %#v", errorObject)
			}
			if errorObject["message"] != tt.wantMessage {
				t.Fatalf("expected %q, got %#v", tt.wantMessage, errorObject)
			}
			if errorObject["code"] != tt.wantCode {
				t.Fatalf("expected code %q, got %#v", tt.wantCode, errorObject["code"])
			}
		})
	}
}

func TestPublicBifrostErrorExposesOnlySafePrivateProviderCategories(t *testing.T) {
	for _, tt := range []struct {
		code        string
		status      int
		wantMessage string
	}{
		{code: "upstream_verification_failed", status: fasthttp.StatusServiceUnavailable, wantMessage: "Provider verification failed; the request was not sent"},
		{code: "upstream_capacity_unavailable", status: fasthttp.StatusServiceUnavailable, wantMessage: "No verified private provider capacity is currently available"},
		{code: "upstream_configuration_error", status: fasthttp.StatusServiceUnavailable, wantMessage: "The managed provider configuration is unavailable"},
		{code: "upstream_protocol_error", status: fasthttp.StatusBadGateway, wantMessage: "The provider returned an invalid private response"},
		{code: "gateway_capacity_exceeded", status: fasthttp.StatusServiceUnavailable, wantMessage: "Gateway capacity is temporarily exhausted"},
	} {
		t.Run(tt.code, func(t *testing.T) {
			status, payload := publicBifrostError(testBifrostError(
				fasthttp.StatusServiceUnavailable,
				"sensitive backend detail",
				tt.code,
				tt.code,
			))
			if status != tt.status {
				t.Fatalf("status = %d, want %d", status, tt.status)
			}
			errorObject := publicErrorObject(t, payload)
			if errorObject["code"] != tt.code || errorObject["message"] != tt.wantMessage {
				t.Fatalf("unexpected public error: %#v", errorObject)
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
		{name: "provider rate limit", status: fasthttp.StatusTooManyRequests, msg: "provider rate_limit exceeded", wantStatus: fasthttp.StatusTooManyRequests, wantType: "rate_limit_error", wantMessage: "The upstream provider rate limit was exceeded"},
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
	bifrostErr := testBifrostError(fasthttp.StatusBadRequest, "messages.0.content is required", "invalid_request_error", "missing_required_parameter")
	bifrostErr.Error.Param = "messages[0].content"
	status, payload := publicBifrostError(bifrostErr)

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
	if errorObject["param"] != "messages[0].content" {
		t.Fatalf("expected provider error param, got %#v", errorObject)
	}
}

func TestPublicBifrostErrorBoundsUntrustedProviderFields(t *testing.T) {
	bifrostErr := testBifrostError(
		fasthttp.StatusBadRequest,
		strings.Repeat("x", 1025),
		"invalid_request_error",
		"invalid code with spaces",
	)
	bifrostErr.Error.Param = map[string]any{"attacker": strings.Repeat("x", 4096)}
	status, payload := publicBifrostError(bifrostErr)
	if status != fasthttp.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	errorObject := publicErrorObject(t, payload)
	if errorObject["message"] != "Invalid request" || errorObject["code"] != nil || errorObject["param"] != nil {
		t.Fatalf("untrusted provider fields were reflected: %#v", errorObject)
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
	ctx.Request.Header.Set("Access-Control-Request-Headers", "authorization,content-type,dnt,x-future-ai-sdk-feature")

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
		"dnt",
		"x-future-ai-sdk-feature",
	} {
		if !strings.Contains(strings.ToLower(allowedHeaders), expected) {
			t.Fatalf("expected CORS headers to include %q, got %q", expected, allowedHeaders)
		}
	}
	if got := string(ctx.Response.Header.Peek("Vary")); !strings.Contains(strings.ToLower(got), "access-control-request-headers") {
		t.Fatalf("expected dynamic CORS response to vary by requested headers, got %q", got)
	}
}

func TestAPIKeyTokenAcceptsCatalogAuthAliases(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
		wantErr error
	}{
		{
			name:    "authorization bearer",
			headers: map[string]string{"Authorization": "Bearer sk-sto-bearer"},
			want:    "sk-sto-bearer",
		},
		{
			name:    "authorization requires bearer scheme",
			headers: map[string]string{"Authorization": "sk-sto-raw"},
			wantErr: errMalformedAPIKeyHeader,
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
			name: "same token aliases",
			headers: map[string]string{
				"Authorization": "Bearer sk-sto-same",
				"x-api-key":     "sk-sto-same",
			},
			want: "sk-sto-same",
		},
		{
			name: "conflicting aliases",
			headers: map[string]string{
				"Authorization": "Bearer sk-sto-primary",
				"x-api-key":     "sk-sto-secondary",
			},
			wantErr: errConflictingAPIKeyHeader,
		},
		{
			name: "missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			for key, value := range tt.headers {
				ctx.Request.Header.Set(key, value)
			}

			got, err := apiKeyToken(ctx, catalog.RouteChat)
			if got != tt.want || !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected token=%q error=%v, got token=%q error=%v", tt.want, tt.wantErr, got, err)
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

func TestInferenceHeadersRejectInvalidContentHeaders(t *testing.T) {
	for _, test := range []struct {
		name       string
		headers    [][2]string
		statusCode int
	}{
		{
			name: "stacked content encoding",
			headers: [][2]string{
				{"Content-Type", "application/json"},
				{"Content-Encoding", "gzip"},
				{"Content-Encoding", "br"},
			},
			statusCode: fasthttp.StatusBadRequest,
		},
		{
			name: "unsupported content encoding",
			headers: [][2]string{
				{"Content-Type", "application/json"},
				{"Content-Encoding", "compress"},
			},
			statusCode: fasthttp.StatusBadRequest,
		},
		{
			name: "conflicting accept values",
			headers: [][2]string{
				{"Content-Type", "application/json"},
				{"Accept", "application/json"},
				{"Accept", "text/html"},
			},
			statusCode: fasthttp.StatusBadRequest,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.SetRequestURI("/v1/chat/completions")
			ctx.Request.Header.SetMethod(fasthttp.MethodPost)
			ctx.Request.Header.Set("Authorization", "Bearer sk-test")
			for _, header := range test.headers {
				ctx.Request.Header.Add(header[0], header[1])
			}
			if _, ok := (&Server{}).requireInferenceHeaders(ctx); ok {
				t.Fatal("ambiguous headers were accepted")
			}
			if ctx.Response.StatusCode() != test.statusCode {
				t.Fatalf("status = %d, want %d: %s", ctx.Response.StatusCode(), test.statusCode, ctx.Response.Body())
			}
		})
	}
}

func TestAPIKeyTokenRejectsConflictingRepeatedHeaderValues(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Add("Authorization", "Bearer sk-sto-one")
	ctx.Request.Header.Add("Authorization", "Bearer sk-sto-two")
	if token, err := apiKeyToken(ctx, catalog.RouteChat); token != "" || !errors.Is(err, errConflictingAPIKeyHeader) {
		t.Fatalf("conflicting repeated authorization values returned token=%q error=%v", token, err)
	}

	ctx = &fasthttp.RequestCtx{}
	ctx.Request.Header.Add("Authorization", "Bearer sk-sto-same")
	ctx.Request.Header.Add("Authorization", "sk-sto-same")
	if token, err := apiKeyToken(ctx, catalog.RouteChat); token != "" || !errors.Is(err, errConflictingAPIKeyHeader) {
		t.Fatalf("mixed-scheme repeated authorization values returned token=%q error=%v", token, err)
	}
}

func TestAPIKeyTokenRejectsEmptyWhitespaceAndNonASCIICredentials(t *testing.T) {
	if validCredentialValue("") {
		t.Fatal("empty credential passed value validation")
	}
	for name, value := range map[string]string{
		"space":        "sk-sto two",
		"tab":          "sk-sto\ttwo",
		"non ascii":    "sk-sto-é",
		"control":      "sk-sto-\x1f",
		"too long":     strings.Repeat("a", 4097),
		"wrong scheme": "Basic c2stdGVzdA==",
	} {
		t.Run(name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.Set("Authorization", value)
			if token, err := apiKeyToken(ctx, catalog.RouteChat); token != "" || !errors.Is(err, errMalformedAPIKeyHeader) {
				t.Fatalf("invalid credential returned token=%q error=%v", token, err)
			}
		})
	}
}

func TestReceiptHeaderRejectsRepeatedValues(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Add(stogasHeaderReceipt, "v1")
	ctx.Request.Header.Add(stogasHeaderReceipt, "v1")
	if _, err := receiptHeader(ctx); err == nil {
		t.Fatal("repeated receipt header was accepted")
	}
}

func TestTakeUpstreamCredentialsRejectsRepeatedHeadersAndClearsSecrets(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Add(upstreamOpenAIHeader, "provider-key-one")
	ctx.Request.Header.Add(upstreamOpenAIHeader, "provider-key-two")
	ctx.Request.Header.Set(upstreamAnthropicHeader, "anthropic-secret")
	if credentials, err := takeUpstreamCredentials(ctx); err == nil || credentials != (upstreamCredentialInputs{}) {
		t.Fatalf("repeated upstream credentials returned credentials=%#v error=%v", credentials, err)
	}
	if len(ctx.Request.Header.PeekAll(upstreamOpenAIHeader)) != 0 ||
		len(ctx.Request.Header.PeekAll(upstreamAnthropicHeader)) != 0 {
		t.Fatal("upstream credential headers were not cleared after rejection")
	}
}

func TestInferenceHeadersIgnoreClientMetadata(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/v1/responses")
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.Header.Set("Authorization", "Bearer sk-test")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Accept", "text/event-stream")
	ctx.Request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	ctx.Request.Header.Set("DNT", "1")
	ctx.Request.Header.Set("HTTP-Referer", "https://client.example")
	ctx.Request.Header.Set("Origin", "https://app.stogas.ai")
	ctx.Request.Header.Set("Anthropic-Beta", "future-feature")
	ctx.Request.Header.Set("Anthropic-Version", "2023-06-01")
	ctx.Request.Header.Set("OpenAI-Organization", "org_client")
	ctx.Request.Header.Set("OpenAI-Project", "proj_client")
	ctx.Request.Header.Set("Priority", "u=1, i")
	ctx.Request.Header.Set("Sec-GPC", "1")
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
	ctx.Request.Header.Set("X-Future-AI-SDK-Feature", "client-controlled")
	ctx.Request.Header.Set("X-OpenRouter-Title", "client")

	server := &Server{}
	if _, ok := server.requireInferenceHeaders(ctx); !ok {
		t.Fatalf("expected client metadata headers to be ignored, got status %d body %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
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

func TestReceiptHeaderAcceptsOnlyV1(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  bool
		valid bool
	}{
		{name: "absent", valid: true},
		{name: "v1", value: "v1", want: true, valid: true},
		{name: "whitespace", value: " v1 ", want: true, valid: true},
		{name: "case", value: "V1"},
		{name: "boolean", value: "true"},
		{name: "field list", value: "provider,latency"},
		{name: "number", value: "1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			if test.value != "" {
				ctx.Request.Header.Set(stogasHeaderReceipt, test.value)
			}
			got, err := receiptHeader(ctx)
			if (err == nil) != test.valid || got != test.want {
				t.Fatalf("receiptHeader() = (%v, %v), want (%v, valid=%v)", got, err, test.want, test.valid)
			}
		})
	}
}

func TestTakeUpstreamCredentialsReturnsBoundedPoolAndClearsSensitiveHeaders(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set(upstreamOpenAIHeader, "sk-openai")
	ctx.Request.Header.Set(upstreamAnthropicHeader, "sk-anthropic")
	credentials, err := takeUpstreamCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.OpenAI != "sk-openai" || credentials.Anthropic != "sk-anthropic" || credentials.Chutes != "" {
		t.Fatalf("credentials = %#v", credentials)
	}
	for _, header := range []string{
		upstreamAnthropicHeader,
		upstreamChutesHeader,
		upstreamOpenAIHeader,
	} {
		if len(ctx.Request.Header.Peek(header)) != 0 {
			t.Fatalf("sensitive header %s was retained", header)
		}
	}
}

func TestPassThroughCredentialCannotAuthenticateStogasRequest(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/v1/chat/completions")
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.Header.SetContentType("application/json")
	ctx.Request.Header.Set(upstreamOpenAIHeader, "sk-upstream")

	if _, ok := (&Server{}).requireInferenceHeaders(ctx); ok {
		t.Fatal("pass-through credential authenticated a request without a Stogas API key")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", ctx.Response.StatusCode())
	}
	if len(ctx.Request.Header.Peek(upstreamOpenAIHeader)) != 0 {
		t.Fatal("rejected pass-through credential remained in request headers")
	}
}

func TestUpstreamCredentialPoolSelectsOnlyResolvedProvider(t *testing.T) {
	pool := upstreamCredentialInputs{
		Anthropic: "sk-anthropic",
		Chutes:    "sk-chutes",
		OpenAI:    "sk-openai",
	}
	selected := pool.only("anthropic")
	if selected.Anthropic != "sk-anthropic" || selected.Chutes != "" || selected.OpenAI != "" {
		t.Fatalf("selected pool = %#v", selected)
	}
	if selected.get("openai") != "" || pool.only("azure") != (upstreamCredentialInputs{}) {
		t.Fatal("a credential crossed its resolved provider boundary")
	}
}

func TestTakeUpstreamCredentialsRejectsLegacyGenericHeaders(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("X-Stogas-Upstream-API-Key", "legacy-secret")
	ctx.Request.Header.Set("X-Stogas-Upstream-Provider", "openai")
	credentials, err := takeUpstreamCredentials(ctx)
	if credentials != (upstreamCredentialInputs{}) || err == nil || !strings.Contains(err.Error(), "generic upstream credential headers are unsupported") {
		t.Fatalf("takeUpstreamCredentials() = (%#v, %v)", credentials, err)
	}
	if len(ctx.Request.Header.Peek("X-Stogas-Upstream-API-Key")) != 0 ||
		len(ctx.Request.Header.Peek("X-Stogas-Upstream-Provider")) != 0 {
		t.Fatal("rejected legacy pass-through credential remained in the request headers")
	}
}

func TestTakeUpstreamCredentialsRejectsEmptyCredential(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set(upstreamOpenAIHeader, " ")
	credentials, err := takeUpstreamCredentials(ctx)
	if credentials != (upstreamCredentialInputs{}) || err == nil || !strings.Contains(err.Error(), "is invalid") {
		t.Fatalf("takeUpstreamCredentials() = (%#v, %v)", credentials, err)
	}
	if len(ctx.Request.Header.Peek(upstreamOpenAIHeader)) != 0 {
		t.Fatal("rejected pass-through credential remained in the request headers")
	}
}

func TestPublicResponsePayloadNeverEmbedsUnsignedStogasFields(t *testing.T) {
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()

	payload := publicResponsePayload(
		bifrostCtx,
		map[string]any{"id": "response_1"},
		schemas.BifrostResponseExtraFields{RawRequest: map[string]any{"api_key": "secret"}},
	)
	object := publicPayloadObject(t, payload)
	if object["id"] != "response_1" {
		t.Fatalf("normalized response changed: %#v", object)
	}
	if _, exists := object["stogas"]; exists {
		t.Fatalf("unsigned Stogas fields must not be embedded in the response: %#v", object)
	}
	if _, exists := object["extra_fields"]; exists {
		t.Fatalf("Bifrost fields must not be embedded in the response: %#v", object)
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
	if server.readinessServer.Concurrency != 64 {
		t.Fatalf("readiness Concurrency = %d, want 64", server.readinessServer.Concurrency)
	}
	if server.server.ReadTimeout != 5*time.Minute {
		t.Fatalf("ReadTimeout = %s, want 5m", server.server.ReadTimeout)
	}
	if server.readinessServer.ReadTimeout != 30*time.Second {
		t.Fatalf("readiness ReadTimeout = %s, want 30s", server.readinessServer.ReadTimeout)
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
	if server.server.WriteBufferSize != 4*1024 || server.readinessServer.ReadBufferSize != 4*1024 || server.readinessServer.WriteBufferSize != 4*1024 {
		t.Fatalf("connection buffers = public write %d, readiness read %d/write %d; want 4096 each", server.server.WriteBufferSize, server.readinessServer.ReadBufferSize, server.readinessServer.WriteBufferSize)
	}
	if !server.server.CloseOnShutdown || !server.readinessServer.CloseOnShutdown {
		t.Fatal("both listeners must close keep-alive connections during shutdown")
	}
	if !server.server.StreamRequestBody {
		t.Fatal("Stogas HTTP server must stream request bodies through memory admission")
	}
	if server.server.MaxRequestBodySize != 1024*1024 {
		t.Fatalf("MaxRequestBodySize = %d, want 1048576", server.server.MaxRequestBodySize)
	}
}

func TestPrepareProviderRequestCoversPublicProvidersAndRoutes(t *testing.T) {
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
			name: "openai chat completions stream",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionStreamRequest,
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
			name: "anthropic chat completions stream",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionStreamRequest,
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
			name: "azure chat completions",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: schemas.Azure,
					Model:    "gpt-5.6-terra",
					Input: []schemas.ChatMessage{{
						Role:    schemas.ChatMessageRoleUser,
						Content: chatContent,
					}},
					Params: &schemas.ChatParameters{MaxCompletionTokens: &maxTokens},
				},
			},
		},
		{
			name: "azure chat completions stream",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionStreamRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: schemas.Azure,
					Model:    "gpt-5.6-terra",
					Input: []schemas.ChatMessage{{
						Role:    schemas.ChatMessageRoleUser,
						Content: chatContent,
					}},
					Params: &schemas.ChatParameters{MaxCompletionTokens: &maxTokens},
				},
			},
		},
		{
			name: "chutes chat completions",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: catalog.ProviderChutes,
					Model:    "deepseek-ai/DeepSeek-V3.2",
					Input: []schemas.ChatMessage{{
						Role:    schemas.ChatMessageRoleUser,
						Content: chatContent,
					}},
					Params: &schemas.ChatParameters{MaxCompletionTokens: &maxTokens},
				},
			},
		},
		{
			name: "chutes chat completions stream",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionStreamRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: catalog.ProviderChutes,
					Model:    "deepseek-ai/DeepSeek-V3.2",
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
			name: "openai responses stream",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ResponsesStreamRequest,
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
		{
			name: "anthropic responses stream",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ResponsesStreamRequest,
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
		{
			name: "azure responses",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ResponsesRequest,
				ResponsesRequest: &schemas.BifrostResponsesRequest{
					Provider: schemas.Azure,
					Model:    "gpt-5.6-terra",
					Input: []schemas.ResponsesMessage{{
						Role:    &responseRole,
						Content: responseContent,
					}},
					Params: &schemas.ResponsesParameters{MaxOutputTokens: &maxTokens},
				},
			},
		},
		{
			name: "azure responses stream",
			req: &schemas.BifrostRequest{
				RequestType: schemas.ResponsesStreamRequest,
				ResponsesRequest: &schemas.BifrostResponsesRequest{
					Provider: schemas.Azure,
					Model:    "gpt-5.6-terra",
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
			bifrostCtx.SetValue(schemas.BifrostContextKeyHTTPRequestType, tt.req.RequestType)
			provider, model, _ := tt.req.GetRequestFields()
			state := &stogas.State{Resolution: &catalog.ResolvedRequest{
				Provider:    provider,
				Model:       model,
				RequestType: tt.req.RequestType,
				Deployment:  catalog.Deployment{},
			}}

			if err := stogas.PrepareProviderRequest(bifrostCtx, state, tt.req); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			var body []byte
			if tt.req.ChatRequest != nil {
				body, _ = providerutils.CheckAndGetPreparedRequestBody(bifrostCtx, tt.req.ChatRequest)
			} else {
				body, _ = providerutils.CheckAndGetPreparedRequestBody(bifrostCtx, tt.req.ResponsesRequest)
			}
			if !json.Valid(body) {
				t.Fatalf("prepared body is not valid JSON: %q", body)
			}
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode prepared body: %v", err)
			}
			streaming := tt.req.RequestType == schemas.ChatCompletionStreamRequest || tt.req.RequestType == schemas.ResponsesStreamRequest
			if streaming && payload["stream"] != true {
				t.Fatalf("stream = %#v, want true", payload["stream"])
			}
			if !streaming && payload["stream"] == true {
				t.Fatal("unary prepared body enabled streaming")
			}
			if streaming && tt.req.ChatRequest != nil && provider != schemas.Anthropic {
				streamOptions, ok := payload["stream_options"].(map[string]any)
				if !ok || streamOptions["include_usage"] != true {
					t.Fatalf("stream_options = %#v, want include_usage=true", payload["stream_options"])
				}
			}
			if (provider == schemas.OpenAI || provider == schemas.Azure) && payload["store"] != false {
				t.Fatalf("%s store = %#v, want false", provider, payload["store"])
			}
		})
	}
}

func TestInferenceStreamResponseLimitIsExactAndOverflowSafe(t *testing.T) {
	cases := []struct {
		name    string
		current int
		next    int
		want    bool
	}{
		{name: "below", current: maxInferenceStreamResponseBytes - 2, next: 1},
		{name: "exact", current: maxInferenceStreamResponseBytes - 1, next: 1},
		{name: "one over", current: maxInferenceStreamResponseBytes, next: 1, want: true},
		{name: "single oversized frame", next: maxInferenceStreamResponseBytes + 1, want: true},
		{name: "negative current", current: -1, want: true},
		{name: "negative next", next: -1, want: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := inferenceStreamResponseLimitExceeded(test.current, test.next); got != test.want {
				t.Fatalf("limit result = %t, want %t", got, test.want)
			}
		})
	}
}

func TestWriteSSEStreamRejectsAggregateMemoryGrowthWithoutLeakingReservation(t *testing.T) {
	admission := &requestMemoryAdmission{}
	seeded := requestMemoryBudgetBytes - 1
	admission.reserved.Store(seeded)
	server := &Server{memory: admission}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk, 1)
	stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
		ID: "chatcmpl_capacity", Object: "chat.completion.chunk", Choices: []schemas.BifrostResponseChoice{},
	}}
	close(stream)
	state := &stogas.State{}

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	payload := requireSSEErrorPayload(t, body)
	if payload["code"] != "gateway_capacity_exceeded" || payload["message"] != "Gateway capacity is temporarily exhausted" {
		t.Fatalf("unexpected capacity error: %#v", payload)
	}
	if state.BifrostError == nil || state.BifrostError.Error == nil || state.BifrostError.Error.Code == nil || *state.BifrostError.Error.Code != "gateway_capacity_exceeded" {
		t.Fatalf("capacity failure did not mark final state: %#v", state.BifrostError)
	}
	if got := admission.reserved.Load(); got != seeded {
		t.Fatalf("stream memory reservation leaked: used = %d, want %d", got, seeded)
	}
}

func TestWriteSSEStreamKeepsMemoryReservedUntilBodyDrain(t *testing.T) {
	admission := &requestMemoryAdmission{}
	server := &Server{memory: admission}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk, 1)
	stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
		ID: "chatcmpl_memory", Object: "chat.completion.chunk", Choices: []schemas.BifrostResponseChoice{},
	}}
	close(stream)

	server.writeSSEStream(ctx, bifrostCtx, nil, stream, true, false, cancel)
	deadline := time.Now().Add(time.Second)
	for admission.reserved.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if admission.reserved.Load() == 0 {
		t.Fatal("stream frame did not reserve memory")
	}
	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	if !strings.Contains(body, "chatcmpl_memory") {
		t.Fatalf("stream frame missing: %q", body)
	}
	if got := admission.reserved.Load(); got != 0 {
		t.Fatalf("body drain left %d reserved bytes", got)
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
	if got := string(ctx.Response.Header.Peek("X-Accel-Buffering")); got != "no" {
		t.Fatalf("X-Accel-Buffering = %q, want no", got)
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

func TestWriteSSEStreamKeepsForcedUsagePrivateUnlessClientRequestedIt(t *testing.T) {
	for _, tc := range []struct {
		name          string
		streamOptions string
		wantUsage     bool
	}{
		{name: "omitted", streamOptions: "", wantUsage: false},
		{name: "false", streamOptions: `,"stream_options":{"include_usage":false}`, wantUsage: false},
		{name: "true", streamOptions: `,"stream_options":{"include_usage":true}`, wantUsage: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true` + tc.streamOptions + `}`
			server := &Server{}
			ctx := &fasthttp.RequestCtx{}
			bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
			stream := make(chan *schemas.BifrostStreamChunk)
			state := &stogas.State{
				Adapter:    stogas.DefaultAdapter{},
				Resolution: mustResolvedRequest(t, "/v1/chat/completions", body),
				StartedAt:  time.Now().Add(-5 * time.Millisecond),
			}

			server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
			defer ctx.Response.CloseBodyStream()

			go func() {
				content := "hello"
				role := string(schemas.ChatMessageRoleAssistant)
				finishReason := "stop"
				serviceTier := schemas.BifrostServiceTier(state.Resolution.Deployment.Upstream.ServiceTier)
				stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
					ID:          "chatcmpl_content",
					Object:      "chat.completion.chunk",
					Model:       state.Resolution.Model,
					ServiceTier: &serviceTier,
					Choices: []schemas.BifrostResponseChoice{{
						Index: 0,
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{Role: &role, Content: &content},
						},
					}},
				}}
				stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
					ID:          "chatcmpl_content",
					Object:      "chat.completion.chunk",
					Model:       state.Resolution.Model,
					ServiceTier: &serviceTier,
					Choices: []schemas.BifrostResponseChoice{{
						Index:        0,
						FinishReason: &finishReason,
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{},
						},
					}},
				}}
				stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
					ID:          "chatcmpl_content",
					Object:      "chat.completion.chunk",
					Model:       state.Resolution.Model,
					ServiceTier: &serviceTier,
					Choices:     []schemas.BifrostResponseChoice{},
					Usage: &schemas.BifrostLLMUsage{
						PromptTokens:     1,
						CompletionTokens: 1,
						TotalTokens:      2,
					},
				}}
				close(stream)
			}()

			streamBody := readResponseBodyStream(t, ctx.Response.BodyStream())
			if !strings.Contains(streamBody, "chatcmpl_content") || !strings.Contains(streamBody, "data: [DONE]\n\n") {
				t.Fatalf("stream content or terminator missing: %q", streamBody)
			}
			if got := strings.Contains(streamBody, `"prompt_tokens":1`); got != tc.wantUsage {
				t.Fatalf("usage visibility = %t, want %t: %q", got, tc.wantUsage, streamBody)
			}
			if !state.ProviderOutputObserved {
				t.Fatal("successfully sent content must be recorded as output")
			}
			if state.TTFTMS == nil {
				t.Fatal("successfully sent generated content must record TTFT")
			}
		})
	}
}

func TestWriteSSEStreamIgnoresFramesAfterBillableTerminal(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk, 3)
	state := &stogas.State{
		Adapter: stogas.DefaultAdapter{},
		Resolution: mustResolvedRequest(t, "/v1/chat/completions",
			`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":true}}`),
	}
	role := string(schemas.ChatMessageRoleAssistant)
	content := "hello"
	finishReason := "stop"
	stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
		ID: "chatcmpl_terminal", Object: "chat.completion.chunk",
		Choices: []schemas.BifrostResponseChoice{{
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
				Delta: &schemas.ChatStreamResponseChoiceDelta{Role: &role, Content: &content},
			},
		}},
	}}
	stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
		ID: "chatcmpl_terminal", Object: "chat.completion.chunk",
		Choices: []schemas.BifrostResponseChoice{{
			FinishReason: &finishReason,
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
				Delta: &schemas.ChatStreamResponseChoiceDelta{},
			},
		}},
		Usage: &schemas.BifrostLLMUsage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
	}}
	stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
		ID: "late_invalid_frame", Object: "not-a-chat-chunk",
	}}

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	defer ctx.Response.CloseBodyStream()
	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	if !strings.Contains(body, "chatcmpl_terminal") || !strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("terminal response was not completed normally: %q", body)
	}
	if strings.Contains(body, "late_invalid_frame") || strings.Contains(body, `"error"`) {
		t.Fatalf("post-terminal provider noise changed the response: %q", body)
	}
}

func TestWriteSSEStreamCompletesWithoutTerminalTokenUsage(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Adapter:    stogas.DefaultAdapter{},
		Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat},
	}

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	defer ctx.Response.CloseBodyStream()

	go func() {
		content := "hello"
		role := string(schemas.ChatMessageRoleAssistant)
		finishReason := "stop"
		stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
			ID:     "chatcmpl_missing_usage",
			Object: "chat.completion.chunk",
			Choices: []schemas.BifrostResponseChoice{{
				ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
					Delta: &schemas.ChatStreamResponseChoiceDelta{Role: &role, Content: &content},
				},
			}},
		}}
		stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
			ID:     "chatcmpl_missing_usage",
			Object: "chat.completion.chunk",
			Choices: []schemas.BifrostResponseChoice{{
				FinishReason: &finishReason,
				ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
					Delta: &schemas.ChatStreamResponseChoiceDelta{},
				},
			}},
		}}
		close(stream)
	}()

	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	if !strings.Contains(body, "chatcmpl_missing_usage") || !strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("stream without token usage did not complete normally: %q", body)
	}
	if state.BifrostError != nil {
		t.Fatalf("missing usage changed the provider outcome: %#v", state.BifrostError)
	}
	if stogas.HasMeasuredUsage(state) {
		t.Fatalf("missing usage created chargeable signals: %#v", state.Signals)
	}
}

func TestWriteSSEStreamIgnoresUnusableUsageWithoutFailingOutput(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Adapter:    stogas.DefaultAdapter{},
		Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat},
	}

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	defer ctx.Response.CloseBodyStream()
	go func() {
		role := string(schemas.ChatMessageRoleAssistant)
		finishReason := "stop"
		stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
			ID:     "chatcmpl_invalid_usage",
			Object: "chat.completion.chunk",
			Choices: []schemas.BifrostResponseChoice{{
				Index: 0,
				ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
					Delta: &schemas.ChatStreamResponseChoiceDelta{Role: &role},
				},
			}},
		}}
		stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
			ID:     "chatcmpl_invalid_usage",
			Object: "chat.completion.chunk",
			Choices: []schemas.BifrostResponseChoice{{
				Index:        0,
				FinishReason: &finishReason,
				ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
					Delta: &schemas.ChatStreamResponseChoiceDelta{},
				},
			}},
		}}
		stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
			ID:      "chatcmpl_invalid_usage",
			Object:  "chat.completion.chunk",
			Choices: []schemas.BifrostResponseChoice{},
			Usage:   &schemas.BifrostLLMUsage{PromptTokens: -1},
		}}
		close(stream)
	}()

	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	if !strings.Contains(body, "chatcmpl_invalid_usage") || !strings.Contains(body, "data: [DONE]\n\n") || strings.Contains(body, `"prompt_tokens":-1`) {
		t.Fatalf("unusable private usage changed the successful stream: %q", body)
	}
	if state.BifrostError != nil {
		t.Fatalf("unusable usage changed the provider outcome: %#v", state.BifrostError)
	}
	if stogas.HasMeasuredUsage(state) {
		t.Fatalf("negative usage created chargeable signals: %#v", state.Signals)
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
	ctx.Request.SetBodyString(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	bifrostCtx.SetValue(stogasReceiptKey, true)
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Resolution: mustResolvedRequest(t, "/v1/chat/completions", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true}`),
		Adapter:    stogas.DefaultAdapter{},
		RequestID:  "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		NodeID:     strings.Repeat("3", 64),
		FinalEvent: &billing.RequestEvent{
			CreatedAt:          "2026-08-24T12:34:56.789Z",
			BilledCostUSDAtoms: "0",
		},
	}

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	defer ctx.Response.CloseBodyStream()

	go func() {
		content := "hello"
		role := string(schemas.ChatMessageRoleAssistant)
		finishReason := "stop"
		serviceTier := schemas.BifrostServiceTier(state.Resolution.Deployment.Upstream.ServiceTier)
		stream <- &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				ID:          "chatcmpl_stream_proof",
				Object:      "chat.completion.chunk",
				Model:       state.Resolution.Model,
				ServiceTier: &serviceTier,
				Choices: []schemas.BifrostResponseChoice{{
					Index:        0,
					FinishReason: &finishReason,
					ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
						Delta: &schemas.ChatStreamResponseChoiceDelta{Role: &role, Content: &content},
					},
				}},
			},
		}
		stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
			ID:          "chatcmpl_stream_proof",
			Object:      "chat.completion.chunk",
			Model:       state.Resolution.Model,
			ServiceTier: &serviceTier,
			Choices:     []schemas.BifrostResponseChoice{},
			Usage: &schemas.BifrostLLMUsage{
				PromptTokens:     1,
				CompletionTokens: 1,
				TotalTokens:      2,
			},
		}}
		close(stream)
	}()

	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	chunkJSON := requireSSEDataFrames(t, body, "chatcmpl_stream_proof")
	proofPrefix := ": " + proofhttp.SSECommentPrefix
	proofIndex := strings.Index(body, proofPrefix)
	doneIndex := strings.Index(body, "data: [DONE]\n\n")
	if proofIndex < 0 || doneIndex < 0 || proofIndex > doneIndex {
		t.Fatalf("expected final proof before [DONE], got %q", body)
	}
	proofEnd := strings.Index(body[proofIndex:], "\n\n")
	if proofEnd < 0 {
		t.Fatalf("expected complete final proof comment, got %q", body)
	}
	proofJSON := []byte(strings.TrimSpace(body[proofIndex+len(proofPrefix) : proofIndex+proofEnd]))

	var proofObject proof.Object
	if err := json.Unmarshal(proofJSON, &proofObject); err != nil {
		t.Fatalf("failed to parse proof comment: %v", err)
	}
	proofFrames := make([][]byte, 0, len(chunkJSON)+1)
	for _, chunk := range chunkJSON {
		proofFrames = append(proofFrames, frameSSEEvent("", []byte(chunk)))
	}
	proofFrames = append(proofFrames, frameSSEDone())
	if !proof.VerifyStreamingInput(publicKey, proof.StreamingInput{
		RequestBody: ctx.Request.Body(),
		Metadata:    proofMetadata(state, ""),
	}, proofFrames, proofObject.Proof.Signature) {
		t.Fatalf("streaming proof did not verify: signature=%q body=%q", proofObject.Proof.Signature, body)
	}
}

func TestWriteSSEStreamEmitsReceiptBeforeResponsesTerminalEvent(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("r", 128)))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{proofs: &proofhttp.Service{
		Quotes: staticProofQuotes{snapshot: testProofSnapshot(t, publicKey)},
		Signer: privateKey,
	}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetBodyString(`{"model":"gpt-5.5","input":"hi","stream":true}`)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	bifrostCtx.SetValue(stogasReceiptKey, true)
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Resolution: mustResolvedRequest(t, "/v1/responses", `{"model":"gpt-5.5","input":"hi","stream":true}`),
		Adapter:    stogas.DefaultAdapter{},
		RequestID:  "018f4f70-7c88-7b9a-baf8-31a93d2cf615",
		NodeID:     strings.Repeat("5", 64),
		FinalEvent: &billing.RequestEvent{
			CreatedAt:          "2026-08-24T12:34:56.789Z",
			BilledCostUSDAtoms: "0",
		},
	}

	server.writeSSEStream(ctx, bifrostCtx, state, stream, false, true, cancel)
	defer ctx.Response.CloseBodyStream()
	go func() {
		inProgress := schemas.ResponsesResponseStatusInProgress
		completed := schemas.ResponsesResponseStatusCompleted
		stream <- &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeCreated,
			Response: &schemas.BifrostResponsesResponse{
				ID: schemas.Ptr("resp_stream_proof"), Object: "response", Status: &inProgress,
			},
		}}
		stream <- &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeCompleted, SequenceNumber: 1,
			Response: &schemas.BifrostResponsesResponse{
				ID: schemas.Ptr("resp_stream_proof"), Object: "response", Status: &completed,
				Usage: &schemas.ResponsesResponseUsage{InputTokens: 1, OutputTokens: 1, TotalTokens: 2},
			},
		}}
		close(stream)
	}()

	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	proofPrefix := ": " + proofhttp.SSECommentPrefix
	proofIndex := strings.Index(body, proofPrefix)
	terminalIndex := strings.Index(body, "event: response.completed\n")
	if proofIndex < 0 || terminalIndex < 0 || proofIndex > terminalIndex {
		t.Fatalf("expected receipt before response.completed, got %q", body)
	}
	proofEnd := strings.Index(body[proofIndex:], "\n\n")
	if proofEnd < 0 {
		t.Fatalf("expected complete receipt comment, got %q", body)
	}
	var proofObject proof.Object
	if err := json.Unmarshal([]byte(strings.TrimSpace(body[proofIndex+len(proofPrefix):proofIndex+proofEnd])), &proofObject); err != nil {
		t.Fatal(err)
	}
	unsignedBody := body[:proofIndex] + body[proofIndex+proofEnd+2:]
	if !proof.VerifyStreamingInput(publicKey, proof.StreamingInput{
		RequestBody: ctx.Request.Body(),
		Metadata:    proofMetadata(state, ""),
	}, [][]byte{[]byte(unsignedBody)}, proofObject.Proof.Signature) {
		t.Fatal("Responses receipt did not cover the complete stream including its terminal event")
	}
}

func TestWriteSSEStreamDoesNotProofMalformedStream(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(chan<- *schemas.BifrostStreamChunk, *stogas.State)
	}{
		{
			name: "response ID changes",
			send: func(stream chan<- *schemas.BifrostStreamChunk, state *stogas.State) {
				content := "partial"
				role := string(schemas.ChatMessageRoleAssistant)
				finishReason := "stop"
				serviceTier := schemas.BifrostServiceTier(state.Resolution.Deployment.Upstream.ServiceTier)
				stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
					ID:          "chatcmpl_unproved",
					Object:      "chat.completion.chunk",
					Model:       state.Resolution.Model,
					ServiceTier: &serviceTier,
					Choices: []schemas.BifrostResponseChoice{{
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{Role: &role, Content: &content},
						},
					}},
				}}
				stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
					ID:          "chatcmpl_changed",
					Object:      "chat.completion.chunk",
					Model:       state.Resolution.Model,
					ServiceTier: &serviceTier,
					Choices: []schemas.BifrostResponseChoice{{
						FinishReason: &finishReason,
						ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
							Delta: &schemas.ChatStreamResponseChoiceDelta{},
						},
					}},
				}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("u", 128)))
			if err != nil {
				t.Fatal(err)
			}
			server := &Server{proofs: &proofhttp.Service{
				Quotes: staticProofQuotes{snapshot: testProofSnapshot(t, publicKey)},
				Signer: privateKey,
			}}
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.SetBodyString(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`)
			bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
			bifrostCtx.SetValue(stogasReceiptKey, true)
			stream := make(chan *schemas.BifrostStreamChunk)
			state := &stogas.State{
				Resolution: mustResolvedRequest(t, "/v1/chat/completions", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true}`),
				Adapter:    stogas.DefaultAdapter{},
				RequestID:  "018f4f70-7c88-7b9a-baf8-31a93d2cf614",
				NodeID:     strings.Repeat("4", 64),
			}

			server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
			defer ctx.Response.CloseBodyStream()
			go func() {
				tc.send(stream, state)
				close(stream)
			}()

			body := readResponseBodyStream(t, ctx.Response.BodyStream())
			if strings.Contains(body, ": "+proofhttp.SSECommentPrefix) {
				t.Fatalf("invalid stream received a confidential proof: %q", body)
			}
			if strings.Contains(body, "data: [DONE]\n\n") {
				t.Fatalf("invalid stream received a success terminator: %q", body)
			}
			_ = requireSSEErrorPayload(t, body)
		})
	}
}

func TestWriteSSEStreamDrainsUpstreamAfterBodyStreamClose(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Adapter: stogas.DefaultAdapter{}, StartedAt: time.Now()}
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
	deadline := time.Now().Add(time.Second)
	cancelledByClient, clientStoppedAt := state.ClientStatus()
	for !cancelledByClient && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		cancelledByClient, clientStoppedAt = state.ClientStatus()
	}
	if !cancelledByClient {
		t.Fatal("client stream closure must be recorded as cancellation")
	}
	if state.ProviderOutputObserved {
		t.Fatal("output must not be recorded after the client closes the stream")
	}
	if state.TTFTMS != nil {
		t.Fatalf("unsent output must not record TTFT: %#v", state.TTFTMS)
	}
	if clientStoppedAt.IsZero() || clientStoppedAt.Before(state.StartedAt) {
		t.Fatalf("client stream closure time was not recorded: %#v", clientStoppedAt)
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
	if state.ProviderOutputObserved {
		t.Fatal("unsent protocol-only frames must not be recorded as output")
	}
}

func TestWriteSSEStreamStopsAtRequestLifetime(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithTimeout(t.Context(), 10*time.Millisecond)
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Adapter: stogas.DefaultAdapter{}, Resolution: &catalog.ResolvedRequest{Route: catalog.RouteResponses}}
	completed := make(chan struct{})
	var once sync.Once

	server.writeSSEStream(ctx, bifrostCtx, state, stream, false, true, func() {
		once.Do(func() { close(completed) })
	})

	body := readResponseBodyStream(t, ctx.Response.BodyStream())
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("request lifetime did not stop the stream")
	}
	payload := requireSSEErrorPayload(t, body)
	if payload["type"] != schemas.RequestTimedOut {
		t.Fatalf("expected request_timed_out stream error, got %#v in %q", payload, body)
	}
	if state.BifrostError == nil || state.BifrostError.Error == nil || state.BifrostError.Error.Code == nil || *state.BifrostError.Error.Code != "request_timeout" {
		t.Fatalf("request lifetime did not mark final state: %#v", state.BifrostError)
	}
}

func TestWriteSSEStreamAllowsQuietChatStream(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}}
	cancelled := make(chan struct{})
	var once sync.Once

	server.writeSSEStream(ctx, bifrostCtx, state, stream, true, false, func() {
		once.Do(func() { close(cancelled) })
	})

	go func() {
		time.Sleep(30 * time.Millisecond)
		stream <- &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				ID:      "chatcmpl_quiet_stream_allowed",
				Object:  "chat.completion.chunk",
				Model:   "gpt-5",
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
		t.Fatalf("parsed-chunk silence must not time out a live provider stream, got %q", body)
	}
	payload := requireSSEDataPayload(t, body, "chatcmpl_quiet_stream_allowed")
	if payload["id"] != "chatcmpl_quiet_stream_allowed" {
		t.Fatalf("expected delayed Chat Completions stream chunk, got %#v", payload)
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
	return requireSSEDataFrames(t, body, id)[0]
}

func requireSSEDataFrames(t *testing.T, body string, id string) []string {
	t.Helper()

	var matches []string

	for _, frame := range strings.Split(body, "\n\n") {
		data, ok := strings.CutPrefix(strings.TrimSpace(frame), "data: ")
		if !ok || data == "[DONE]" {
			continue
		}

		var payload map[string]any
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatalf("failed to parse SSE JSON frame %q: %v", frame, err)
		}
		matchesID := payload["id"] == id
		if response, ok := payload["response"].(map[string]any); ok && response["id"] == id {
			matchesID = true
		}
		if matchesID {
			matches = append(matches, data)
		}
	}
	if len(matches) > 0 {
		return matches
	}

	t.Fatalf("expected SSE data frame with id %q, got %q", id, body)
	return nil
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

type countingRequestReader struct {
	reader *strings.Reader
	reads  int
}

func (r *countingRequestReader) Read(buffer []byte) (int, error) {
	r.reads++
	return r.reader.Read(buffer)
}
