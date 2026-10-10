package stogashttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/maximhq/bifrost/transports/stogas/money"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	ref "github.com/StogasAI/verifier/go/reference"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	"net/http"
	"net/http/httptest"
)

func TestNewRequestContextAlwaysGeneratesRequestID(t *testing.T) {
	ctx := newTestRequest(t)
	ctx.request.Header.Set("x-request-id", "client-controlled")

	bifrostCtx, _, cancel, err := newRequestContext(ctx, time.Now(), testResolution(), apiCredential{Raw: "sk-test"}, stogas.AdapterFor(schemas.OpenAI), "")
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
	ctx := newTestRequest(t)
	ctx.request.Header.Set("Authorization", "Bearer sk-secret")
	ctx.request.Header.Set("X-OpenAI-Agents-SDK", "client-controlled")

	bifrostCtx, _, cancel, err := newRequestContext(ctx, time.Now(), testResolution(), apiCredential{Raw: "sk-test"}, stogas.AdapterFor(schemas.OpenAI), "")
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
		Method: http.MethodPost,
		Path:   path,
		Body:   []byte(body),
	})
	if err != nil {
		t.Fatalf("resolve catalog request: %v", err)
	}
	return resolution
}

func TestNewRequestContextUsesSharedInferenceLifetime(t *testing.T) {
	ctx := newTestRequest(t)
	resolution := testResolution()
	resolution.Route = catalog.RouteResponses
	resolution.RequestType = schemas.ResponsesStreamRequest

	bifrostCtx, _, cancel, err := newRequestContext(ctx, time.Now(), resolution, apiCredential{Raw: "sk-test"}, stogas.AdapterFor(schemas.OpenAI), "")
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
	ctx := newTestRequest(t)
	ctx.request.Method = http.MethodGet
	testRequestURI(ctx, "/ready")

	server.readinessServer.Handler.ServeHTTP(ctx.writer, ctx.request)

	if testResponse(ctx).Code != http.StatusNoContent {
		t.Fatalf("expected 204 readiness, got %d", testResponse(ctx).Code)
	}
	if len(testResponse(ctx).Body.Bytes()) != 0 {
		t.Fatalf("readiness probe should not return a body on success, got %q", testResponse(ctx).Body.Bytes())
	}
}

func TestPrivateReadinessProbeFailsClosedForIncompleteConfidentialRuntime(t *testing.T) {
	server := &Server{
		config: stogas.Config{MaxRequestBodyMiB: 1},
		secure: &confidentialruntime.Runtime{},
	}
	if err := server.routes(); err != nil {
		t.Fatal(err)
	}
	ctx := newTestRequest(t)
	ctx.request.Method = http.MethodGet
	testRequestURI(ctx, "/ready")

	server.readinessServer.Handler.ServeHTTP(ctx.writer, ctx.request)

	if testResponse(ctx).Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 readiness, got %d", testResponse(ctx).Code)
	}
	if got := string(testResponse(ctx).Body.Bytes()); got != `{"ok":false}` {
		t.Fatalf("readiness probe should not leak private reasons, got %q", got)
	}
}

func TestTransientMemoryPressureShedsWorkWithoutFailingReadiness(t *testing.T) {
	server := &Server{memory: &requestMemoryAdmission{budget: minimumRequestWeightBytes}}
	lease, ok := server.memory.acquire(0)
	if !ok {
		t.Fatal("initial memory reservation failed")
	}
	defer lease.release()
	ready := newTestRequest(t)
	server.readiness(ready)
	if testResponse(ready).Code != http.StatusNoContent {
		t.Fatal("memory pressure ejected a healthy member")
	}
	request := newTestRequest(t)
	request.memory = nil
	request.body = []byte(`{}`)
	server.inference(request)
	if testResponse(request).Code != http.StatusServiceUnavailable || !strings.Contains(testResponse(request).Body.String(), "gateway_capacity_exceeded") {
		t.Fatal("memory admission did not shed new work")
	}
	if !server.privateDiagnostics().Requests.Memory.Saturated {
		t.Fatal("memory pressure was not observable")
	}
}

func TestDenseJSONIsRejectedBeforeConfigurationFetchOrPolicyCompilation(t *testing.T) {
	for _, path := range []string{"/v1/chat/completions", policyValidationPath} {
		t.Run(path, func(t *testing.T) {
			server := &Server{memory: &requestMemoryAdmission{budget: minimumRequestWeightBytes}}
			ctx := newTestRequest(t)
			ctx.memory.release()
			ctx.request.Method = http.MethodPost
			testRequestURI(ctx, path)
			field := "messages"
			if path == policyValidationPath {
				field = "policySources"
			}
			testRequestBody(ctx, `{"`+field+`":[`+strings.Repeat(`{},`, 6000)+`{}]}`)
			ctx.memory, _ = server.memory.acquire(cap(ctx.body))
			t.Cleanup(ctx.memory.release)
			ctx.credential = &apiCredential{Raw: "authenticated-fixture"}
			if path == policyValidationPath {
				server.validatePolicy(ctx)
			} else {
				// No runtime/database is installed: reaching configuration fetch
				// instead of admission would fail this test.
				server.inference(ctx)
			}
			if testResponse(ctx).Code != http.StatusServiceUnavailable || !strings.Contains(testResponse(ctx).Body.String(), "gateway_capacity_exceeded") {
				t.Fatalf("dense JSON bypassed admission: %d, %s", testResponse(ctx).Code, testResponse(ctx).Body.String())
			}
			ctx.memory.release()
			if server.memory.reserved.Load() != 0 {
				t.Fatal("rejected JSON structure retained memory")
			}
		})
	}
}

func TestPausedAdmissionDoesNotReadRequestBody(t *testing.T) {
	server := &Server{secure: &confidentialruntime.Runtime{}, memory: newRequestMemoryAdmission()}
	request := newTestRequest(t)
	request.request.Method = http.MethodPost
	testRequestURI(request, "/v1/chat/completions")
	reader := &countingRequestReader{reader: strings.NewReader("request body")}
	request.request.Body = io.NopCloser(reader)
	server.publicAdmission(server.requestBodyAdmission(func(*requestContext) { t.Fatal("paused request reached dispatch") }))(request)
	if reader.reads != 0 || server.memory.reserved.Load() != 0 || testResponse(request).Code != http.StatusServiceUnavailable {
		t.Fatal("policy pause did not reject before request work")
	}
}

func TestInferenceStopsBeforeParsingWhenConfidentialReadinessIsUnhealthy(t *testing.T) {
	server := &Server{
		config: stogas.Config{MaxRequestBodyMiB: 1},
		secure: &confidentialruntime.Runtime{},
	}
	ctx := newTestRequest(t)
	ctx.request.Method = http.MethodPost
	ctx.request.Header.Set("Authorization", "Bearer sk-test")
	ctx.request.Header.Set("Content-Type", "application/json")
	testRequestURI(ctx, "/v1/chat/completions")

	server.inference(ctx)

	if testResponse(ctx).Code != http.StatusServiceUnavailable {
		t.Fatalf("expected policy rejection before body validation, got %d", testResponse(ctx).Code)
	}
	if !strings.Contains(string(testResponse(ctx).Body.Bytes()), "gateway_unavailable") {
		t.Fatalf("unexpected inference response %q", testResponse(ctx).Body.Bytes())
	}
}

func TestPrivateDiagnosticsV1ExposeActionableReasons(t *testing.T) {
	server := &Server{
		config: stogas.Config{MaxRequestBodyMiB: 1},
		secure: &confidentialruntime.Runtime{},
	}
	if err := server.routes(); err != nil {
		t.Fatal(err)
	}
	ctx := newTestRequest(t)
	ctx.request.Method = http.MethodGet
	testRequestURI(ctx, "/diagnostics/v1")

	server.diagnosticsServer.Handler.ServeHTTP(ctx.writer, ctx.request)

	if testResponse(ctx).Code != http.StatusOK {
		t.Fatalf("expected 200 diagnostics, got %d", testResponse(ctx).Code)
	}
	var payload struct {
		Maintenance *confidentialruntime.MaintenanceDiagnostics `json:"maintenance"`
		Node        privateNodeDiagnostics                      `json:"node"`
		Ready       bool                                        `json:"ready"`
		Reasons     []string                                    `json:"reasons"`
		Schema      string                                      `json:"schema"`
	}
	if err := json.Unmarshal(testResponse(ctx).Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode readiness details: %v", err)
	}
	if payload.Ready || len(payload.Reasons) == 0 {
		t.Fatalf("expected actionable non-ready reasons, got %#v", payload)
	}
	if payload.Schema != "stogas.node-diagnostics.v1" {
		t.Fatalf("unexpected diagnostics schema %q", payload.Schema)
	}
	if payload.Maintenance != nil || !bytes.Contains(testResponse(ctx).Body.Bytes(), []byte(`"maintenance":null`)) {
		t.Fatalf("uninitialized maintenance should report null diagnostics, got %#v", payload.Maintenance)
	}
	if payload.Node.GeneratedAt.IsZero() || payload.Node.Process.NumCPU < 1 || payload.Node.Process.GOMAXPROCS < 1 {
		t.Fatalf("private node diagnostics are incomplete: %#v", payload.Node)
	}
	if payload.Node.Process.CPUTimeMicros == nil || payload.Node.Process.AllocatedBytes < payload.Node.Process.HeapAllocBytes || payload.Node.Process.Allocations == 0 {
		t.Fatalf("process cost diagnostics are incomplete: %#v", payload.Node.Process)
	}
	process := payload.Node.Process
	if process.GCPercent == nil || process.HeapLiveBytes == nil || process.HeapGoalBytes == nil || *process.HeapGoalBytes < *process.HeapLiveBytes {
		t.Fatalf("GC tuning diagnostics are incomplete: %#v", process)
	}
	if process.GoManagedBytes != process.HeapAllocBytes+process.HeapUnusedBytes+process.HeapFreeBytes+process.StackSystemBytes+process.RuntimeMetadataBytes {
		t.Fatalf("Go memory breakdown does not reconcile: %#v", process)
	}
	if process.GoCPUCapacitySeconds == nil || process.GoGCCPUSeconds == nil || process.GoGCIdleCPUSeconds == nil || process.GCLimiterLastEnabledCycle == nil ||
		*process.GoCPUCapacitySeconds <= 0 || *process.GoGCCPUSeconds < *process.GoGCIdleCPUSeconds || *process.GoCPUCapacitySeconds < *process.GoGCCPUSeconds {
		t.Fatalf("interval GC diagnostics are incomplete or inconsistent: %#v", process)
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

	public := newTestRequest(t)
	public.request.Method = http.MethodGet
	testRequestURI(public, "/ready")
	server.server.Handler.ServeHTTP(public.writer, public.request)
	if testResponse(public).Code != http.StatusNotFound {
		t.Fatalf("public GET /ready status = %d, want 404", testResponse(public).Code)
	}
	publicDetails := newTestRequest(t)
	publicDetails.request.Method = http.MethodGet
	testRequestURI(publicDetails, "/diagnostics/v1")
	server.server.Handler.ServeHTTP(publicDetails.writer, publicDetails.request)
	if testResponse(publicDetails).Code != http.StatusNotFound {
		t.Fatalf("public GET /diagnostics/v1 status = %d, want 404", testResponse(publicDetails).Code)
	}

	for _, request := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/diagnostics/v1"},
		{method: http.MethodGet, path: "/v1/models"},
		{method: http.MethodPost, path: "/ready"},
	} {
		ctx := newTestRequest(t)
		ctx.request.Method = request.method
		testRequestURI(ctx, request.path)
		server.readinessServer.Handler.ServeHTTP(ctx.writer, ctx.request)
		if testResponse(ctx).Code == http.StatusNoContent {
			t.Fatalf("private %s %s unexpectedly served readiness", request.method, request.path)
		}
	}
}

func TestRequestDecompressionGzip(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := newTestRequest(t)
	ctx.request.Header.Set("Content-Encoding", "gzip")
	testRequestBody(ctx, gzipBody(t, `{"model":"gpt-5"}`))

	called := false
	server.requestDecompression(func(ctx *requestContext) {
		called = true
		if got := string(ctx.body); got != `{"model":"gpt-5"}` {
			t.Fatalf("expected decompressed body, got %q", got)
		}
		if encoding := string(ctx.request.Header.Get("Content-Encoding")); encoding != "" {
			t.Fatalf("expected content encoding to be removed, got %q", encoding)
		}
	})(ctx)

	if !called {
		t.Fatal("expected next handler to be called")
	}
}

func TestRequestBodyAdmissionAuthenticatesBeforeReadingStream(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}, memory: &requestMemoryAdmission{}}
	ctx := newTestRequest(t)
	testRequestURI(ctx, mustCatalogPath(t, catalog.RouteChat))
	ctx.request.Method = http.MethodPost
	ctx.request.Header.Set("Content-Type", "application/json")
	reader := &countingRequestReader{reader: strings.NewReader(`{"model":"gpt-5"}`)}
	testRequestBodyStream(ctx, reader, reader.reader.Len())

	server.requestBodyAdmission(func(*requestContext) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if reader.reads != 0 {
		t.Fatalf("unauthenticated request body was read %d times", reader.reads)
	}
	if testResponse(ctx).Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", testResponse(ctx).Code)
	}
	if !(ctx.writer.Header().Get("Connection") == "close") {
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
			ctx := newTestRequest(t)
			testRequestURI(ctx, mustCatalogPath(t, catalog.RouteChat))
			ctx.request.Method = http.MethodPost
			ctx.request.Header.Set("Authorization", "Bearer test-key")
			ctx.request.Header.Set("Content-Type", "application/json")
			testRequestBodyStream(ctx, strings.NewReader(body), test.bodySize)

			called := false
			server.requestBodyAdmission(func(ctx *requestContext) {
				called = true
				if ctx.body == nil {
					t.Fatal("admitted body remained a stream")
				}
				if got := string(ctx.body); got != body {
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
	ctx := newTestRequest(t)
	testRequestURI(ctx, mustCatalogPath(t, catalog.RouteResponses))
	ctx.request.Method = http.MethodPost
	ctx.request.Header.Set("Authorization", "Bearer test-key")
	ctx.request.Header.Set("Content-Type", "application/json")
	reader := &countingRequestReader{reader: strings.NewReader("x")}
	testRequestBodyStream(ctx, reader, 1024*1024+1)

	server.requestBodyAdmission(func(*requestContext) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if reader.reads != 0 {
		t.Fatalf("oversized request body was read %d times", reader.reads)
	}
	if testResponse(ctx).Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", testResponse(ctx).Code)
	}
	if !(ctx.writer.Header().Get("Connection") == "close") {
		t.Fatal("oversized streamed request must close its connection")
	}
}

func TestCompressedBodyKeepsMaximumReservationUntilBoundedDecompression(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}, memory: &requestMemoryAdmission{}}
	compressed := gzipBody(t, `{"model":"gpt-5"}`)
	ctx := newTestRequest(t)
	testRequestURI(ctx, mustCatalogPath(t, catalog.RouteChat))
	ctx.request.Method = http.MethodPost
	ctx.request.Header.Set("Authorization", "Bearer test-key")
	ctx.request.Header.Set("Content-Type", "application/json")
	ctx.request.Header.Set("Content-Encoding", "gzip")
	testRequestBodyStream(ctx, bytes.NewReader(compressed), len(compressed))

	server.requestBodyAdmission(func(ctx *requestContext) {
		if got, want := server.memory.reserved.Load(), minimumRequestWeightBytes; got != want {
			t.Fatalf("pre-decompression reservation = %d, want %d", got, want)
		}
		server.requestDecompression(func(ctx *requestContext) {
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
	ctx := newTestRequest(t)
	ctx.request.Header.Set("Content-Encoding", "gzip")
	testRequestBody(ctx, "not gzip")

	server.requestDecompression(func(ctx *requestContext) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if testResponse(ctx).Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", testResponse(ctx).Code)
	}
	if !strings.Contains(string(testResponse(ctx).Body.Bytes()), "Invalid compressed request body") {
		t.Fatalf("expected invalid compression error, got %s", testResponse(ctx).Body.Bytes())
	}
}

func TestRequestDecompressionEnforcesDecompressedSize(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := newTestRequest(t)
	ctx.request.Header.Set("Content-Encoding", "gzip")
	testRequestBody(ctx, gzipBody(t, strings.Repeat("a", 1024*1024+1)))

	server.requestDecompression(func(ctx *requestContext) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if testResponse(ctx).Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", testResponse(ctx).Code)
	}
}

func TestRequestDecompressionChecksAPIKeyBeforeCompressedBody(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := newTestRequest(t)
	testRequestURI(ctx, "/v1/chat/completions")
	ctx.request.Header.Set("Content-Encoding", "gzip")
	ctx.request.Header.Set("Content-Type", "text/plain")
	testRequestBody(ctx, "not gzip")

	server.requestDecompression(func(ctx *requestContext) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if testResponse(ctx).Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 before decompression, got %d", testResponse(ctx).Code)
	}
}

func TestRequestDecompressionChecksContentTypeBeforeCompressedBody(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := newTestRequest(t)
	testRequestURI(ctx, "/v1/responses")
	ctx.request.Header.Set("Authorization", "Bearer test-key")
	ctx.request.Header.Set("Content-Encoding", "gzip")
	ctx.request.Header.Set("Content-Type", "text/plain")
	testRequestBody(ctx, "not gzip")

	server.requestDecompression(func(ctx *requestContext) {
		t.Fatal("next handler should not be called")
	})(ctx)

	if testResponse(ctx).Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 before decompression, got %d", testResponse(ctx).Code)
	}
}

func TestRequestDecompressionCachesInferenceCredential(t *testing.T) {
	server := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}}
	ctx := newTestRequest(t)
	testRequestURI(ctx, mustCatalogPath(t, catalog.RouteChat))
	ctx.request.Header.Set("Authorization", "Bearer test-key")
	ctx.request.Header.Set("Content-Encoding", "gzip")
	ctx.request.Header.Set("Content-Type", "application/json")
	testRequestBody(ctx, gzipBody(t, `{}`))

	called := false
	server.requestDecompression(func(ctx *requestContext) {
		called = true
		ctx.request.Header.Set("Content-Type", "text/plain")
		credential, ok := server.requireInferenceEnvelope(ctx)
		if !ok {
			t.Fatalf("expected cached inference credential to pass, got status %d body %s", testResponse(ctx).Code, testResponse(ctx).Body.Bytes())
		}
		if credential.Raw != "test-key" {
			t.Fatalf("expected cached token, got %q", credential.Raw)
		}
	})(ctx)

	if !called {
		t.Fatal("expected next handler to be called")
	}
}

func TestWriteInferenceJSONAddsContentReceipt(t *testing.T) {
	service, publicKey, boot := testProofService(t)
	server := &Server{proofs: service}
	ctx := newTestRequest(t)
	testRequestBody(ctx, `{"model":"gpt-5.5"}`)
	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	bifrostCtx.SetValue(stogasMetadataKey, true)
	state := &stogas.State{Resolution: mustResolvedRequest(t, "/v1/chat/completions", string(ctx.body)), RequestID: "req_1", FinalEvent: &billing.RequestEvent{CreatedAt: "2026-08-24T12:34:56.789Z", Usage: billing.RequestUsage{BilledCostUSD: "0", UpstreamCostUSD: "0", Meters: billing.EventMeters{}}}}
	state.FinalEvent.Usage.Meters = billing.EventMeters{
		"input_tokens":        billing.PricedMeter("1000", "per_mill_tokens", "2", "0.002"),
		"cached_input_tokens": billing.PricedMeter("300", "per_mill_tokens", "0", "0"),
		"total_input_tokens":  {Quantity: "1300"},
	}
	state.FinalEvent.Usage.UpstreamCostUSD, state.FinalEvent.Usage.BilledCostUSD = "0.002", "0.00004"
	state.FinalEvent.Usage.CacheReadSavingsUSD, state.FinalEvent.Usage.CacheWriteOverheadUSD = schemas.Ptr("0.0006"), schemas.Ptr("0")
	requestDigest := sha256.Sum256(ctx.body)
	if _, err := ctx.receiptRequestDigest(); err != nil {
		t.Fatal(err)
	}
	ctx.body = nil
	server.writeInferenceJSON(ctx, bifrostCtx, state, http.StatusOK, map[string]any{"ok": true})
	var response struct {
		OK     bool         `json:"ok"`
		Stogas proof.Object `json:"stogas"`
	}
	if err := json.Unmarshal(testResponse(ctx).Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Stogas.CreatedAt != state.FinalEvent.CreatedAt {
		t.Fatal("missing response metadata")
	}
	wantMeters, _ := json.Marshal(state.FinalEvent.Usage.Meters)
	gotMeters, _ := json.Marshal(response.Stogas.Meters)
	if !bytes.Equal(wantMeters, gotMeters) || response.Stogas.UpstreamCostUSD != "0.002" || response.Stogas.BilledCostUSD != "0.00004" ||
		response.Stogas.CacheReadSavingsUSD == nil || *response.Stogas.CacheReadSavingsUSD != "0.0006" ||
		response.Stogas.CacheWriteOverheadUSD == nil || *response.Stogas.CacheWriteOverheadUSD != "0" {
		t.Fatal("response metadata differs from final request history")
	}
	if !verifyReceipt(publicKey, response.Stogas, boot, requestDigest, sha256.Sum256([]byte(`{"ok":true}`))) {
		t.Fatal("receipt does not bind exact request and response")
	}
	if verifyReceipt(publicKey, response.Stogas, boot, sha256.Sum256([]byte(`{}`)), sha256.Sum256([]byte(`{"ok":true}`))) {
		t.Fatal("receipt accepted another request")
	}
	response.Stogas.Meters["total_input_tokens"] = billing.EventMeter{Quantity: "1301"}
	if verifyReceipt(publicKey, response.Stogas, boot, requestDigest, sha256.Sum256([]byte(`{"ok":true}`))) {
		t.Fatal("receipt accepted a changed informational meter")
	}
}

func TestWriteInferenceJSONFailsClosedWhenProofCannotBeBuilt(t *testing.T) {
	server := &Server{proofs: &proofhttp.Service{}}
	ctx := newTestRequest(t)
	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	bifrostCtx.SetValue(stogasMetadataKey, true)
	state := &stogas.State{
		Resolution:        testResolution(),
		FinalEvent:        &billing.RequestEvent{CreatedAt: "2026-08-24T12:34:56.789Z"},
		Authorization:     &billing.Authorization{AuthorizedBilledCostUSD: new(money.USD), AvailableBalanceUSD: new(money.USD)},
		StartedAt:         time.Now().Add(-time.Second),
		ProviderStartedAt: time.Now().Add(-time.Millisecond),
		UpstreamCostUSD:   "0",
		Response:          &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{ID: "response"}},
	}

	server.writeInferenceJSON(ctx, bifrostCtx, state, http.StatusOK, map[string]any{"ok": true})

	if testResponse(ctx).Code != http.StatusInternalServerError {
		t.Fatalf("expected proof failure to return 500, got %d body=%s", testResponse(ctx).Code, testResponse(ctx).Body.Bytes())
	}
	if !strings.Contains(string(testResponse(ctx).Body.Bytes()), "Failed to build confidential response proof") {
		t.Fatalf("unexpected proof failure body: %s", testResponse(ctx).Body.Bytes())
	}
	if !strings.Contains(string(testResponse(ctx).Body.Bytes()), responseProofErrorCode) {
		t.Fatalf("proof failure did not include its stable code: %s", testResponse(ctx).Body.Bytes())
	}
	if state.FinalEvent != nil {
		t.Fatalf("proof failure retained a prepared success event: %#v", state.FinalEvent)
	}
	event := stogas.PrepareFinalState(state)
	if event == nil || event.GatewayError == nil || len(event.ProviderAttempts) != 1 || event.ProviderAttempts[0].Status != "success" ||
		event.ProviderAttempts[0].StatusCode == nil || *event.ProviderAttempts[0].StatusCode != 200 {
		t.Fatalf("proof failure overwrote the successful provider result: %#v", event)
	}
}

func TestWriteSSEStreamCompletesDrainTrackingWhenProofCannotBeBuilt(t *testing.T) {
	server := &Server{proofs: &proofhttp.Service{}}
	ctx := newTestRequest(t)
	ctx.request.Method = http.MethodPost
	testRequestURI(ctx, "/v1/chat/completions")
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	bifrostCtx.SetValue(stogasMetadataKey, true)
	completed := make(chan struct{})
	state := &stogas.State{Resolution: testResolution()}
	stream := make(chan *schemas.BifrostStreamChunk)
	close(stream)

	_ = server.startSSEStream(
		ctx,
		bifrostCtx,
		state,
		stream,
		true,
		false,
		cancel,
		func() { close(completed) },
	)

	if testResponse(ctx).Code != http.StatusInternalServerError {
		t.Fatalf("expected proof failure to return 500, got %d", testResponse(ctx).Code)
	}
	if state.BifrostError != nil || state.ProcessingError == nil || state.ProcessingError.Error == nil ||
		state.ProcessingError.Error.Code == nil || *state.ProcessingError.Error.Code != responseProofErrorCode {
		t.Fatalf("proof failure was not retained separately from provider errors: %#v", state.ProcessingError)
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("proof failure left request drain tracking active")
	}
}

func TestWriteSSEStreamRetainsProofFailureAtCompletion(t *testing.T) {
	service, _, _ := testProofService(t)
	server := &Server{proofs: service}
	ctx := newTestRequest(t)
	testRequestBody(ctx, `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	bifrostCtx.SetValue(stogasMetadataKey, true)
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Resolution: mustResolvedRequest(t, "/v1/chat/completions", string(ctx.body)),
		RequestID:  "", // Invalid final metadata must not become a successful receipt.
		NodeID:     strings.Repeat("3", 64),
		FinalEvent: &billing.RequestEvent{CreatedAt: "2026-08-24T12:34:56.789Z", Usage: billing.RequestUsage{BilledCostUSD: "0", UpstreamCostUSD: "0", Meters: billing.EventMeters{}}},
	}

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	close(stream)
	body := readResponseBodyStream(t, streamBodyReader)
	payload := requireSSEErrorPayload(t, body)
	if payload["code"] != responseProofErrorCode {
		t.Fatalf("proof failure code = %#v, want %q", payload["code"], responseProofErrorCode)
	}
	if state.BifrostError != nil || state.ProcessingError == nil || state.ProcessingError.Error == nil ||
		state.ProcessingError.Error.Code == nil || *state.ProcessingError.Error.Code != responseProofErrorCode {
		t.Fatalf("completed proof failure was not retained separately from provider errors: %#v", state.ProcessingError)
	}
	if state.FinalEvent != nil {
		t.Fatalf("completed proof failure retained a prepared success event: %#v", state.FinalEvent)
	}
}

func testProofService(t *testing.T) (*proofhttp.Service, []byte, [32]byte) {
	t.Helper()
	keys, document, nodeID, err := fixtureNode("testdata/node-boot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	service, err := proofhttp.New(sha256.Sum256(document), nodeID, keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	// Go derives the same composite key independently from the public fixture seeds.
	seed := bytes.Repeat([]byte{42}, 32)
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		t.Fatal(err)
	}
	public := append(key.PublicKey().Bytes(), ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)...)
	return service, public, sha256.Sum256(document)
}

// verifyReceipt independently checks the Rust signer's message, digests and metadata.
func verifyReceipt(public []byte, object proof.Object, boot, request, response [32]byte) bool {
	receipt := object.Receipt
	encoded, err := json.Marshal(object)
	var bag map[string]json.RawMessage
	if err != nil || json.Unmarshal(encoded, &bag) != nil {
		return false
	}
	delete(bag, "receipt")
	if encoded, err = json.Marshal(bag); err != nil {
		return false
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || signatureErr != nil || receipt.Schema != "stogas.receipt.v1" || receipt.BootSHA256 != hex.EncodeToString(boot[:]) ||
		receipt.RequestSHA256 != hex.EncodeToString(request[:]) || receipt.ResponseSHA256 != hex.EncodeToString(response[:]) {
		return false
	}
	digest := sha256.Sum256(canonical)
	message := bytes.Join([][]byte{[]byte("stogas.receipt.v1\x00"), request[:], response[:], digest[:]}, nil)
	return ref.VerifySignature(public, message, signature) == nil
}

func TestRequireInferenceEnvelopeChecksAPIKeyBeforeBodyValidation(t *testing.T) {
	server := &Server{}
	ctx := newTestRequest(t)
	testRequestURI(ctx, mustCatalogPath(t, catalog.RouteChat))
	ctx.request.Header.Set("Content-Type", "text/plain")
	testRequestBody(ctx, "{}")

	if _, ok := server.requireInferenceEnvelope(ctx); ok {
		t.Fatal("expected missing API key to fail")
	}
	if testResponse(ctx).Code != http.StatusUnauthorized {
		t.Fatalf("expected auth to be checked before content type, got %d", testResponse(ctx).Code)
	}
}

func TestRequireInferenceEnvelopeRejectsNonJSONContentType(t *testing.T) {
	server := &Server{}
	ctx := newTestRequest(t)
	testRequestURI(ctx, mustCatalogPath(t, catalog.RouteChat))
	ctx.request.Header.Set("Authorization", "Bearer test-key")
	ctx.request.Header.Set("Content-Type", "text/plain")
	testRequestBody(ctx, "{}")

	if _, ok := server.requireInferenceEnvelope(ctx); ok {
		t.Fatal("expected unsupported content type to fail")
	}
	if testResponse(ctx).Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", testResponse(ctx).Code)
	}
}

func TestRequireInferenceEnvelopeAcceptsJSONContentTypeWithParameters(t *testing.T) {
	server := &Server{}
	ctx := newTestRequest(t)
	testRequestURI(ctx, mustCatalogPath(t, catalog.RouteChat))
	ctx.request.Header.Set("Authorization", "Bearer test-key")
	ctx.request.Header.Set("Content-Type", "application/json; charset=utf-8")
	testRequestBody(ctx, "{}")

	if _, ok := server.requireInferenceEnvelope(ctx); !ok {
		t.Fatalf("expected JSON envelope to pass, got status %d body %s", testResponse(ctx).Code, testResponse(ctx).Body.Bytes())
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
			ctx := newTestRequest(t)
			testRequestURI(ctx, mustCatalogPath(t, catalog.RouteChat))
			ctx.request.Header.Set("Authorization", "Bearer test-key")
			ctx.request.Header.Set("Content-Type", contentType)
			testRequestBody(ctx, "{}")

			if _, ok := server.requireInferenceEnvelope(ctx); ok {
				t.Fatalf("ambiguous Content-Type %q was accepted", contentType)
			}
			if testResponse(ctx).Code != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", testResponse(ctx).Code)
			}
		})
	}
}

func TestRequireInferenceEnvelopeRejectsEmptyBody(t *testing.T) {
	server := &Server{}
	ctx := newTestRequest(t)
	testRequestURI(ctx, mustCatalogPath(t, catalog.RouteChat))
	ctx.request.Header.Set("Authorization", "Bearer test-key")
	ctx.request.Header.Set("Content-Type", "application/json")

	if _, ok := server.requireInferenceEnvelope(ctx); ok {
		t.Fatal("expected empty body to fail")
	}
	if testResponse(ctx).Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", testResponse(ctx).Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	ctx := newTestRequest(t)
	ctx.request.Header.Set("X-Forwarded-Proto", "https")

	securityHeaders(func(ctx *requestContext) {})(ctx)

	expected := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "frame-ancestors 'none'",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}
	for header, value := range expected {
		if got := string(ctx.writer.Header().Get(header)); got != value {
			t.Fatalf("expected %s=%q, got %q", header, value, got)
		}
	}
}

func TestPublicBifrostErrorDoesNotClassifyMessageText(t *testing.T) {
	for _, message := range []string{
		"failed to marshal request: missing required field messages",
		"failed to unmarshal provider response: invalid json",
		"provider do request failed: dial tcp: connection refused",
		"timeout reading private database",
		"panic: database DSN leaked",
	} {
		status, payload := publicBifrostError(testBifrostError(0, message, "", ""))
		errorObject := publicErrorObject(t, payload)
		if status != http.StatusInternalServerError || errorObject["type"] != "internal_error" ||
			errorObject["message"] != "Internal server error" {
			t.Fatalf("message %q affected the public classification: status=%d error=%#v", message, status, errorObject)
		}
	}
}

func TestPublicBifrostErrorUsesStructuredErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		err     *schemas.BifrostError
		status  int
		message string
	}{
		{"Bifrost validation", providerutils.NewBifrostBadRequestError("messages.0.content is required"), 400, "messages.0.content is required"},
		{"Bifrost connection", providerutils.NewBifrostUpstreamConnectionError("private host", errors.New("private network details")), 502, "Upstream provider error"},
		{"Bifrost timeout", providerutils.NewBifrostTimeoutError("private host", errors.New("private network details")), 504, "Upstream request timed out"},
		{"validation without status", testBifrostError(0, "messages.0.content is required", "invalid_request_error", ""), 400, "messages.0.content is required"},
		{"connection without status", testBifrostError(0, "private network details", schemas.ProviderConnectionFailed, ""), 502, "Upstream provider error"},
		{"timeout without status", testBifrostError(0, "private network details", schemas.RequestTimedOut, ""), 504, "Upstream request timed out"},
		{"timeout code without status", testBifrostError(0, "private network details", "", schemas.RequestTimedOut), 504, "Upstream request timed out"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, payload := publicBifrostError(tt.err)
			errorObject := publicErrorObject(t, payload)
			if status != tt.status || errorObject["message"] != tt.message {
				t.Fatalf("status=%d error=%#v, want status=%d message=%q", status, errorObject, tt.status, tt.message)
			}
		})
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
		{name: "provider auth", status: http.StatusUnauthorized, msg: "OpenAI API key is invalid", code: "invalid_api_key", wantCode: "upstream_authentication_failed", wantMessage: "The configured provider credential was rejected"},
		{name: "provider quota", status: http.StatusPaymentRequired, msg: "upstream account quota exceeded", code: "insufficient_quota", wantCode: "upstream_quota_exceeded", wantMessage: "The configured provider account has insufficient quota"},
		{name: "provider quota code overrides rate-limit status", status: http.StatusTooManyRequests, msg: "quota exhausted", code: "insufficient_quota", wantCode: "upstream_quota_exceeded", wantMessage: "The configured provider account has insufficient quota"},
		{name: "provider permission", status: http.StatusForbidden, msg: "organization policy disabled provider access", code: "permission_denied", wantCode: "upstream_access_denied", wantMessage: "The configured provider credential cannot access the requested model"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, payload := publicBifrostError(testBifrostError(tt.status, tt.msg, "", tt.code))

			if status != http.StatusBadGateway {
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
		{code: "upstream_verification_failed", status: http.StatusServiceUnavailable, wantMessage: "Provider verification failed; the request was not sent"},
		{code: "upstream_capacity_unavailable", status: http.StatusServiceUnavailable, wantMessage: "Provider temporarily unavailable."},
		{code: "upstream_configuration_error", status: http.StatusServiceUnavailable, wantMessage: "The managed provider configuration is unavailable"},
		{code: "upstream_protocol_error", status: http.StatusBadGateway, wantMessage: "The provider returned an invalid private response"},
		{code: "gateway_capacity_exceeded", status: http.StatusServiceUnavailable, wantMessage: "Gateway capacity is temporarily exhausted"},
	} {
		t.Run(tt.code, func(t *testing.T) {
			status, payload := publicBifrostError(testBifrostError(
				http.StatusServiceUnavailable,
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
		{name: "provider rate limit", status: http.StatusTooManyRequests, msg: "provider rate_limit exceeded", wantStatus: http.StatusTooManyRequests, wantType: "rate_limit_error", wantMessage: "The upstream provider rate limit was exceeded"},
		{name: "provider timeout", status: http.StatusGatewayTimeout, msg: "upstream timed out", wantStatus: http.StatusGatewayTimeout, wantType: schemas.RequestTimedOut, wantMessage: "Upstream request timed out"},
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
	bifrostErr := testBifrostError(http.StatusBadRequest, "messages.0.content is required", "invalid_request_error", "missing_required_parameter")
	bifrostErr.Error.Param = "messages[0].content"
	status, payload := publicBifrostError(bifrostErr)

	if status != http.StatusBadRequest {
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
		http.StatusBadRequest,
		strings.Repeat("x", 1025),
		"invalid_request_error",
		"invalid code with spaces",
	)
	bifrostErr.Error.Param = map[string]any{"attacker": strings.Repeat("x", 4096)}
	status, payload := publicBifrostError(bifrostErr)
	if status != http.StatusBadRequest {
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
	status, payload := publicBifrostError(testBifrostError(http.StatusRequestEntityTooLarge, "request exceeds maximum size", "", ""))

	if status != http.StatusRequestEntityTooLarge {
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
	status, payload := publicBifrostError(testBifrostError(http.StatusInternalServerError, "provider stack trace: token=secret", "api_error", ""))

	if status != http.StatusInternalServerError {
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
	ctx := newTestRequest(t)
	ctx.request.Method = http.MethodOptions
	ctx.request.Header.Set("Origin", "https://example.com")
	ctx.request.Header.Set("Access-Control-Request-Headers", "authorization,content-type,dnt,x-future-ai-sdk-feature")

	called := false
	cors(func(ctx *requestContext) { called = true })(ctx)

	if called {
		t.Fatal("preflight should not call next handler")
	}
	if testResponse(ctx).Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", testResponse(ctx).Code)
	}
	if got := string(ctx.writer.Header().Get("Access-Control-Allow-Origin")); got != "*" {
		t.Fatalf("expected wildcard CORS origin, got %q", got)
	}
	allowedHeaders := string(ctx.writer.Header().Get("Access-Control-Allow-Headers"))
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
	if got := string(ctx.writer.Header().Get("Vary")); !strings.Contains(strings.ToLower(got), "access-control-request-headers") {
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
			ctx := newTestRequest(t)
			for key, value := range tt.headers {
				ctx.request.Header.Set(key, value)
			}

			got, err := apiKeyToken(ctx, catalog.RouteChat)
			if got != tt.want || !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected token=%q error=%v, got token=%q error=%v", tt.want, tt.wantErr, got, err)
			}
		})
	}
}

func TestInferenceHeadersRejectConflictingAuthAliases(t *testing.T) {
	ctx := newTestRequest(t)
	testRequestURI(ctx, "/v1/chat/completions")
	ctx.request.Method = http.MethodPost
	ctx.request.Header.Set("Authorization", "Bearer sk-test-primary")
	ctx.request.Header.Set("X-API-Key", "sk-test-secondary")
	ctx.request.Header.Set("Content-Type", "application/json")

	server := &Server{}
	if _, ok := server.requireInferenceHeaders(ctx); ok {
		t.Fatal("expected conflicting API key aliases to be rejected")
	}
	if testResponse(ctx).Code != http.StatusBadRequest {
		t.Fatalf("expected 400 conflicting API key response, got %d", testResponse(ctx).Code)
	}
	if !strings.Contains(string(testResponse(ctx).Body.Bytes()), "Conflicting API key headers") {
		t.Fatalf("expected conflict message, got %s", string(testResponse(ctx).Body.Bytes()))
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
			statusCode: http.StatusBadRequest,
		},
		{
			name: "unsupported content encoding",
			headers: [][2]string{
				{"Content-Type", "application/json"},
				{"Content-Encoding", "compress"},
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "conflicting accept values",
			headers: [][2]string{
				{"Content-Type", "application/json"},
				{"Accept", "application/json"},
				{"Accept", "text/html"},
			},
			statusCode: http.StatusBadRequest,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestRequest(t)
			testRequestURI(ctx, "/v1/chat/completions")
			ctx.request.Method = http.MethodPost
			ctx.request.Header.Set("Authorization", "Bearer sk-test")
			for _, header := range test.headers {
				ctx.request.Header.Add(header[0], header[1])
			}
			if _, ok := (&Server{}).requireInferenceHeaders(ctx); ok {
				t.Fatal("ambiguous headers were accepted")
			}
			if testResponse(ctx).Code != test.statusCode {
				t.Fatalf("status = %d, want %d: %s", testResponse(ctx).Code, test.statusCode, testResponse(ctx).Body.Bytes())
			}
		})
	}
}

func TestAPIKeyTokenRejectsConflictingRepeatedHeaderValues(t *testing.T) {
	ctx := newTestRequest(t)
	ctx.request.Header.Add("Authorization", "Bearer sk-sto-one")
	ctx.request.Header.Add("Authorization", "Bearer sk-sto-two")
	if token, err := apiKeyToken(ctx, catalog.RouteChat); token != "" || !errors.Is(err, errConflictingAPIKeyHeader) {
		t.Fatalf("conflicting repeated authorization values returned token=%q error=%v", token, err)
	}

	ctx = newTestRequest(t)
	ctx.request.Header.Add("Authorization", "Bearer sk-sto-same")
	ctx.request.Header.Add("Authorization", "sk-sto-same")
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
			ctx := newTestRequest(t)
			ctx.request.Header.Set("Authorization", value)
			if token, err := apiKeyToken(ctx, catalog.RouteChat); token != "" || !errors.Is(err, errMalformedAPIKeyHeader) {
				t.Fatalf("invalid credential returned token=%q error=%v", token, err)
			}
		})
	}
}

func TestReceiptHeaderRejectsRepeatedValues(t *testing.T) {
	ctx := newTestRequest(t)
	ctx.request.Header.Add(stogasHeaderMetadata, "v1")
	ctx.request.Header.Add(stogasHeaderMetadata, "v1")
	if _, err := metadataHeader(ctx); err == nil {
		t.Fatal("repeated receipt header was accepted")
	}
}

func TestInferenceHeadersIgnoreClientMetadata(t *testing.T) {
	ctx := newTestRequest(t)
	testRequestURI(ctx, "/v1/responses")
	ctx.request.Method = http.MethodPost
	ctx.request.Header.Set("Authorization", "Bearer sk-test")
	ctx.request.Header.Set("Content-Type", "application/json")
	ctx.request.Header.Set("Accept", "text/event-stream")
	ctx.request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	ctx.request.Header.Set("DNT", "1")
	ctx.request.Header.Set("HTTP-Referer", "https://client.example")
	ctx.request.Header.Set("Origin", "https://app.stogas.ai")
	ctx.request.Header.Set("Anthropic-Beta", "future-feature")
	ctx.request.Header.Set("Anthropic-Version", "2023-06-01")
	ctx.request.Header.Set("OpenAI-Organization", "org_client")
	ctx.request.Header.Set("OpenAI-Project", "proj_client")
	ctx.request.Header.Set("Priority", "u=1, i")
	ctx.request.Header.Set("Sec-GPC", "1")
	ctx.request.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
	ctx.request.Header.Set("X-Datadog-Trace-Id", "123")
	ctx.request.Header.Set("X-Request-ID", "client-controlled")
	ctx.request.Header.Set("X-Stainless-Arch", "x64")
	ctx.request.Header.Set("X-Stainless-Lang", "js")
	ctx.request.Header.Set("X-Stainless-Package-Version", "6.0.0")
	ctx.request.Header.Set("X-Stainless-Retry-Count", "0")
	ctx.request.Header.Set("X-Stainless-Runtime", "node")
	ctx.request.Header.Set("X-Stainless-Runtime-Version", "24.0.0")
	ctx.request.Header.Set("X-Stainless-Timeout", "600")
	ctx.request.Header.Set("X-Future-AI-SDK-Feature", "client-controlled")
	ctx.request.Header.Set("X-OpenRouter-Title", "client")

	server := &Server{}
	if _, ok := server.requireInferenceHeaders(ctx); !ok {
		t.Fatalf("expected client metadata headers to be ignored, got status %d body %s", testResponse(ctx).Code, string(testResponse(ctx).Body.Bytes()))
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
			ctx := newTestRequest(t)
			testRequestURI(ctx, "/v1/responses")
			ctx.request.Method = http.MethodPost
			ctx.request.Header.Set("Authorization", "Bearer sk-test")
			ctx.request.Header.Set("Content-Type", "application/json")
			ctx.request.Header.Set(header, "client-controlled")

			server := &Server{}
			if _, ok := server.requireInferenceHeaders(ctx); ok {
				t.Fatalf("expected %s to be rejected", header)
			}
			if testResponse(ctx).Code != http.StatusBadRequest {
				t.Fatalf("expected 400 unsupported header response, got %d", testResponse(ctx).Code)
			}
			if !strings.Contains(string(testResponse(ctx).Body.Bytes()), strings.ToLower(header)) {
				t.Fatalf("expected rejected header in response, got %s", string(testResponse(ctx).Body.Bytes()))
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
			ctx := newTestRequest(t)
			testRequestURI(ctx, "/v1/responses")
			ctx.request.Method = http.MethodPost
			ctx.request.Header.Set("Authorization", "Bearer sk-test")
			ctx.request.Header.Set("Content-Type", "application/json")
			if tt.accept != "" {
				ctx.request.Header.Set("Accept", tt.accept)
			}

			_, ok := (&Server{}).requireInferenceHeaders(ctx)
			if ok != tt.ok {
				t.Fatalf("expected ok=%v for Accept %q, got %v with status %d", tt.ok, tt.accept, ok, testResponse(ctx).Code)
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
			ctx := newTestRequest(t)
			if test.value != "" {
				ctx.request.Header.Set(stogasHeaderMetadata, test.value)
			}
			got, err := metadataHeader(ctx)
			if (err == nil) != test.valid || got != test.want {
				t.Fatalf("metadataHeader() = (%v, %v), want (%v, valid=%v)", got, err, test.want, test.valid)
			}
		})
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
	if err := server.routes(); err != nil {
		t.Fatal(err)
	}
	if server.server.WriteTimeout != 0 || server.server.HTTP2.WriteByteTimeout <= 0 {
		t.Fatal("quiet model time and blocked writes need separate deadlines")
	}
	if !server.server.Protocols.HTTP1() || !server.server.Protocols.HTTP2() || server.server.Protocols.UnencryptedHTTP2() {
		t.Fatal("public server must support H1 and TLS H2 without h2c")
	}
	if server.server.MaxHeaderBytes <= 0 || server.server.HTTP2.MaxReceiveBufferPerConnection <= 0 || server.server.HTTP2.MaxReceiveBufferPerStream <= 0 {
		t.Fatal("transport allocations must be bounded")
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

func TestWriteSSEStreamUsesExistingReservationAtSaturation(t *testing.T) {
	admission := &requestMemoryAdmission{budget: minimumRequestWeightBytes}
	lease, ok := admission.acquire(32 << 10)
	if !ok || !lease.ReserveResponse(4096, 20) {
		t.Fatal("admit request and provider response")
	}
	if _, ok := admission.acquire(0); ok {
		t.Fatal("expected saturated admission")
	}
	server := &Server{memory: admission}
	ctx := newTestRequest(t)
	ctx.memory = lease
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk, 1)
	stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
		ID: "chatcmpl_capacity", Object: "chat.completion.chunk", Choices: []schemas.BifrostResponseChoice{},
	}}
	close(stream)
	complete := make(chan struct{})
	reader := server.startSSEStream(ctx, bifrostCtx, &stogas.State{}, stream, true, false, cancel, func() { lease.release(); close(complete) })
	body := readResponseBodyStream(t, reader)
	<-complete
	if !strings.Contains(body, "chatcmpl_capacity") || !strings.Contains(body, "[DONE]") || strings.Contains(body, "gateway_capacity_exceeded") {
		t.Fatalf("reserved stream failed under saturation: %q", body)
	}
	if admission.reserved.Load() != 0 {
		t.Fatal("response leaked reservation")
	}
}

func TestWriteSSEStreamKeepsMemoryReservedUntilBodyDrain(t *testing.T) {
	admission := &requestMemoryAdmission{budget: minimumRequestWeightBytes}
	lease, ok := admission.acquire(0)
	if !ok {
		t.Fatal("admit")
	}
	server := &Server{memory: admission}
	ctx := newTestRequest(t)
	ctx.memory = lease
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk, 1)
	stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
		ID: "chatcmpl_memory", Object: "chat.completion.chunk", Choices: []schemas.BifrostResponseChoice{},
	}}
	close(stream)
	completed := make(chan struct{})
	reader := server.startSSEStream(ctx, bifrostCtx, nil, stream, true, false, cancel, func() { lease.release(); close(completed) })
	defer reader.Close()
	// Consume the model frame so the producer can queue its terminal frame and
	// finish. The final delivery must keep its own pin after request completion.
	first := make([]byte, 4096)
	n, err := reader.Read(first)
	if err != nil || !strings.Contains(string(first[:n]), "chatcmpl_memory") {
		t.Fatalf("first frame: %q, %v", first[:n], err)
	}
	<-completed
	if got := admission.reserved.Load(); got == 0 || got >= minimumRequestWeightBytes {
		t.Fatalf("delivery tail reservation=%d", got)
	}
	rest := readResponseBodyStream(t, reader)
	if rest != "data: [DONE]\n\n" {
		t.Fatalf("terminal frame=%q", rest)
	}
	if got := admission.reserved.Load(); got != 0 {
		t.Fatalf("body drain left %d reserved bytes", got)
	}
}

func TestWriteSSEStreamEmitsOpenAIFramesFromBodyStream(t *testing.T) {
	server := &Server{}
	ctx := newTestRequest(t)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, nil, stream, true, false, cancel)
	defer streamBodyReader.Close()

	if !(streamBodyReader != nil) {
		t.Fatal("expected an SSE response reader")
	}
	if got := string(ctx.writer.Header().Get("X-Accel-Buffering")); got != "no" {
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

	body := readResponseBodyStream(t, streamBodyReader)
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
			ctx := newTestRequest(t)
			bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
			stream := make(chan *schemas.BifrostStreamChunk)
			state := &stogas.State{
				Adapter:    stogas.DefaultAdapter{},
				Resolution: mustResolvedRequest(t, "/v1/chat/completions", body),
				StartedAt:  time.Now().Add(-5 * time.Millisecond),
			}

			streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
			defer streamBodyReader.Close()

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

			streamBody := readResponseBodyStream(t, streamBodyReader)
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
	ctx := newTestRequest(t)
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

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	defer streamBodyReader.Close()
	body := readResponseBodyStream(t, streamBodyReader)
	if !strings.Contains(body, "chatcmpl_terminal") || !strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("terminal response was not completed normally: %q", body)
	}
	if strings.Contains(body, "late_invalid_frame") || strings.Contains(body, `"error"`) {
		t.Fatalf("post-terminal provider noise changed the response: %q", body)
	}
}

func TestWriteSSEStreamCompletesWithoutTerminalTokenUsage(t *testing.T) {
	server := &Server{}
	ctx := newTestRequest(t)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Adapter:    stogas.DefaultAdapter{},
		Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat},
	}

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	defer streamBodyReader.Close()

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

	body := readResponseBodyStream(t, streamBodyReader)
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
	ctx := newTestRequest(t)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Adapter:    stogas.DefaultAdapter{},
		Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat},
	}

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	defer streamBodyReader.Close()
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

	body := readResponseBodyStream(t, streamBodyReader)
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
	service, publicKey, boot := testProofService(t)
	server := &Server{proofs: service}
	ctx := newTestRequest(t)
	testRequestBody(ctx, `{"messages":[{"role":"user","content":"hi"}],"stream":true}`)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	bifrostCtx.SetValue(stogasMetadataKey, true)
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Resolution: mustResolvedRequest(t, "/v1/chat/completions", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true}`),
		Adapter:    stogas.DefaultAdapter{},
		RequestID:  "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		NodeID:     strings.Repeat("3", 64),
		FinalEvent: &billing.RequestEvent{
			CreatedAt: "2026-08-24T12:34:56.789Z", Usage: billing.RequestUsage{BilledCostUSD: "0", UpstreamCostUSD: "0", Meters: billing.EventMeters{}},
		},
	}

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
	defer streamBodyReader.Close()

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

	body := readResponseBodyStream(t, streamBodyReader)
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
	if !verifyReceipt(publicKey, proofObject, boot, sha256.Sum256(ctx.body), sha256.Sum256(bytes.Join(proofFrames, nil))) {
		t.Fatalf("streaming proof did not verify: signature=%q body=%q", proofObject.Receipt.Signature, body)
	}
}

func TestWriteSSEStreamEmitsReceiptBeforeResponsesTerminalEvent(t *testing.T) {
	service, publicKey, boot := testProofService(t)
	server := &Server{proofs: service}
	ctx := newTestRequest(t)
	testRequestBody(ctx, `{"model":"gpt-5.5","input":"hi","stream":true}`)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	bifrostCtx.SetValue(stogasMetadataKey, true)
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{
		Resolution: mustResolvedRequest(t, "/v1/responses", `{"model":"gpt-5.5","input":"hi","stream":true}`),
		Adapter:    stogas.DefaultAdapter{},
		RequestID:  "018f4f70-7c88-7b9a-baf8-31a93d2cf615",
		NodeID:     strings.Repeat("5", 64),
		FinalEvent: &billing.RequestEvent{
			CreatedAt: "2026-08-24T12:34:56.789Z", Usage: billing.RequestUsage{BilledCostUSD: "0", UpstreamCostUSD: "0", Meters: billing.EventMeters{}},
		},
	}

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, false, true, cancel)
	defer streamBodyReader.Close()
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

	body := readResponseBodyStream(t, streamBodyReader)
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
	if !verifyReceipt(publicKey, proofObject, boot, sha256.Sum256(ctx.body), sha256.Sum256([]byte(unsignedBody))) {
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
			service, _, _ := testProofService(t)
			server := &Server{proofs: service}
			ctx := newTestRequest(t)
			testRequestBody(ctx, `{"messages":[{"role":"user","content":"hi"}],"stream":true}`)
			bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
			bifrostCtx.SetValue(stogasMetadataKey, true)
			stream := make(chan *schemas.BifrostStreamChunk)
			state := &stogas.State{
				Resolution: mustResolvedRequest(t, "/v1/chat/completions", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true}`),
				Adapter:    stogas.DefaultAdapter{},
				RequestID:  "018f4f70-7c88-7b9a-baf8-31a93d2cf614",
				NodeID:     strings.Repeat("4", 64),
			}

			streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, cancel)
			defer streamBodyReader.Close()
			go func() {
				tc.send(stream, state)
				close(stream)
			}()

			body := readResponseBodyStream(t, streamBodyReader)
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
	ctx := newTestRequest(t)
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Adapter: stogas.DefaultAdapter{}, StartedAt: time.Now()}
	cancelled := make(chan struct{})
	var once sync.Once

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, func() {
		once.Do(func() { close(cancelled) })
	})

	closer, ok := streamBodyReader.(io.Closer)
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
	ctx := newTestRequest(t)
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Adapter: stogas.DefaultAdapter{}}
	cancelled := make(chan struct{})
	var once sync.Once

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, func() {
		once.Do(func() { close(cancelled) })
	})

	closer, ok := streamBodyReader.(io.Closer)
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
	ctx := newTestRequest(t)
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithTimeout(t.Context(), 10*time.Millisecond)
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Adapter: stogas.DefaultAdapter{}, Resolution: &catalog.ResolvedRequest{Route: catalog.RouteResponses}}
	completed := make(chan struct{})
	var once sync.Once

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, false, true, func() {
		once.Do(func() { close(completed) })
	})

	body := readResponseBodyStream(t, streamBodyReader)
	close(stream)
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
	ctx := newTestRequest(t)
	bifrostCtx, bifrostCancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer bifrostCancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	state := &stogas.State{Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}}
	cancelled := make(chan struct{})
	var once sync.Once

	streamBodyReader := server.startSSEStream(ctx, bifrostCtx, state, stream, true, false, func() {
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

	body := readResponseBodyStream(t, streamBodyReader)
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

func TestSilentStreamKeepaliveDoesNotCountAsOutput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &Server{memory: newRequestMemoryAdmission()}
		ctx := newTestRequest(t)
		request, cancel := schemas.NewBifrostContextWithCancel(t.Context())
		defer cancel()
		state := &stogas.State{}
		provider := make(chan *schemas.BifrostStreamChunk)
		finished := make(chan struct{})
		reader := server.startSSEStream(ctx, request, state, provider, true, false, cancel, func() { close(finished) })
		defer reader.Close()
		time.Sleep(responseKeepaliveInterval)
		keepalive := make([]byte, len(": STOGAS PROCESSING\n\n"))
		if _, err := io.ReadFull(reader, keepalive); err != nil {
			t.Fatal(err)
		}
		if string(keepalive) != ": STOGAS PROCESSING\n\n" {
			t.Fatalf("keepalive = %q", keepalive)
		}
		if got := server.memory.diagnostics().StreamStateReservedBytes; got != 0 {
			t.Fatalf("keepalive counted as model output: %d", got)
		}
		close(provider)
		rest, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if string(rest) != "data: [DONE]\n\n" {
			t.Fatalf("terminal response = %q", rest)
		}
		<-finished
	})
}

func TestIncrementalUploadAccountsGrowthAndFailsWithoutWaiting(t *testing.T) {
	admission := &requestMemoryAdmission{budget: 2 << 20}
	lease, ok := admission.acquire(0)
	if !ok {
		t.Fatal("initial admission")
	}
	// The next capacity growth needs both old and new storage at once.
	_, err := readAdmittedBody(strings.NewReader(strings.Repeat("s", 1<<20)), 1<<20, lease, 0, -1)
	if !errors.Is(err, errRequestMemoryCapacity) {
		t.Fatalf("growth = %v", err)
	}
	if admission.peakReserved.Load() > admission.budget {
		t.Fatal("allocated beyond admission")
	}
	if admission.reserved.Load() < minimumRequestWeightBytes {
		t.Fatal("failed read released its caller's work reservation")
	}
	lease.release()
	if admission.reserved.Load() != 0 {
		t.Fatal("failed upload leaked admission")
	}
	// Unknown-length short uploads reserve their actual capacity, not the ceiling.
	lease, ok = admission.acquire(0)
	if !ok {
		t.Fatal("next admission")
	}
	body, err := readAdmittedBody(strings.NewReader("{}"), 128<<20, lease, 0, -1)
	if err != nil || string(body) != "{}" || admission.reserved.Load() != minimumRequestWeightBytes {
		t.Fatalf("small upload = %q, %v, %d", body, err, admission.reserved.Load())
	}
	lease.release()
}

func TestHTTP2DisconnectRetainsInferenceAdmissionUntilProviderEnds(t *testing.T) {
	server := &Server{memory: newRequestMemoryAdmission(), requests: newRequestDrain()}
	provider := make(chan *schemas.BifrostStreamChunk, 1)
	provider <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{ID: "first", Object: "chat.completion.chunk", Choices: []schemas.BifrostResponseChoice{}}}
	handlerDone, providerDone := make(chan struct{}), make(chan struct{})
	httpServer := httptest.NewUnstartedServer(requestHandler(func(ctx *requestContext) {
		defer close(handlerDone)
		lease, ok := server.memory.acquire(0)
		if !ok || !server.requests.begin() {
			t.Error("admission failed")
			return
		}
		ctx.memory = lease
		request, cancel := schemas.NewBifrostContextWithTimeout(context.Background(), time.Minute)
		reader := server.startSSEStream(ctx, request, &stogas.State{}, provider, true, false, cancel, func() { lease.release(); server.requests.end(); close(providerDone) })
		server.writeStream(ctx, reader)
	}))
	httpServer.EnableHTTP2 = true
	httpServer.StartTLS()
	defer httpServer.Close()
	response, err := httpServer.Client().Get(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 {
		t.Fatal("did not exercise HTTP/2")
	}
	if _, err := response.Body.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("reset did not stop downstream handler")
	}
	if server.requests.diagnostics().Active != 1 || server.memory.reserved.Load() < minimumRequestWeightBytes {
		t.Fatal("handler exit released live provider ownership")
	}
	select {
	case <-providerDone:
		t.Fatal("provider stopped on downstream reset")
	default:
	}
	// Detached provider reading must still consume later work before finalization.
	provider <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{ID: "later", Object: "chat.completion.chunk", Choices: []schemas.BifrostResponseChoice{}}}
	close(provider)
	select {
	case <-providerDone:
	case <-time.After(time.Second):
		t.Fatal("detached provider failed to finish")
	}
	if server.memory.reserved.Load() != 0 || server.requests.diagnostics().Active != 0 {
		t.Fatal("finished provider retained admission")
	}
}

func TestKeepaliveWhileProviderStartupIsSilent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &Server{memory: newRequestMemoryAdmission()}
		ctx := newTestRequest(t)
		request, cancel := schemas.NewBifrostContextWithCancel(t.Context())
		state := &stogas.State{}
		open := make(chan struct{})
		provider := make(chan *schemas.BifrostStreamChunk)
		prepared := make(chan chan *schemas.BifrostStreamChunk, 1)
		go func() {
			stream, failure := awaitProviderStream(ctx, cancel, func() (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) { <-open; return provider, nil })
			if failure != nil {
				t.Error("unexpected startup failure")
			}
			prepared <- stream
		}()
		time.Sleep(responseKeepaliveInterval)
		stream := <-prepared
		if stream != nil || ctx.pendingStream == nil {
			t.Fatal("silent startup was not retained")
		}
		finished := make(chan struct{})
		reader := server.startSSEStream(ctx, request, state, stream, true, false, cancel, func() { close(finished) })
		comment := make([]byte, len(": STOGAS PROCESSING\n\n"))
		if _, err := io.ReadFull(reader, comment); err != nil || string(comment) != ": STOGAS PROCESSING\n\n" {
			t.Fatalf("startup keepalive=%q, %v", comment, err)
		}
		_ = reader.Close()
		cancel()
		synctest.Wait()
		select {
		case <-finished:
			t.Fatal("cancellation released a still-running startup task")
		default:
		}
		close(open)
		close(provider)
		<-finished
	})
}

func TestUnregisteredUpstreamCredentialsAreUnsupported(t *testing.T) {
	for _, header := range []string{"X-Stogas-Upstream-OpenAI-API-Key", "X-Stogas-Upstream-Anthropic-API-Key", "X-Stogas-Upstream-Chutes-API-Key", "X-Stogas-Upstream-API-Key", "X-Stogas-Upstream-Provider"} {
		ctx := newTestRequest(t)
		ctx.request.Header.Set(header, "sensitive-value")
		if unsupportedInferenceHeader(ctx) == "" {
			t.Fatalf("accepted provider credential header %s", header)
		}
	}
}
