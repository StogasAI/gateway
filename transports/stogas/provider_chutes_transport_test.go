package stogas

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/network"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"github.com/maximhq/bifrost/transports/stogas/providerio"
	"github.com/valyala/fasthttp"
)

type recordingEncryptedTransport struct {
	calls atomic.Int64
}

func (r *recordingEncryptedTransport) DoRequestWithContext(context.Context, *fasthttp.Request, *fasthttp.Response) error {
	r.calls.Add(1)
	return nil
}

func chutesChatRequest(url string) *fasthttp.Request {
	request := fasthttp.AcquireRequest()
	request.SetRequestURI(url + "/v1/chat/completions")
	request.Header.SetMethod(http.MethodPost)
	request.Header.Set("Authorization", "Bearer sk-test")
	request.Header.SetContentType("application/json")
	request.SetBodyString(`{"model":"zai-org/GLM-5.2-Fast","messages":[{"role":"user","content":"hi"}]}`)
	return request
}

func TestChutesStandardCallReachesOnlyChutesAPIOverTheStandardClient(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","created":1,"model":"glm-5.2-fast-preview","choices":[]}`))
	}))
	defer server.Close()
	encrypted := &recordingEncryptedTransport{}
	transport := &chutesTransport{
		encrypted: encrypted,
		standard:  newChutesStandardClient(schemas.NetworkConfig{AllowPrivateNetwork: true}),
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	SetChutesCall(ctx, &catalog.ResolvedRequest{Deployment: catalog.Deployment{}}, 1, nil)
	response := fasthttp.AcquireResponse()
	if err := transport.DoRequestWithContext(ctx, chutesChatRequest(server.URL), response); err != nil {
		t.Fatal(err)
	}
	if encrypted.calls.Load() != 0 {
		t.Fatal("a standard call reached the encrypted transport")
	}
	if len(paths) != 1 || paths[0] != "/v1/chat/completions" {
		t.Fatalf("standard call reached %v, want only /v1/chat/completions", paths)
	}
}

// A Standard operator is a third party, so its streamed reply must stop at the limit that every
// provider reply has, which fasthttp's own body limit does not apply to streams.
func TestChutesStandardStreamStopsAtTheProviderResponseLimit(t *testing.T) {
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for written := 0; written <= maxProviderResponseBodySize; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	transport := &chutesTransport{
		encrypted: &recordingEncryptedTransport{},
		standard:  newChutesStandardClient(schemas.NetworkConfig{AllowPrivateNetwork: true}),
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	SetChutesCall(ctx, &catalog.ResolvedRequest{Deployment: catalog.Deployment{}}, 1, nil)
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(response)
	response.StreamBody = true
	if err := transport.DoRequestWithContext(ctx, chutesChatRequest(server.URL), response); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.BodyStream()); !errors.Is(err, providerio.ErrTooLarge) {
		t.Fatalf("reading a streamed reply over the limit = %v, want providerio.ErrTooLarge", err)
	}
}

func TestChutesStandardConnectFailureIsNotSent(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	transport := &chutesTransport{
		encrypted: &recordingEncryptedTransport{},
		standard:  newChutesStandardClient(schemas.NetworkConfig{AllowPrivateNetwork: true}),
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	SetChutesCall(ctx, &catalog.ResolvedRequest{Deployment: catalog.Deployment{}}, 1, nil)
	err = transport.DoRequestWithContext(ctx, chutesChatRequest("http://"+address), fasthttp.AcquireResponse())
	if err == nil || !network.RequestNotSent(err) || !IsStandardCall(ctx) {
		t.Fatalf("standard connect failure = %v, want a not-sent error on a standard call", err)
	}
}

func TestChutesEncryptedCallNeverReachesThePlainUpstream(t *testing.T) {
	var plain atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { plain.Add(1) }))
	defer server.Close()
	encrypted := &recordingEncryptedTransport{}
	transport := &chutesTransport{
		encrypted: encrypted,
		standard:  newChutesStandardClient(schemas.NetworkConfig{AllowPrivateNetwork: true}),
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	SetChutesCall(ctx, &catalog.ResolvedRequest{Deployment: catalog.Deployment{
		DataHandling: catalog.DataHandling{EndToEndEncrypted: true},
		Upstream:     catalog.Upstream{ChuteID: "08901219-159f-55a7-87cf-9d0d02744668", GPUCount: schemas.Ptr(8)},
	}}, 1, nil)
	if err := transport.DoRequestWithContext(ctx, chutesChatRequest(server.URL), fasthttp.AcquireResponse()); err != nil {
		t.Fatal(err)
	}
	if encrypted.calls.Load() != 1 || plain.Load() != 0 {
		t.Fatalf("encrypted calls = %d, plain requests = %d", encrypted.calls.Load(), plain.Load())
	}
}

func TestChutesCallWithoutRouteDecisionIsRefusedBeforeSending(t *testing.T) {
	var plain atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { plain.Add(1) }))
	defer server.Close()
	e2ee, err := chutese2ee.New(chutese2ee.Options{
		APIKey:         "sk-test",
		APIBaseURL:     "https://api.chutes.ai",
		RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e2ee.Close()
	transport := &chutesTransport{
		encrypted: e2ee,
		standard:  newChutesStandardClient(schemas.NetworkConfig{AllowPrivateNetwork: true}),
	}
	response := fasthttp.AcquireResponse()
	if err := transport.DoRequestWithContext(context.Background(), chutesChatRequest(server.URL), response); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode() != http.StatusServiceUnavailable || plain.Load() != 0 {
		t.Fatalf("status = %d, plain requests = %d, want 503 and none", response.StatusCode(), plain.Load())
	}
}

func TestChutesStandardClientRequiresPostQuantumTLSWhenConfigured(t *testing.T) {
	required := newChutesStandardClient(schemas.NetworkConfig{RequirePostQuantumTLS: true}).TLSConfig
	if required == nil || required.MinVersion != tls.VersionTLS13 ||
		len(required.CurvePreferences) != 1 || required.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("standard client TLS = %#v, want TLS 1.3 with X25519MLKEM768 only", required)
	}
	if optional := newChutesStandardClient(schemas.NetworkConfig{}).TLSConfig; optional != nil && len(optional.CurvePreferences) != 0 {
		t.Fatalf("standard client without the requirement restricts key exchange to %v", optional.CurvePreferences)
	}
}

func TestChutesUnknownHostingAcceptsTheOperatorsModelName(t *testing.T) {
	unknown := &State{Resolution: &catalog.ResolvedRequest{Model: "glm-5.2-fast", Deployment: catalog.Deployment{
		Upstream: catalog.Upstream{Hosting: catalog.HostingUnknown, Model: "zai-org/GLM-5.2-Fast"},
	}}}
	if err := validateActualResponseModel(unknown, "glm-5.2-fast-preview"); err != nil {
		t.Fatalf("operator's own model name was refused: %v", err)
	}
	observeActualResponseModel(unknown, "glm-5.2-fast-preview")
	if err := validateActualResponseModel(unknown, "qwen3.8-max"); err != ErrProviderExecutionMismatch {
		t.Fatalf("reply that changes model mid-reply = %v, want ErrProviderExecutionMismatch", err)
	}

	known := &State{Resolution: &catalog.ResolvedRequest{Model: "glm-5.2-fast", Deployment: catalog.Deployment{
		Upstream: catalog.Upstream{Model: "zai-org/GLM-5.2-Fast"},
	}}}
	if err := validateActualResponseModel(known, "glm-5.2-fast-preview"); err != ErrProviderExecutionMismatch {
		t.Fatalf("a known hosting accepted another model name: %v", err)
	}
}
