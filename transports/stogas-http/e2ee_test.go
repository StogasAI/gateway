package stogashttp

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/confidential/e2ee"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	"github.com/valyala/fasthttp"
)

func TestEncryptedInferenceRestoresOrdinaryRequestAndUsesBoundRequestID(t *testing.T) {
	server, material := encryptedTestServer(t)
	now := time.Now().UTC()
	body, clientSession, err := e2ee.SealRequestWithID(
		"POST",
		"/v1/chat/completions",
		"018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		now.Add(time.Minute),
		strings.Repeat("1", 64),
		[]e2ee.PublicRecipient{{PublicKey: material.HPKEPrivateKey.PublicKey().Bytes()}},
		e2ee.InnerRequest{
			APIKey:  "sk-encrypted",
			Accept:  "text/event-stream",
			Receipt: "v1",
			UpstreamCredentials: &e2ee.UpstreamCredentials{
				Anthropic: "sk-anthropic",
				OpenAI:    "sk-upstream",
			},
			Body: json.RawMessage(`{"model":"gpt-5.5","stream":true}`),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/v1/chat/completions")
	ctx.Request.Header.SetContentType(e2ee.ContentType)
	ctx.Request.Header.Set("Accept", "*/*")
	ctx.Request.Header.Set("Authorization", "Bearer outer-key")
	ctx.Request.Header.Set(stogasHeaderReceipt, "invalid")
	ctx.Request.SetBody(body)

	session, ok := server.openEncryptedInference(ctx)
	if !ok || session == nil {
		t.Fatalf("openEncryptedInference = (%#v, %v), response=%s", session, ok, ctx.Response.Body())
	}
	if session.RequestID != clientSession.RequestID {
		t.Fatalf("request id = %q, want %q", session.RequestID, clientSession.RequestID)
	}
	if got := string(ctx.Request.Header.Peek("Authorization")); got != "Bearer sk-encrypted" {
		t.Fatalf("authorization = %q", got)
	}
	if got := string(ctx.Request.Header.Peek(stogasHeaderReceipt)); got != "v1" {
		t.Fatalf("receipt = %q", got)
	}
	if got := string(ctx.Request.Header.Peek(upstreamOpenAIHeader)); got != "sk-upstream" {
		t.Fatalf("upstream credential = %q", got)
	}
	if got := string(ctx.Request.Header.Peek(upstreamAnthropicHeader)); got != "sk-anthropic" {
		t.Fatalf("Anthropic upstream credential = %q", got)
	}
	if got := string(ctx.Request.Body()); got != `{"model":"gpt-5.5","stream":true}` {
		t.Fatalf("inner body = %q", got)
	}

	resolution := testResolution()
	bifrostCtx, state, cancel, err := newRequestContext(ctx, resolution, apiCredential{Raw: "sk-encrypted"}, stogas.AdapterFor(resolution.Provider), "")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	requestID, _ := bifrostCtx.Value(schemas.BifrostContextKeyRequestID).(string)
	if requestID != session.RequestID {
		t.Fatalf("Bifrost request id = %q, want %q", requestID, session.RequestID)
	}
	if !state.SingleUseRequestID {
		t.Fatal("encrypted request id must be single-use")
	}
}

func TestEncryptedInferenceDefersCredentialsUntilAfterBodyAdmission(t *testing.T) {
	server, material := encryptedTestServer(t)
	body, _, err := e2ee.SealRequestWithID(
		"POST",
		"/v1/chat/completions",
		"018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		time.Now().UTC().Add(time.Minute),
		strings.Repeat("1", 64),
		[]e2ee.PublicRecipient{{PublicKey: material.HPKEPrivateKey.PublicKey().Bytes()}},
		e2ee.InnerRequest{
			APIKey: "sk-encrypted",
			Accept: "text/event-stream",
			Body:   json.RawMessage(`{"model":"gpt-5.5","stream":true}`),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		contentType string
		compressed  bool
		outerAPIKey string
	}{
		{name: "ordinary outer envelope", contentType: e2ee.ContentType},
		{
			name:        "compressed envelope with benign outer credential",
			contentType: e2ee.ContentType + "; charset=UTF-8",
			compressed:  true,
			outerAPIKey: "outer-key",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			wireBody := body
			if test.compressed {
				wireBody = gzipBody(t, string(body))
			}
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.SetMethod(fasthttp.MethodPost)
			ctx.Request.SetRequestURI("/v1/chat/completions")
			ctx.Request.Header.SetContentType(test.contentType)
			ctx.Request.Header.Set("Accept", "*/*")
			if test.compressed {
				ctx.Request.Header.Set("Content-Encoding", "gzip")
			}
			if test.outerAPIKey != "" {
				ctx.Request.Header.Set("Authorization", "Bearer "+test.outerAPIKey)
			}
			ctx.Request.SetBodyStream(bytes.NewReader(wireBody), len(wireBody))

			called := false
			server.requestBodyAdmission(server.requestDecompression(func(ctx *fasthttp.RequestCtx) {
				called = true
				if cached := ctx.UserValue(inferenceCredentialContextKey); cached != nil {
					t.Fatalf("outer credential was cached before decryption: %#v", cached)
				}
				if session, ok := server.openEncryptedInference(ctx); !ok || session == nil {
					t.Fatalf("encrypted request was rejected before decryption: %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
				}
				credential, ok := server.requireInferenceHeaders(ctx)
				if !ok || credential.Raw != "sk-encrypted" {
					t.Fatalf("restored credential = %#v, accepted = %v", credential, ok)
				}
				lease := requestMemoryLeaseForInference(ctx)
				if lease == nil {
					t.Fatal("encrypted request memory lease was not transferred")
				}
				lease.release()
			}))(ctx)

			if !called {
				t.Fatalf("encrypted request did not reach decryption: %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
			}
			if used := server.memory.reserved.Load(); used != 0 {
				t.Fatalf("completed encrypted request retained %d memory bytes", used)
			}
		})
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/v1/chat/completions")
	ctx.Request.Header.SetContentType(e2ee.ContentType)
	ctx.Request.SetBodyStream(strings.NewReader(`{"model":"gpt-5.5"}`), -1)

	called := false
	server.requestBodyAdmission(server.requestDecompression(func(ctx *fasthttp.RequestCtx) {
		called = true
		if session, ok := server.openEncryptedInference(ctx); ok || session != nil {
			t.Fatalf("plaintext body was accepted in encrypted mode: session=%#v accepted=%v", session, ok)
		}
	}))(ctx)
	if !called || ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("spoofed E2EE marker response = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if used := server.memory.reserved.Load(); used != 0 {
		t.Fatalf("rejected spoofed request retained %d memory bytes", used)
	}
}

func TestEncryptedBufferedResponseHidesInnerStatusHeadersAndBody(t *testing.T) {
	server, material := encryptedTestServer(t)
	ctx, clientSession := encryptedRequestContext(t, server, material)
	ctx.SetStatusCode(fasthttp.StatusPaymentRequired)
	ctx.SetContentType("application/json")
	ctx.Response.Header.Set("X-Frame-Options", "DENY")
	ctx.Response.Header.Set("X-Private-Diagnostic", "secret")
	ctx.Response.Header.Set("Cache-Control", "private")
	ctx.Response.SetBodyString(`{"error":{"type":"billing_error"}}`)

	server.sealBufferedEncryptedResponse(ctx, encryptedSession(ctx))

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("outer status = %d", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Header.ContentType()); got != e2ee.ContentType {
		t.Fatalf("outer content type = %q", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Frame-Options")); got != "DENY" {
		t.Fatalf("security header was removed: %q", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Private-Diagnostic")); got != "" {
		t.Fatalf("unexpected response metadata leaked outside encryption: %q", got)
	}
	if bytes.Contains(ctx.Response.Body(), []byte("billing_error")) {
		t.Fatal("plaintext response leaked outside encryption")
	}
	decoded, err := clientSession.DecodeResponse(ctx.Response.Body())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Metadata.StatusCode != fasthttp.StatusPaymentRequired ||
		decoded.Metadata.Headers["Cache-Control"] != "private" ||
		string(decoded.Body) != `{"error":{"type":"billing_error"}}` {
		t.Fatalf("decoded response = %#v", decoded)
	}
}

func TestEncryptedStreamingResponseAuthenticatesEOFAndPropagatesClose(t *testing.T) {
	server, material := encryptedTestServer(t)
	ctx, clientSession := encryptedRequestContext(t, server, material)
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	source := &closingReader{Reader: bytes.NewReader([]byte("data: one\n\ndata: two\n\n"))}

	if err := server.sealStreamingEncryptedResponse(ctx, encryptedSession(ctx), source); err != nil {
		t.Fatal(err)
	}
	if got := string(ctx.Response.Header.Peek("X-Accel-Buffering")); got != "no" {
		t.Fatalf("X-Accel-Buffering = %q, want no", got)
	}
	encoded, err := io.ReadAll(ctx.Response.BodyStream())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := clientSession.DecodeResponse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Metadata.ContentType != "text/event-stream" || string(decoded.Body) != "data: one\n\ndata: two\n\n" {
		t.Fatalf("decoded stream = %#v", decoded)
	}
	if err := ctx.Response.CloseBodyStream(); err != nil {
		t.Fatal(err)
	}
	if !source.closed {
		t.Fatal("closing encrypted stream did not close plaintext stream")
	}
}

func TestEncryptedResponseSessionCannotReuseResponseNonceSequence(t *testing.T) {
	server, material := encryptedTestServer(t)
	ctx, _ := encryptedRequestContext(t, server, material)
	session := encryptedSession(ctx)
	metadata := e2ee.ResponseMetadata{StatusCode: fasthttp.StatusOK, ContentType: "application/json"}
	if _, err := session.EncodeResponse(metadata, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("first response encoding failed: %v", err)
	}
	if _, err := session.EncodeResponse(metadata, []byte(`{"ok":false}`)); err == nil ||
		!strings.Contains(err.Error(), "single-use") {
		t.Fatalf("response nonce sequence reuse error = %v", err)
	}
}

func TestEncryptedInferenceFailsClosedBeforeDecryption(t *testing.T) {
	server, _ := encryptedTestServer(t)
	for _, body := range []string{
		`{"version":1}`,
		`{"version":1,"version":1}`,
	} {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodPost)
		ctx.Request.SetRequestURI("/v1/chat/completions")
		ctx.Request.Header.SetContentType(e2ee.ContentType)
		ctx.Request.SetBodyString(body)
		if session, ok := server.openEncryptedInference(ctx); ok || session != nil {
			t.Fatalf("malformed envelope was accepted: %s", body)
		}
		if ctx.Response.StatusCode() != fasthttp.StatusBadRequest || !bytes.Contains(ctx.Response.Body(), []byte("Invalid encrypted request")) {
			t.Fatalf("response = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
		}
	}
}

func TestEncryptedInferenceRejectsUnboundQueryParameters(t *testing.T) {
	server, material := encryptedTestServer(t)
	body, _, err := e2ee.SealRequestWithID(
		"POST",
		"/v1/chat/completions",
		"018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		time.Now().UTC().Add(time.Minute),
		strings.Repeat("1", 64),
		[]e2ee.PublicRecipient{{PublicKey: material.HPKEPrivateKey.PublicKey().Bytes()}},
		e2ee.InnerRequest{APIKey: "sk-encrypted", Body: json.RawMessage(`{"model":"gpt-5.5"}`)},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/v1/chat/completions?unbound=true")
	ctx.Request.Header.SetContentType(e2ee.ContentType)
	ctx.Request.SetBody(body)
	if session, ok := server.openEncryptedInference(ctx); ok || session != nil {
		t.Fatal("encrypted request with query parameters was accepted")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("response status = %d", ctx.Response.StatusCode())
	}
}

func TestPlainInferenceRejectsQueryParametersOutsideTheProofTranscript(t *testing.T) {
	server := &Server{}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/v1/chat/completions?unbound=true")
	ctx.Request.SetBodyString(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}]}`)

	if session, ok := server.openEncryptedInference(ctx); ok || session != nil {
		t.Fatal("plaintext request with query parameters was accepted")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest ||
		!bytes.Contains(ctx.Response.Body(), []byte("Query parameters are not supported")) {
		t.Fatalf("unexpected query rejection: status=%d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

func TestPlainInferenceDoesNotEnterEncryptedPath(t *testing.T) {
	server, _ := encryptedTestServer(t)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetContentType("application/json")
	ctx.Request.Header.Set("Accept", e2ee.ContentType)
	ctx.Request.SetBodyString(`{"model":"gpt-5.5"}`)
	session, ok := server.openEncryptedInference(ctx)
	if !ok || session != nil {
		t.Fatalf("plain request = (%#v, %v)", session, ok)
	}
}

func encryptedTestServer(t *testing.T) (*Server, *identity.Material) {
	t.Helper()
	material, err := identity.Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		config: stogas.Config{MaxRequestBodyMiB: 1},
		secure: &confidentialruntime.Runtime{Identity: material},
	}, material
}

func encryptedRequestContext(t *testing.T, server *Server, material *identity.Material) (*fasthttp.RequestCtx, *e2ee.Session) {
	t.Helper()
	body, clientSession, err := e2ee.SealRequestWithID(
		"POST",
		"/v1/chat/completions",
		"018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		time.Now().UTC().Add(time.Minute),
		strings.Repeat("1", 64),
		[]e2ee.PublicRecipient{{PublicKey: material.HPKEPrivateKey.PublicKey().Bytes()}},
		e2ee.InnerRequest{APIKey: "sk-encrypted", Body: json.RawMessage(`{"model":"gpt-5.5"}`)},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/v1/chat/completions")
	ctx.Request.Header.SetContentType(e2ee.ContentType)
	ctx.Request.SetBody(body)
	if session, ok := server.openEncryptedInference(ctx); !ok || session == nil {
		t.Fatalf("failed to open test request: %s", ctx.Response.Body())
	}
	return ctx, clientSession
}

type closingReader struct {
	io.Reader
	closed bool
}

func (r *closingReader) Close() error {
	r.closed = true
	return nil
}
