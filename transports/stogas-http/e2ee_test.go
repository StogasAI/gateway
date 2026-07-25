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
			APIKey:            "sk-encrypted",
			Accept:            "text/event-stream",
			ReturnExtraFields: "provider",
			Body:              json.RawMessage(`{"model":"gpt-5.5","stream":true}`),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/v1/chat/completions")
	ctx.Request.Header.Set("Authorization", "Bearer outer-key")
	ctx.Request.Header.Set(stogasHeaderReturnExtraFields, "raw_response")
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
	if got := string(ctx.Request.Header.Peek(stogasHeaderReturnExtraFields)); got != "provider" {
		t.Fatalf("extra fields = %q", got)
	}
	if got := string(ctx.Request.Body()); got != `{"model":"gpt-5.5","stream":true}` {
		t.Fatalf("inner body = %q", got)
	}

	resolution := testResolution()
	bifrostCtx, state, cancel, err := newRequestContext(ctx, resolution, apiCredential{Raw: "sk-encrypted"}, stogas.AdapterFor(resolution.Provider), "", "")
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

func TestEncryptedBufferedResponseHidesInnerStatusHeadersAndBody(t *testing.T) {
	server, material := encryptedTestServer(t)
	ctx, clientSession := encryptedRequestContext(t, server, material)
	ctx.SetStatusCode(fasthttp.StatusPaymentRequired)
	ctx.SetContentType("application/json")
	ctx.Response.Header.Set("X-Stogas-Proof", "receipt")
	ctx.Response.Header.Set("X-Frame-Options", "DENY")
	ctx.Response.Header.Set("Cache-Control", "private")
	ctx.Response.SetBodyString(`{"error":{"type":"billing_error"}}`)

	server.sealBufferedEncryptedResponse(ctx, encryptedSession(ctx))

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("outer status = %d", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Header.ContentType()); got != e2ee.ResponseContentType {
		t.Fatalf("outer content type = %q", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Stogas-Proof")); got != "" {
		t.Fatalf("proof header leaked outside encryption: %q", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Frame-Options")); got != "DENY" {
		t.Fatalf("security header was removed: %q", got)
	}
	if bytes.Contains(ctx.Response.Body(), []byte("billing_error")) {
		t.Fatal("plaintext response leaked outside encryption")
	}
	decoded, err := clientSession.DecodeResponse(ctx.Response.Body())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Metadata.StatusCode != fasthttp.StatusPaymentRequired ||
		decoded.Metadata.Headers["X-Stogas-Proof"] != "receipt" ||
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

func TestEncryptedInferenceFailsClosedBeforeDecryption(t *testing.T) {
	server, _ := encryptedTestServer(t)
	for _, body := range []string{
		`{"stogas_e2ee":{}}`,
		`{"stogas_e2ee":{},"stogas_e2ee":{}}`,
	} {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodPost)
		ctx.Request.SetRequestURI("/v1/chat/completions")
		ctx.Request.SetBodyString(body)
		if session, ok := server.openEncryptedInference(ctx); ok || session != nil {
			t.Fatalf("malformed envelope was accepted: %s", body)
		}
		if ctx.Response.StatusCode() != fasthttp.StatusBadRequest || !bytes.Contains(ctx.Response.Body(), []byte("Invalid encrypted request")) {
			t.Fatalf("response = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
		}
	}
}

func TestPlainInferenceDoesNotEnterEncryptedPath(t *testing.T) {
	server, _ := encryptedTestServer(t)
	ctx := &fasthttp.RequestCtx{}
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
