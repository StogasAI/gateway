package stogashttp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type testResponseWriter struct{ *httptest.ResponseRecorder }

func (*testResponseWriter) SetWriteDeadline(time.Time) error { return nil }

func newTestRequest(t *testing.T) *requestContext {
	t.Helper()
	admission := newRequestMemoryAdmission()
	lease, _ := admission.acquire(0)
	t.Cleanup(lease.release)
	return &requestContext{request: httptest.NewRequest(http.MethodGet, "/", nil), writer: &testResponseWriter{httptest.NewRecorder()}, memory: lease, startedAt: time.Now()}
}

func testResponse(ctx *requestContext) *httptest.ResponseRecorder {
	return ctx.writer.(*testResponseWriter).ResponseRecorder
}
func testRequestURI(ctx *requestContext, uri string) {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		panic(err)
	}
	ctx.request.URL, ctx.request.RequestURI = parsed, uri
}
func testRequestBody(ctx *requestContext, value any) {
	var body []byte
	switch v := value.(type) {
	case string:
		body = []byte(v)
	case []byte:
		body = bytes.Clone(v)
	default:
		panic(fmt.Sprintf("unsupported test body %T", value))
	}
	ctx.body = body
	ctx.request.Body = io.NopCloser(bytes.NewReader(body))
	ctx.request.ContentLength = int64(len(body))
}
func testRequestBodyStream(ctx *requestContext, reader io.Reader, length int) {
	// An unread upload enters before admission; its server supplies the lease.
	ctx.memory.release()
	ctx.memory = nil
	ctx.body = nil
	ctx.request.Body = io.NopCloser(reader)
	ctx.request.ContentLength = int64(length)
}
func testWriteString(ctx *requestContext, value string) (int, error) {
	return io.WriteString(ctx.writer, value)
}
