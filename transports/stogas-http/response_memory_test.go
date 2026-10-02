package stogashttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestJSONResponseBuffersClearOnlyOwnedEncodings(t *testing.T) {
	for _, mode := range []string{"json", "inference", "error"} {
		for _, borrowed := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/owned", true: "/borrowed"}[borrowed], func(t *testing.T) {
				original := []byte(`{"message":"private response"}`)
				var payload any = map[string]any{"message": "private response"}
				if borrowed {
					payload = original
				}
				writer := &responseBufferRecorder{testResponseWriter: &testResponseWriter{httptest.NewRecorder()}}
				ctx := newTestRequest(t)
				ctx.writer = writer
				server := &Server{}
				switch mode {
				case "json":
					server.writeJSON(ctx, http.StatusOK, payload)
				case "inference":
					bifrostCtx := schemas.NewBifrostContext(t.Context(), schemas.NoDeadline)
					server.writeInferenceJSON(ctx, bifrostCtx, nil, http.StatusOK, payload)
				case "error":
					server.writeError(ctx, http.StatusBadRequest, payload)
				}
				if writer.Body.Len() == 0 || len(writer.buffers) == 0 {
					t.Fatal("response was not delivered")
				}
				if string(original) != `{"message":"private response"}` {
					t.Fatal("response cleanup modified caller-owned bytes")
				}
				var delivered []byte
				for _, buffer := range writer.buffers {
					delivered = append(delivered, buffer...)
				}
				if !borrowed || mode == "error" {
					if !bytes.Equal(delivered, make([]byte, len(delivered))) {
						t.Fatal("completed response retained its owned encoding")
					}
				} else if !bytes.Equal(delivered, original) || !bytes.Equal(writer.Body.Bytes(), original) {
					t.Fatal("borrowed response changed during delivery")
				}
			})
		}
	}
}

// Retain aliases only as a test oracle for cleanup after the synchronous writer
// returns. The recorder separately copies the bytes delivered to the client.
type responseBufferRecorder struct {
	*testResponseWriter
	buffers [][]byte
}

func (w *responseBufferRecorder) Write(data []byte) (int, error) {
	w.buffers = append(w.buffers, data)
	return w.testResponseWriter.Write(data)
}
