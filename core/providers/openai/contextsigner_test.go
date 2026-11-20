package openai

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// TestContextSignerSignsTheExactChatBodySent checks that both Chat Completions paths sign the
// final body with the context's signer and send its headers, and send no Authorization without
// one or a key.
func TestContextSignerSignsTheExactChatBodySent(t *testing.T) {
	var mu sync.Mutex
	var sentBody, sentAuthorization, signedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		sentBody, sentAuthorization = string(body), r.Header.Get("Authorization")
		mu.Unlock()
		if strings.Contains(string(body), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, chatChunk("ok", schemas.Ptr("stop"))+"data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"c1","object":"chat.completion","model":"repro-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	defer server.Close()
	provider := newStreamTestProvider(server.URL)

	sends := map[string]func(*schemas.BifrostContext) *schemas.BifrostError{
		"chat": func(ctx *schemas.BifrostContext) *schemas.BifrostError {
			_, err := provider.ChatCompletion(ctx, schemas.Key{}, basicChatRequest())
			return err
		},
		"chat stream": func(ctx *schemas.BifrostContext) *schemas.BifrostError {
			stream, err := provider.ChatCompletionStream(ctx, passthroughPostHook, nil, schemas.Key{}, basicChatRequest())
			if err != nil {
				return err
			}
			for _, chunk := range collectChunks(t, stream) {
				if chunk.BifrostError != nil {
					return chunk.BifrostError
				}
			}
			return nil
		},
	}
	for name, send := range sends {
		for _, signed := range []bool{false, true} {
			mu.Lock()
			sentBody, sentAuthorization, signedBody = "", "", ""
			mu.Unlock()
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			if signed {
				ctx.SetValue(schemas.BifrostContextKeyRequestSigner, schemas.RequestSigner(func(body []byte) (map[string]string, *schemas.BifrostError) {
					mu.Lock()
					signedBody = string(body)
					mu.Unlock()
					return map[string]string{"Authorization": "signed " + strconv.Itoa(len(body))}, nil
				}))
			}
			if err := send(ctx); err != nil {
				t.Fatalf("%s signed=%v: %v", name, signed, err.Error)
			}
			mu.Lock()
			body, authorization, signedFor := sentBody, sentAuthorization, signedBody
			mu.Unlock()
			switch {
			case body == "":
				t.Fatalf("%s signed=%v: no request reached the server", name, signed)
			case !signed && authorization != "":
				t.Fatalf("%s: unsigned request sent Authorization %q", name, authorization)
			case signed && (signedFor != body || authorization != "signed "+strconv.Itoa(len(body))):
				t.Fatalf("%s: signature does not cover the body sent: signed %q, sent %q with %q", name, signedFor, body, authorization)
			}
		}
	}
}
