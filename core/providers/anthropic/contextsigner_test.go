package anthropic

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	schemas "github.com/maximhq/bifrost/core/schemas"
)

// Each of the five Anthropic send paths must sign the exact body it sends, and
// send no Authorization header without a signer.
func TestContextSignerSignsTheExactBodySent(t *testing.T) {
	var mu sync.Mutex
	var sentBody, sentAuthorization, signedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		sentBody, sentAuthorization = string(body), r.Header.Get("Authorization")
		mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/count_tokens"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"input_tokens":1}`)
		case strings.Contains(string(body), `"stream":true`):
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, anthropicMessageStart+anthropicTextDelta+anthropicMessageStop)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-repro","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
		}
	}))
	defer server.Close()
	provider := NewAnthropicProvider(&schemas.ProviderConfig{
		NetworkConfig: schemas.NetworkConfig{BaseURL: server.URL, AllowPrivateNetwork: true},
	}, truncationTestLogger{})

	streamError := func(stream chan *schemas.BifrostStreamChunk, err *schemas.BifrostError) *schemas.BifrostError {
		if err != nil {
			return err
		}
		for _, chunk := range collectTruncationChunks(t, stream) {
			if chunk.BifrostError != nil {
				return chunk.BifrostError
			}
		}
		return nil
	}
	sends := map[string]func(*schemas.BifrostContext) *schemas.BifrostError{
		"chat": func(ctx *schemas.BifrostContext) *schemas.BifrostError {
			_, err := provider.ChatCompletion(ctx, schemas.Key{}, truncationChatRequest())
			return err
		},
		"chat stream": func(ctx *schemas.BifrostContext) *schemas.BifrostError {
			return streamError(provider.ChatCompletionStream(ctx, truncationPassthroughPostHook, nil, schemas.Key{}, truncationChatRequest()))
		},
		"responses": func(ctx *schemas.BifrostContext) *schemas.BifrostError {
			_, err := provider.Responses(ctx, schemas.Key{}, truncationResponsesRequest())
			return err
		},
		"responses stream": func(ctx *schemas.BifrostContext) *schemas.BifrostError {
			return streamError(provider.ResponsesStream(ctx, truncationPassthroughPostHook, nil, schemas.Key{}, truncationResponsesRequest()))
		},
		"count tokens": func(ctx *schemas.BifrostContext) *schemas.BifrostError {
			_, err := provider.CountTokens(ctx, schemas.Key{}, truncationResponsesRequest())
			return err
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
