package gemini

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// TestContextSignerSignsTheExactGenerateContentBodySent checks that both generateContent paths
// send to the full URL that the context names, sign the final body with the context's signer and
// send its headers, and send no Authorization without one.
func TestContextSignerSignsTheExactGenerateContentBodySent(t *testing.T) {
	var mu sync.Mutex
	var sentPath, sentBody, sentAuthorization, signedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		sentPath, sentBody, sentAuthorization = r.URL.RequestURI(), string(body), r.Header.Get("Authorization")
		mu.Unlock()
		reply := `{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":1,"totalTokenCount":4}}`
		if strings.Contains(r.URL.RawQuery, "alt=sse") {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: "+reply+"\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()
	config := &schemas.ProviderConfig{NetworkConfig: schemas.DefaultNetworkConfig}
	config.NetworkConfig.BaseURL = "https://upstream-url-required.invalid"
	config.NetworkConfig.AllowPrivateNetwork = true
	provider := NewGeminiProvider(config, nil)
	request := func() *schemas.BifrostChatRequest {
		text := "Say ok."
		return &schemas.BifrostChatRequest{
			Provider: schemas.Gemini,
			Model:    "gemini-3.8-flash",
			Input:    []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: &text}}},
		}
	}
	sends := map[string]struct {
		path string
		send func(*schemas.BifrostContext) *schemas.BifrostError
	}{
		"generateContent": {"/v1/models/m:generateContent", func(ctx *schemas.BifrostContext) *schemas.BifrostError {
			_, err := provider.ChatCompletion(ctx, schemas.Key{}, request())
			return err
		}},
		"streamGenerateContent": {"/v1/models/m:streamGenerateContent?alt=sse", func(ctx *schemas.BifrostContext) *schemas.BifrostError {
			postHook := func(_ *schemas.BifrostContext, result *schemas.BifrostResponse, err *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
				return result, err
			}
			stream, err := provider.ChatCompletionStream(ctx, postHook, nil, schemas.Key{}, request())
			if err != nil {
				return err
			}
			timeout := time.After(10 * time.Second)
			for {
				select {
				case chunk, open := <-stream:
					if !open {
						return nil
					}
					if chunk.BifrostError != nil {
						return chunk.BifrostError
					}
				case <-timeout:
					t.Fatal("stream did not end")
				}
			}
		}},
	}
	for name, call := range sends {
		for _, signed := range []bool{false, true} {
			mu.Lock()
			sentPath, sentBody, sentAuthorization, signedBody = "", "", "", ""
			mu.Unlock()
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyURLPath, server.URL+call.path)
			if signed {
				ctx.SetValue(schemas.BifrostContextKeyRequestSigner, schemas.RequestSigner(func(body []byte) (map[string]string, *schemas.BifrostError) {
					mu.Lock()
					signedBody = string(body)
					mu.Unlock()
					return map[string]string{"Authorization": "signed " + strconv.Itoa(len(body))}, nil
				}))
			}
			if err := call.send(ctx); err != nil {
				t.Fatalf("%s signed=%v: %v", name, signed, err.Error.Message)
			}
			mu.Lock()
			path, body, authorization, signedFor := sentPath, sentBody, sentAuthorization, signedBody
			mu.Unlock()
			switch {
			case body == "":
				t.Fatalf("%s signed=%v: no request reached the server", name, signed)
			case path != call.path:
				t.Fatalf("%s signed=%v: sent to %q, want %q", name, signed, path, call.path)
			case !signed && authorization != "":
				t.Fatalf("%s: unsigned request sent Authorization %q", name, authorization)
			case signed && (signedFor != body || authorization != "signed "+strconv.Itoa(len(body))):
				t.Fatalf("%s: signature does not cover the body sent: signed %q, sent %q with %q", name, signedFor, body, authorization)
			}
		}
	}
}
