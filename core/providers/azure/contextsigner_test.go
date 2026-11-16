package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// Each call reads its headers from the context's signer, on the OpenAI and the
// Claude paths, so a retry sends the token current when it starts.
func TestContextSignerSuppliesEachCallsHeaders(t *testing.T) {
	var mu sync.Mutex
	var authorization, apiKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authorization, apiKey = r.Header.Get("Authorization"), r.Header.Get("api-key")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()
	provider, err := NewAzureProvider(&schemas.ProviderConfig{
		NetworkConfig: schemas.NetworkConfig{DefaultRequestTimeoutInSeconds: 10},
	}, &authTestLogger{})
	if err != nil {
		t.Fatal(err)
	}
	key := schemas.Key{
		Models:         []string{"*"},
		AzureKeyConfig: &schemas.AzureKeyConfig{Endpoint: *schemas.NewSecretVar(server.URL)},
	}
	text := "hi"
	for _, model := range []string{"gpt-5", "claude-sonnet-4-5"} {
		ctx, cancel := schemas.NewBifrostContextWithTimeout(context.Background(), 10*time.Second)
		attempts := 0
		ctx.SetValue(schemas.BifrostContextKeyRequestSigner, schemas.RequestSigner(func([]byte) (map[string]string, *schemas.BifrostError) {
			attempts++
			return map[string]string{"Authorization": "Bearer token-" + strconv.Itoa(attempts)}, nil
		}))
		for attempt := 1; attempt <= 2; attempt++ {
			_, _ = provider.ChatCompletion(ctx, key, &schemas.BifrostChatRequest{
				Provider: schemas.Azure,
				Model:    model,
				Input:    []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: &text}}},
			})
			mu.Lock()
			got, gotAPIKey := authorization, apiKey
			mu.Unlock()
			if want := "Bearer token-" + strconv.Itoa(attempt); got != want || gotAPIKey != "" {
				t.Fatalf("%s attempt %d sent Authorization %q and api-key %q, want %q", model, attempt, got, gotAPIKey, want)
			}
		}
		cancel()
	}

	// A sign-in that fails stops the call before it reaches Azure.
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	refused := &schemas.BifrostError{StatusCode: schemas.Ptr(http.StatusUnauthorized), Error: &schemas.ErrorField{Message: "Upstream credential rejected"}}
	ctx.SetValue(schemas.BifrostContextKeyRequestSigner, schemas.RequestSigner(func([]byte) (map[string]string, *schemas.BifrostError) {
		return nil, refused
	}))
	if _, err := provider.getAzureAuthHeaders(ctx, key, false); err != refused {
		t.Fatalf("failed sign-in returned %v", err)
	}
}
