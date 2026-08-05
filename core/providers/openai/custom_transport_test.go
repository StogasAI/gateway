package openai

import (
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

type markerFastHTTPTransport struct{}

func (*markerFastHTTPTransport) RoundTrip(_ *fasthttp.HostClient, _ *fasthttp.Request, _ *fasthttp.Response) (bool, error) {
	return false, nil
}

func TestNewOpenAIProviderPropagatesCustomTransportToUnaryAndStreamingClients(t *testing.T) {
	marker := &markerFastHTTPTransport{}
	provider := NewOpenAIProvider(&schemas.ProviderConfig{
		NetworkConfig: schemas.NetworkConfig{Transport: marker},
	}, testNoopLogger{})
	if provider.client.Transport != marker {
		t.Fatal("unary client did not retain the custom transport")
	}
	if provider.streamingClient.Transport != marker {
		t.Fatal("streaming client did not retain the custom transport")
	}
}
