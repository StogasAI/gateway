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
	const responseCap = 123456
	provider := NewOpenAIProvider(&schemas.ProviderConfig{
		NetworkConfig: schemas.NetworkConfig{Transport: marker, MaxResponseBodySize: responseCap},
	}, testNoopLogger{})
	if provider.client.Transport != marker {
		t.Fatal("unary client did not retain the custom transport")
	}
	if provider.streamingClient.Transport != marker {
		t.Fatal("streaming client did not retain the custom transport")
	}
	if provider.client.MaxResponseBodySize != responseCap || provider.streamingClient.MaxResponseBodySize != responseCap {
		t.Fatalf("response cap did not reach both clients: unary=%d stream=%d", provider.client.MaxResponseBodySize, provider.streamingClient.MaxResponseBodySize)
	}
}
