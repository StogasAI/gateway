package schemas

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
)

type runtimeOnlyTransport struct{}

func (*runtimeOnlyTransport) RoundTrip(_ *fasthttp.HostClient, _ *fasthttp.Request, _ *fasthttp.Response) (bool, error) {
	return false, nil
}

func TestNetworkConfigDoesNotSerializeRuntimeTransport(t *testing.T) {
	encoded, err := json.Marshal(NetworkConfig{
		BaseURL:   "https://example.com",
		Transport: &runtimeOnlyTransport{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "transport") {
		t.Fatalf("runtime transport leaked into JSON: %s", encoded)
	}
	var decoded NetworkConfig
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Transport != nil {
		t.Fatal("JSON unexpectedly populated a runtime transport")
	}
}
