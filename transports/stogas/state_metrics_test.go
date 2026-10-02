package stogas

import (
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

func TestRequestPluginMetricsDistinguishDisabledAndCleanRedaction(t *testing.T) {
	configured, err := redaction.CompilePolicy(redaction.Options{Patterns: []redaction.Pattern{redaction.PatternEmailAddress}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, policy := range []*redaction.Policy{nil, configured} {
			body := []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}]}`)
			if path == "/v1/responses" {
				body = []byte(`{"model":"gpt-5.5","input":"hello"}`)
			}
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: path, Body: body, RedactionPolicy: policy})
			if err != nil {
				t.Fatal(err)
			}
			state := NewState(resolved, "", nil, AdapterFor(resolved.Provider))
			metrics := state.PluginMetrics.StogasStructuredPIIRedaction
			if (metrics != nil) != (policy != nil) || metrics != nil && metrics.ItemsRedacted != 0 {
				t.Fatalf("%s: policy=%t metrics=%+v", path, policy != nil, metrics)
			}
		}
	}
}
