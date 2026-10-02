package catalog

import (
	"errors"
	"fmt"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestRoutingQueryUsesFactsAvailableBeforeInputProcessing(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		content := `"messages":[{"role":"user","content":"hello 🌍 contact a@b.co"}],"max_completion_tokens":100`
		if path == "/v1/responses" {
			content = `"input":"hello 🌍 contact a@b.co","max_output_tokens":100`
		}
		body := []byte(`{"model":"gpt-5.6-sol",` + content + `}`)
		input := RequestInput{AvailableCredentials: map[string][]int{"openai": {0}}, Method: "POST", Path: path, Body: body, RedactionPolicy: testEmailRedactionPolicy(t)}
		base, err := ResolveRequest(input)
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			source  string
			allowed bool
		}{
			{"request.model == 'gpt-5.6-sol'", true},
			{"!has(request.model)", false},
			{fmt.Sprintf("request.route == '%s'", base.Route), true},
			{fmt.Sprintf("request.bodyBytes == %d", len(body)), true},
			{fmt.Sprintf("request.bodyBytes < %d", len(body)), false},
		} {
			config := policyConfig(1)
			config.Routing.Query, err = policy.CompileRouting(test.source, nil)
			if err != nil {
				t.Fatal(err)
			}
			input.Policy = config
			_, err = ResolveRequest(input)
			if test.allowed && err != nil {
				t.Fatalf("%s %s: %v", path, test.source, err)
			}
			if !test.allowed && !errors.Is(err, ErrModelUnavailable) {
				t.Fatalf("%s %s: allowed || wrong error: %v", path, test.source, err)
			}
		}
	}
}

func TestRoutingCannotDependOnPostRedactionEstimates(t *testing.T) {
	for _, expression := range []string{"request.estimatedInputTokens > 0", "request.maximumOutputTokens > 0", "estimated_cost('per_mill_tokens') > decimal('0')"} {
		if _, err := policy.CompileRouting(expression, nil); err == nil {
			t.Fatalf("accepted filter %s", expression)
		}
		if _, err := policy.CompileRouting("", []policy.Sort{{By: expression, Direction: "asc"}}); err == nil {
			t.Fatalf("accepted sort %s", expression)
		}
	}
}
