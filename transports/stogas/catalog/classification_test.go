package catalog

import (
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func classificationPolicy(t *testing.T, raw string) *policy.Config {
	t.Helper()
	source, err := policy.CompileSource([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestInputClassification(t *testing.T) {
	const german = "Kannst du mir bitte erklären, wie ich in Python eine Liste nach einem Schlüssel sortiere? Ich habe es mit sorted versucht."
	smuggled := "Summarize this." + "\U000E0069\U000E0067\U000E006E\U000E006F\U000E0072\U000E0065"
	both := `{"plugins":{"classification":["language","hidden_characters"]}}`
	for _, test := range []struct {
		name, path, policy, body string
		classifiers              int
		language                 string
		hidden                   int
	}{
		{
			"the newest user message, whatever came before", "/v1/chat/completions", both,
			`{"model":"openai-gpt-5.6-sol","messages":[{"role":"system","content":"` + smuggled + `"},{"role":"user","content":"Please translate this email into a more formal tone and keep it short."},{"role":"assistant","content":"Sure."},{"role":"user","content":[{"type":"text","text":"` + german + `​​"}]}]}`,
			2, "de", 8,
		},
		{
			"code in a fence is not prose", "/v1/chat/completions", both,
			"{\"model\":\"openai-gpt-5.6-sol\",\"messages\":[{\"role\":\"user\",\"content\":\"" + german + "\\n```python\\nfor item in sorted(items, key=lambda item: item.name):\\n    print(item)\\n```\"}]}",
			2, "de", 0,
		},
		{
			"a newest message without prose leaves it to the one before", "/v1/chat/completions", both,
			`{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":"` + german + `"},{"role":"assistant","content":"Ja."},{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}`,
			2, "de", 0,
		},
		{
			"input text on Responses", "/v1/responses", both,
			`{"model":"openai-gpt-5.6-sol","instructions":"` + smuggled + `","input":[{"role":"user","content":[{"type":"input_text","text":"` + german + `"}]},{"type":"function_call_output","call_id":"call_1","output":"Please translate this email into a more formal tone and keep it short."}]}`,
			2, "de", 6,
		},
		{"an input string", "/v1/responses", both, `{"model":"openai-gpt-5.6-sol","input":"` + german + `"}`, 2, "de", 0},
		{"no prose", "/v1/responses", both, `{"model":"openai-gpt-5.6-sol","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.com/a.png"}]}]}`, 2, "", 0},
		{"too short to tell", "/v1/responses", both, `{"model":"openai-gpt-5.6-sol","input":"ok"}`, 2, "und", 0},
		{"only languages", "/v1/responses", `{"plugins":{"classification":["language"]}}`, `{"model":"openai-gpt-5.6-sol","input":"` + german + smuggled + `"}`, 1, "de", 0},
		{"no classifiers", "/v1/responses", `{}`, `{"model":"openai-gpt-5.6-sol","input":"` + german + `"}`, 0, "", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := ResolveRequest(RequestInput{
				AvailableCredentials: map[string][]int{"openai": {0}},
				Body:                 []byte(test.body),
				Method:               "POST",
				Path:                 test.path,
				Policy:               classificationPolicy(t, test.policy),
			})
			if err != nil {
				t.Fatal(err)
			}
			language, hidden := resolved.InputClassification()
			if len(resolved.Classifiers()) != test.classifiers || language != test.language || hidden != test.hidden {
				t.Fatalf("classifiers %q, language %q, hidden %d; want %d classifiers, %q, %d",
					resolved.Classifiers(), language, hidden, test.classifiers, test.language, test.hidden)
			}
		})
	}
}
