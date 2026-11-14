package catalog

import "testing"

func TestCatalogDecodeRejectsAmbiguousMembers(t *testing.T) {
	for _, test := range []struct {
		into  any
		input string
	}{
		{&catalogRoot{}, `{"schema":"stogas.catalog.v1","schema":"stogas.catalog.v1"}`},
		{&catalogRoot{}, `{"schema":"stogas.catalog.v1","Schema":"stogas.catalog.v1"}`},
		{&catalogRoot{}, `{"locations":{"world":{"name":"World","parentIds":[],"name":"Earth"}}}`},
		{&catalogRoot{}, `{"locations":{"world":{"name":"World","parentIds":[],"childIds":[]}}}`},
		{&catalogRoot{}, `{"summaries":{"deployments":{"a":{"part":0,"retirementDate":null,"notes":""}}}}`},
		{&catalogRoot{}, `{"summaries":{"providers":{"openai":{"aliases":[],"credentialModes":["byok"],"name":"OpenAI","retirementDate":null,"region":"us"}}}}`},
		{&catalogPart{}, `{"graph":{"deployments":{"a":{"pricing":{"input_tokens":{"per_mill_tokens":"1","per_mill_tokens":"2"}}}}}}`},
		{&catalogPart{}, `{"graph":{"routes":{"openai-responses":{"documentFormats":{"mediaTypes":[],"extensions":[],"remoteParser":"https://example.com"}}}}}`},
		{&catalogPart{}, `{"graph":{"models":{"m":{"capabilities":{},"description":"shown nowhere"}}}}`},
		{&catalogPart{}, `{"graph":{"providers":{}}}`},
	} {
		if err := decodeStrict([]byte(test.input), test.into, sharedJSON[Pricing]()); err == nil {
			t.Fatalf("accepted ambiguous or unknown catalog member: %s", test.input)
		}
	}
}
