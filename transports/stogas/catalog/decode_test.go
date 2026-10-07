package catalog

import "testing"

func TestCatalogDecodeRejectsAmbiguousMembers(t *testing.T) {
	for _, input := range []string{
		`{"schema":"stogas.catalog.runtime.v3","schema":"stogas.catalog.runtime.v3"}`,
		`{"schema":"stogas.catalog.runtime.v3","Schema":"stogas.catalog.runtime.v3"}`,
		`{"graph":{"deployments":{"a":{"pricing":{"input_tokens":{"per_mill_tokens":"1","per_mill_tokens":"2"}}}}}}`,
		`{"graph":{"deployments":{"a":{"fileInputsByRoute":{"openai-responses":{"mediaTypes":[],"extensions":[],"remoteParser":"https://example.com"}}}}}}`,
	} {
		if _, err := decodeCompiledCatalog([]byte(input)); err == nil {
			t.Fatalf("accepted ambiguous or unknown catalog member: %s", input)
		}
	}
}
