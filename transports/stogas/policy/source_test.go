package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

func FuzzSourceCanonicalIdentity(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"limits":{"numbers":[-0,1e-7,1e21,9007199254740993,333333333.33333329]}}`,
		`{"limits":{"\ue000":"<>&\u2028","\ud83d\ude00":"é"}}`,
		`{"input":{"asciiOnly":true,"asciiOnly":false}}`,
		`{"limits":{"value":"\ud800"}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		document, err := ParseSourceDocument(raw)
		if !bytes.Equal(raw, before) {
			t.Fatal("parsing mutated the caller's source")
		}
		if err != nil {
			return
		}
		canonical, err := jsoncanonicalizer.Transform(raw)
		if err != nil || !bytes.Equal(document.CanonicalJSON(), append(canonical, '\n')) {
			t.Fatalf("canonical identity differs from independent JCS implementation: %v", err)
		}
	})
}

func TestSavedSourceCompositionMatchesCompilerCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/source-policies.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []struct {
		Name     string
		Sources  [3]json.RawMessage
		Digest   string
		Compiled json.RawMessage
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, row := range corpus {
		t.Run(row.Name, func(t *testing.T) {
			var sources []ScopedSource
			for i, document := range row.Sources {
				if string(document) == "null" {
					continue
				}
				value, compileErr := CompileSource(document)
				err = compileErr
				sources = append(sources, ScopedSource{[]Scope{OrganizationScope, GrantScope, KeyScope}[i], value})
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := ChainDigest(sources); got != row.Digest {
				t.Fatalf("digest=%s want=%s", got, row.Digest)
			}
			got, err := ComposeSources(sources)
			if err != nil {
				t.Fatal(err)
			}
			// Materialize only in the test to compare the old flat execution contract.
			// Runtime retains references to these sections and their individual matchers.
			if len(got.RedactionSources) > 0 {
				p := &Redaction{Presets: []string{}}
				presets, patterns := map[string]bool{}, map[string]bool{}
				for _, part := range got.RedactionSources {
					r := part.StogasRedaction
					for _, s := range r.Presets {
						presets[s] = true
					}
					for _, s := range r.CustomPatterns {
						patterns[s] = true
					}
					p.Literals = append(p.Literals, r.Literals...)
				}
				for s := range presets {
					p.Presets = append(p.Presets, s)
				}
				for s := range patterns {
					p.CustomPatterns = append(p.CustomPatterns, s)
				}
				sort.Strings(p.Presets)
				sort.Strings(p.CustomPatterns)
				p.Literals = redaction.NormalizeLiterals(p.Literals)
				got.Plugins = &Plugins{StogasRedaction: p}
			}
			actualJSON, _ := json.Marshal(got)
			expectedJSON := row.Compiled
			var a, b any
			json.Unmarshal(actualJSON, &a)
			json.Unmarshal(expectedJSON, &b)
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("actual %s\nexpected %s", actualJSON, expectedJSON)
			}
		})
	}
}

func TestSavedSourceRejectsMalformedRuntimePolicy(t *testing.T) {
	for _, raw := range []string{
		`null`, `{"version":1}`, `{"version":2}`, `{"version":1,"version":1}`,
		`{"routing":null}`, `{"plugins":{"stogasRedaction":null}}`,
		`{"plugins":{"stogasRedaction":{"email_address":null}}}`,
		`{"plugins":{"stogasRedaction":{"invented":true}}}`,
		`{"routing":{"sortOverridable":false}}`,
		`{"routing":{"filter":"unknown == 1"}}`,
		`{"routing":{"fallbacks":{"maxPreDispatchCandidates":0}}}`,
		`{"delegation":{"request":"yes"}}`,
		`{"plugins":{"stogasRedaction":{"literals":[]}}}`,
		`{"plugins":{"stogasRedaction":{"literals":[{"values":[]}]}}}`,
		`{"plugins":{"stogasRedaction":{"literals":[{"values":["abcdefgh","short"],"fuzzy":true}]}}}`,
		`{"plugins":{"stogasRedaction":{"literals":[{"values":["abcdefgh"],"fuzzy":true,"wholeWord":false}]}}}`,
		`{"unexpected":true}`,
		`{"enabled":false}`, `{"expiresAt":"2027-01-01T00:00:00Z"}`,
		`{"plugins":{"stogasRedaction":{"literals":[{"text":"foo","surprise":true}]}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, err := ParseSourceDocument([]byte(strings.Repeat(" ", 2*MaxSourceBytes+1))); err == nil {
		t.Fatal("accepted oversized source")
	}
}

func TestCompositionKeepsParentsImmutableAndChecksCombinedLimits(t *testing.T) {
	org, err := CompileSource([]byte(`{"routing":{"filter": "provider.id == \"openai\""},"plugins":{"stogasRedaction":{"customPattern":"ABCD"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	key, err := CompileSource([]byte(`{"delegation":{"request":["routing"]},"routing":{"filter": "model.id == \"model\"", "sort": [{"by":"provider.id","direction":"asc"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(org.Config)
	combined, err := ComposeSources([]ScopedSource{{OrganizationScope, org}, {KeyScope, key}})
	if err != nil {
		t.Fatal(err)
	}
	if combined.RedactionSources[0] != org.Config.Plugins || combined.Routing.Query.Filters[0] != org.Config.Routing.Query.Filters[0] {
		t.Fatal("parent data was copied")
	}
	_, err = applyRequestJSON(combined, []byte(`{"routing":{"filter": "deployment.contextWindowTokens < 1000"}}`))
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(org.Config)
	if string(before) != string(after) {
		t.Fatal("request changed parent")
	}
	for _, sources := range [][]ScopedSource{
		{{KeyScope, key}},
		{{OrganizationScope, nil}, {KeyScope, key}},
		{{OrganizationScope, org}, {KeyScope, nil}},
		{{OrganizationScope, org}, {Scope("unknown"), key}, {KeyScope, key}},
	} {
		if _, err := ComposeSources(sources); err == nil {
			t.Fatal("missing or invalid scope accepted")
		}
	}
	if _, err := ComposeSources([]ScopedSource{{OrganizationScope, org}}); err != nil {
		t.Fatalf("organization preview failed: %v", err)
	}
	forbidden, _ := CompileSource([]byte(`{"delegation":{"keys":true}}`))
	if _, err := ComposeSources([]ScopedSource{{OrganizationScope, org}, {KeyScope, forbidden}}); err == nil {
		t.Fatal("key delegated editing")
	}
}
