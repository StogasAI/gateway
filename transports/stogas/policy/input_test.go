package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestMediaTypeListsTakeLowercaseTypesAndClasses(t *testing.T) {
	for _, tc := range []struct {
		types string
		err   string
	}{
		{`{"allow":["image/png","text/*"],"deny":["image/svg+xml"]}`, ""},
		{`{"allow":[]}`, ""},
		{`{"deny":["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]}`, ""},
		{`{}`, "input.mediaTypes requires allow or deny"},
		{`{"allow":["Image/png"]}`, `input.mediaTypes.allow has "Image/png", which is not a lowercase media type such as image/png or class such as image/*`},
		{`{"deny":["image"]}`, `input.mediaTypes.deny has "image", which is not`},
		{`{"deny":["*/*"]}`, `input.mediaTypes.deny has "*/*", which is not`},
		{`{"deny":["text/plain; charset=utf-8"]}`, `input.mediaTypes.deny has "text/plain; charset=utf-8", which is not`},
		{`{"deny":["image/png","image/png"]}`, `input.mediaTypes.deny lists "image/png" twice`},
		{`{"deny":[` + manyTypes(65) + `]}`, "input.mediaTypes.deny lists at most 64 types"},
	} {
		t.Run(tc.types, func(t *testing.T) {
			_, err := CompileSource([]byte(`{"input":{"mediaTypes":` + tc.types + `}}`))
			if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("got %v, want %q", err, tc.err)
			}
		})
	}
}

func manyTypes(n int) string {
	values := make([]string, n)
	for i := range values {
		values[i] = fmt.Sprintf(`"x/t%d"`, i)
	}
	return strings.Join(values, ",")
}

// Every policy's lists apply: the types that all allow lists admit, and the types that any deny
// list names.
func TestMediaTypeListsCombineAcrossPolicies(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sources []string
		want    *Input
	}{
		{"one policy", []string{`{"input":{"mediaTypes":{"deny":["audio/*"]}}}`}, &Input{MediaTypes: &MediaTypes{Deny: []string{"audio/*"}}}},
		{"allow lists intersect", []string{`{"input":{"mediaTypes":{"allow":["image/*","text/plain"]}}}`, `{"input":{"mediaTypes":{"allow":["image/png","application/pdf","text/*"]}}}`},
			&Input{MediaTypes: &MediaTypes{Allow: []string{"image/png", "text/plain"}}}},
		{"disjoint allow lists admit nothing", []string{`{"input":{"mediaTypes":{"allow":["image/*"]}}}`, `{"input":{"mediaTypes":{"allow":["text/*"]}}}`},
			&Input{MediaTypes: &MediaTypes{Allow: []string{}}}},
		{"deny lists join", []string{`{"input":{"mediaTypes":{"deny":["audio/*","image/gif"]}}}`, `{"input":{"mediaTypes":{"deny":["image/gif","video/*"]}}}`},
			&Input{MediaTypes: &MediaTypes{Deny: []string{"audio/*", "image/gif", "video/*"}}}},
		{"ASCII and types", []string{`{"input":{"asciiOnly":true}}`, `{"input":{"mediaTypes":{"allow":["text/*"]}}}`},
			&Input{ASCIIOnly: true, MediaTypes: &MediaTypes{Allow: []string{"text/*"}}}},
		{"a rule's list", []string{`{"rules":{"strict":{"when":"provider.id == 'openai'","input":{"mediaTypes":{"deny":["image/*"]}}}}}`, `{"input":{"mediaTypes":{"deny":["audio/*"]}}}`},
			&Input{MediaTypes: &MediaTypes{Deny: []string{"audio/*", "image/*"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := []ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, `{}`)}}
			for _, raw := range tc.sources {
				sources = append(sources, ScopedSource{Scope: KeyScope, Value: ruleSource(t, raw)})
			}
			combined, err := ComposeSources(sources)
			if err != nil {
				t.Fatal(err)
			}
			active, err := combined.Activate(ruleValues{"provider.id": {Type: "string", String: "openai"}})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(active.Input, tc.want) {
				got, _ := json.Marshal(active.Input)
				t.Fatalf("got %s", got)
			}
			// Composition never changes a source's own lists.
			for _, source := range sources[1:] {
				if input := source.Value.Config.Input; input != nil && input.MediaTypes != nil && input.MediaTypes.Allow != nil && len(input.MediaTypes.Allow) == 0 {
					t.Fatal("composition emptied a source's allow list")
				}
			}
		})
	}
}

func TestMediaTypesRefuseWhatTheyCannotCheck(t *testing.T) {
	allowImages := &MediaTypes{Allow: []string{"image/*", "application/pdf"}}
	denyGIF := &MediaTypes{Deny: []string{"image/gif"}}
	denyAudio := &MediaTypes{Deny: []string{"audio/*"}}
	none := &MediaTypes{Allow: []string{}}
	for _, tc := range []struct {
		types        *MediaTypes
		class, value string
		refused      bool
	}{
		{nil, "", "", false},
		{allowImages, "image", "image/png", false},
		{allowImages, "application", "application/pdf", false},
		{allowImages, "text", "text/plain", true},
		{allowImages, "image", "", false},
		{allowImages, "", "", true},
		{denyGIF, "image", "image/gif", true},
		{denyGIF, "image", "image/png", false},
		{denyGIF, "image", "", true},
		{denyGIF, "audio", "", false},
		{denyGIF, "", "", true},
		{denyAudio, "image", "", false},
		{denyAudio, "audio", "audio/wav", true},
		{none, "image", "image/png", true},
		{&MediaTypes{Allow: []string{"image/png"}}, "image", "", true},
	} {
		if got := tc.types.Refuses(tc.class, tc.value); got != tc.refused {
			t.Errorf("%+v refuses %q %q: %v", tc.types, tc.class, tc.value, got)
		}
	}
}

func TestInspectionShowsCombinedMediaTypesAndEveryPolicyThatSetsThem(t *testing.T) {
	org := InspectionSource{Scope: OrganizationScope, ID: "org", Config: json.RawMessage(`{"input":{"mediaTypes":{"deny":["audio/*"]}}}`)}
	key := InspectionSource{Scope: KeyScope, ID: "key", Config: json.RawMessage(`{"input":{"asciiOnly":true,"mediaTypes":{"allow":["image/*"]}}}`)}
	result, err := InspectSources([]InspectionSource{org, key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	effective, _ := json.Marshal(result.Effective["input"])
	if string(effective) != `{"asciiOnly":true,"mediaTypes":{"allow":["image/*"],"deny":["audio/*"]}}` {
		t.Fatalf("effective input %s", effective)
	}
	var setBy []string
	entries, _ := result.Effective["setBy"].([]map[string]any)
	for _, entry := range entries {
		if entry["setting"] == "input" {
			setBy = append(setBy, fmt.Sprint(entry["policy"]))
		}
	}
	if len(setBy) != 2 {
		t.Fatalf("input set by %v", setBy)
	}
}
