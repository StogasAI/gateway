package policy

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
)

func TestDelegationChecksSectionsAndExactResourceIDs(t *testing.T) {
	const id = "019a0100-0000-7000-8000-000000000001"
	const other = "019a0100-0000-7000-8000-000000000002"
	for _, scope := range []Scope{FolderScope, GrantScope, RoleScope, MemberScope, CredentialScope, KeyScope} {
		t.Run(string(scope), func(t *testing.T) {
			parent, _ := json.Marshal(map[string]any{"delegation": map[string]any{delegationTarget(scope): map[string]any{"default": false, "exceptions": map[string]any{id: []string{"routing.filter"}}}}})
			entries := []InspectionSource{{Scope: OrganizationScope, Config: parent}}
			// A second role must not cause the first role's exception to be ignored.
			entries = append(entries, InspectionSource{Scope: scope, ID: id, Config: json.RawMessage(`{"routing":{"filter":"provider.id == 'openai'"}}`)})
			if scope == RoleScope {
				entries = append(entries, InspectionSource{Scope: RoleScope, ID: other, Config: json.RawMessage(`{}`)})
			}
			if scope != KeyScope {
				entries = append(entries, InspectionSource{Scope: KeyScope, Config: json.RawMessage(`{}`)})
			}
			edit := &InspectionEdit{Scope: scope, ID: id, Previous: json.RawMessage(`{}`)}
			if _, err := InspectSources(entries, edit); err != nil {
				t.Fatalf("allowed filter: %v", err)
			}
			entries[1].Config = json.RawMessage(`{"routing":{"filter":"provider.id == 'openai'"},"input":{"asciiOnly":true}}`)
			if _, err := InspectSources(entries, edit); !errors.Is(err, ErrPolicyEditForbidden) {
				t.Fatalf("disallowed input setting: %v", err)
			}
			entries[1].Config = json.RawMessage(`{}`)
			if _, err := InspectSources(entries, edit); err != nil {
				t.Fatalf("clear under restriction: %v", err)
			}
			entries[1].ID = other
			edit.ID = other
			entries[1].Config = json.RawMessage(`{"routing":{"filter":"provider.id == 'openai'"}}`)
			if _, err := InspectSources(entries, edit); !errors.Is(err, ErrPolicyEditForbidden) {
				t.Fatalf("exception leaked to another ID: %v", err)
			}
		})
	}
}

func TestDelegationFollowsResourceOwnershipAndRequestPermissionsIntersect(t *testing.T) {
	for _, owner := range []Scope{OrganizationScope, FolderScope, GrantScope, RoleScope, MemberScope, CredentialScope, KeyScope} {
		for _, target := range []Scope{FolderScope, GrantScope, RoleScope, MemberScope, CredentialScope, KeyScope} {
			raw, _ := json.Marshal(map[string]any{"delegation": map[string]any{delegationTarget(target): false, "request": []string{"routing.filter"}}})
			source, err := CompileSource(raw)
			if err != nil {
				t.Fatal(err)
			}
			empty, err := CompileSource([]byte(`{"delegation":{"request":true}}`))
			if err != nil {
				t.Fatal(err)
			}
			chain := []ScopedSource{{Scope: OrganizationScope, Value: empty}}
			if owner == OrganizationScope {
				chain[0].Value = source
			} else if owner != KeyScope {
				chain = append(chain, ScopedSource{Scope: owner, Value: source})
			}
			key := empty
			if owner == KeyScope {
				key = source
			}
			chain = append(chain, ScopedSource{Scope: KeyScope, Value: key})
			config, err := ComposeSources(chain)
			allowed := owner == OrganizationScope || owner == FolderScope && (target == GrantScope || target == KeyScope) || owner == GrantScope && target == KeyScope
			if (err == nil) != allowed {
				t.Fatalf("%s -> %s: %v", owner, target, err)
			}
			if allowed && Permission(config.RequestPermission) != permissionFilter {
				t.Fatalf("%s request permission did not intersect", owner)
			}
		}
	}
	for _, raw := range []string{
		`{"delegation":{"request":["limits"]}}`,
		`{"delegation":{"request":["delegation"]}}`,
		`{"delegation":{"request":["encryption"]}}`,
		`{"delegation":{"keys":["unknown"]}}`,
		`{"delegation":{"keys":["input","input"]}}`,
		`{"delegation":{"keys":{"default":true,"exceptions":{}}}}`,
		`{"delegation":{"keys":{"default":true,"exceptions":{"not-an-id":false}}}}`,
		`{"delegation":{"keys":null}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid permission: %s", raw)
		}
	}
}

func TestEncryptedPluginsNeedEveryPluginPermission(t *testing.T) {
	raw, err := os.ReadFile("../customerkey/testdata/webcrypto.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Root, OrganizationID string
		Envelope             customerkey.Envelope
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := customerkey.Parse(fixture.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Clear()
	plugins := map[string]any{"encrypted": fixture.Envelope}
	for _, permission := range [][]string{{"plugins.stogasRedaction", "plugins.encrypted"}, {"plugins"}} {
		// The ciphertext can hold an export that the parent did not allow.
		allowed := len(permission) == 1
		parent, _ := json.Marshal(map[string]any{
			"encryption": map[string]any{"keys": map[string]string{"test": fixture.Envelope.KeyID}},
			"delegation": map[string]any{"keys": permission, "request": permission},
		})
		for _, child := range []map[string]any{{"plugins": plugins}, {"rules": map[string]any{"private": map[string]any{"plugins": plugins}}}} {
			config, _ := json.Marshal(child)
			entries := []InspectionSource{{Scope: OrganizationScope, Config: parent}, {Scope: KeyScope, Config: config}}
			_, err := InspectSources(entries, &InspectionEdit{Scope: KeyScope, Previous: json.RawMessage(`{}`)})
			if allowed && err != nil || !allowed && !errors.Is(err, ErrPolicyEditForbidden) {
				t.Fatalf("saved %s with %v: %v", config, permission, err)
			}
		}
		base, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, string(parent))}})
		if err != nil {
			t.Fatal(err)
		}
		config, _ := json.Marshal(map[string]any{"plugins": plugins})
		request, err := CompileRequest(config, fixture.OrganizationID, customerkey.Keys{"test": key})
		if err != nil {
			t.Fatal(err)
		}
		_, err = ApplyRequest(base, request)
		if allowed && err != nil || !allowed && !errors.Is(err, ErrRequestPolicyDenied) {
			t.Fatalf("request with %v: %v", permission, err)
		}
	}
}

// A policy keeps sections that its parents no longer permit until someone
// removes them, but nobody can add or change those sections.
func TestPoliciesKeepSectionsTheirParentsNoLongerPermit(t *testing.T) {
	org := json.RawMessage(`{"delegation":{"keys":["routing.filter","input"]}}`)
	folder := json.RawMessage(`{"delegation":{"keys":["routing.filter","timeouts.totalSeconds"]}}`)
	previous := `{"input":{"asciiOnly":true},"routing":{"filter":"provider.id != 'a'"},"rules":{"chat":{"when":"request.interface == 'chat_completions'","timeouts":{"totalSeconds":60}}}}`
	inspect := func(proposal string, previous json.RawMessage) (*Inspection, error) {
		return InspectSources([]InspectionSource{
			{Scope: OrganizationScope, Config: org},
			{Scope: FolderScope, ID: "folder", Config: folder},
			{Scope: KeyScope, ID: "key", Config: json.RawMessage(proposal)},
		}, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: previous})
	}
	kept := []InspectionNote{
		{Kind: "kept", Scope: OrganizationScope, Sections: []string{"timeouts.totalSeconds"}},
		{Kind: "kept", Scope: FolderScope, ID: "folder", Sections: []string{"input"}},
	}
	for _, proposal := range []string{
		previous,
		strings.Replace(previous, "provider.id != 'a'", "provider.id != 'b'", 1),
		strings.Replace(previous, `"rules"`, `"$schema":"https://stogas.ai/schemas/key-config-v1.json","rules"`, 1),
	} {
		inspection, err := inspect(proposal, json.RawMessage(previous))
		if err != nil || !reflect.DeepEqual(inspection.Notes, kept) {
			t.Fatalf("%s: notes %+v, %v", proposal, inspection, err)
		}
	}
	inspection, err := inspect(`{"rules":{"chat":{"when":"request.interface == 'chat_completions'","timeouts":{"totalSeconds":60}}}}`, json.RawMessage(previous))
	if err != nil || !reflect.DeepEqual(inspection.Notes, kept[:1]) {
		t.Fatalf("removing a kept section: %+v, %v", inspection, err)
	}
	for proposal, message := range map[string]string{
		strings.Replace(previous, `"asciiOnly":true`, `"asciiOnly":false`, 1):           "The folder policy does not let key policies set input",
		strings.Replace(previous, `"totalSeconds":60`, `"totalSeconds":30`, 1):          "The organization policy does not let key policies set timeouts.totalSeconds",
		strings.Replace(previous, `request.interface == 'chat_completions'`, `true`, 1): "The organization policy does not let key policies set timeouts.totalSeconds",
		strings.Replace(previous, `"chat"`, `"chats"`, 1):                               "The organization policy does not let key policies set timeouts.totalSeconds",
		strings.Replace(previous, `"when"`, `"mode":"default","when"`, 1):               "The organization policy does not let key policies set timeouts.totalSeconds",
	} {
		if _, err := inspect(proposal, json.RawMessage(previous)); !errors.Is(err, ErrPolicyEditForbidden) || err.Error() != message {
			t.Fatalf("%s: %v", proposal, err)
		}
	}
	// A move has no previous policy, so its new parents check every section.
	for _, before := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`{}`)} {
		_, err := inspect(previous, before)
		if !errors.Is(err, ErrPolicyEditForbidden) || err.Error() != "The organization policy does not let key policies set timeouts.totalSeconds" {
			t.Fatalf("previous %s: %v", before, err)
		}
	}
}
