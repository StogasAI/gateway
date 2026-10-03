package policy

import (
	"encoding/json"
	"errors"
	"testing"
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
