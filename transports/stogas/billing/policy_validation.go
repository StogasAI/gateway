package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// PolicyValidation reports a policy check that creates no hold and changes no state.
type PolicyValidation struct {
	Status           string                  `json:"status"`
	UncheckedPlugins []UncheckedPolicyPlugin `json:"uncheckedPlugins"`
}

// UncheckedPolicyPlugin names an encrypted plugin whose root the check did not
// receive: export or redaction, in the policy itself or in one of its rules.
type UncheckedPolicyPlugin struct {
	PolicyValidationReference
	Rule   string `json:"rule,omitempty"`
	Plugin string `json:"plugin"`
}

func (s *Service) AuthorizePolicyValidation(ctx context.Context, rawKey string, dashboard *DashboardCredential) (*APIKeyClaims, error) {
	if s == nil || s.db == nil {
		return nil, ErrGatewayUnavailable
	}
	// The database finds the key by the ID in its MAC, or the one a dashboard credential selected.
	var hash, keyID, actorID, sessionID *string
	var expected *APIKeyClaims
	if dashboard != nil {
		keyID, actorID, sessionID = &dashboard.KeyID, &dashboard.ActorUserID, &dashboard.SessionID
	} else {
		signed, keyHash, _, err := s.parseVerifiedAPIKey(rawKey)
		if err != nil {
			return nil, err
		}
		hash, keyID, expected = &keyHash, &signed.KeyID, signed
	}
	ctx, cancel := context.WithTimeout(ctx, keyConfigFetchTimeout)
	defer cancel()
	var result string
	var claims *APIKeyClaims
	query := "select result, key_claims from (" + strings.TrimSuffix(s.keyConfigQuery, ";") + ") as policy_authorization"
	if err := s.queryForTool(ctx, query, []any{hash, keyID, actorID, sessionID, nil, "use"}, &result, &claims); err != nil {
		return nil, err
	}
	if err := authorizationResultError(result, nil, RefusedLimit{}); err != nil {
		return nil, err
	}
	if result != "ok" || claims == nil {
		return nil, ErrGatewayUnavailable
	}
	if expected != nil && (claims.KeyID != expected.KeyID || claims.OrganizationID != expected.OrganizationID || claims.ResponsibleID != expected.ResponsibleID || derefString(claims.GrantID) != derefString(expected.GrantID)) {
		return nil, ErrInvalidAPIKey
	}
	return claims, nil
}

type PolicyValidationReference struct {
	Scope policy.Scope `json:"scope"`
	ID    string       `json:"id,omitempty"`
}

type PolicyValidationSource struct {
	PolicyValidationReference
	Config json.RawMessage `json:"config"`
}

func (s *Service) ValidatePolicySources(raw []PolicyValidationSource, organizationID string, key customerkey.Keys) (*PolicyValidation, error) {
	if len(raw) < 2 || len(raw) > 36 {
		return nil, policy.ErrInvalidConfig
	}
	order := map[policy.Scope]int{policy.OrganizationScope: 0, policy.FolderScope: 1, policy.GrantScope: 2, policy.RoleScope: 3, policy.MemberScope: 4, policy.CredentialScope: 5, policy.KeyScope: 6}
	prepared := append([]PolicyValidationSource(nil), raw...)
	seen := map[PolicyValidationReference]bool{}
	counts := map[policy.Scope]int{}
	for _, entry := range prepared {
		if !entry.Scope.Valid() || len(entry.ID) > 64 || len(entry.Config) == 0 || seen[entry.PolicyValidationReference] {
			return nil, policy.ErrInvalidConfig
		}
		seen[entry.PolicyValidationReference] = true
		counts[entry.Scope]++
		if counts[entry.Scope] > 1 && entry.Scope != policy.RoleScope || counts[entry.Scope] > 30 {
			return nil, policy.ErrInvalidConfig
		}
	}
	if counts[policy.OrganizationScope] != 1 || counts[policy.KeyScope] != 1 {
		return nil, policy.ErrInvalidConfig
	}
	sort.Slice(prepared, func(i, j int) bool {
		if prepared[i].Scope == prepared[j].Scope {
			return prepared[i].ID < prepared[j].ID
		}
		return order[prepared[i].Scope] < order[prepared[j].Scope]
	})
	result := &PolicyValidation{Status: "valid", UncheckedPlugins: []UncheckedPolicyPlugin{}}
	var sources []*sharedPolicySource
	defer func() { s.keyConfigs.releaseSources(sources) }()
	values := make([]policy.ScopedSource, 0, len(prepared))
	for _, entry := range prepared {
		source := entry.Config
		if bytes.Equal(bytes.TrimSpace(source), []byte("null")) {
			source = json.RawMessage(`{}`)
		}
		var doc map[string]json.RawMessage
		if json.Unmarshal(source, &doc) != nil {
			return nil, policy.ErrInvalidConfig
		}
		document, err := policy.ParseSourceDocument(source)
		if err != nil {
			return nil, err
		}
		// Check the rest of the policy without each plugin whose root is missing.
		var plugins map[string]json.RawMessage
		for _, plugin := range document.EncryptedPlugins() {
			if matchesEvery(key, plugin.KeyIDs) {
				continue
			}
			if plugins == nil && json.Unmarshal(doc["plugins"], &plugins) != nil {
				return nil, policy.ErrInvalidConfig
			}
			delete(plugins, plugin.Name)
			result.Status = "partial"
			result.UncheckedPlugins = append(result.UncheckedPlugins, UncheckedPolicyPlugin{PolicyValidationReference: entry.PolicyValidationReference, Plugin: plugin.Name})
		}
		var compiled *sharedPolicySource
		if plugins == nil {
			compiled, err = s.keyConfigs.acquireSourceDocument(document, source, organizationID, key, false)
		} else {
			doc["plugins"], _ = json.Marshal(plugins)
			if len(plugins) == 0 {
				delete(doc, "plugins")
			}
			source, _ = json.Marshal(doc)
			compiled, err = s.keyConfigs.acquireSource(source, organizationID, key)
		}
		if err != nil {
			return nil, err
		}
		sources = append(sources, compiled)
		values = append(values, policy.ScopedSource{Scope: entry.Scope, Value: compiled.value})
		// Every bound is the policy's own, so each policy is checked alone:
		// its matchers build, and its sections, which one request can match
		// together, keep to the bounds of one policy.
		if compiled.plan != nil {
			if _, err := compiled.plan.get(); err != nil {
				return nil, err
			}
		}
		sections := []*policy.Plugins{compiled.value.Config.Plugins}
		for _, shared := range compiled.rulePlans {
			if _, err := shared.get(); err != nil {
				return nil, err
			}
		}
		for _, rule := range compiled.value.Rules {
			sections = append(sections, rule.Value.Config.Plugins)
			if rule.Encrypted == nil {
				continue
			}
			var units policy.Permission
			for _, plugin := range rule.Encrypted.EncryptedPlugins() {
				if matchesEvery(key, plugin.KeyIDs) {
					units |= plugin.Unit
					continue
				}
				result.Status = "partial"
				result.UncheckedPlugins = append(result.UncheckedPlugins, UncheckedPolicyPlugin{PolicyValidationReference: entry.PolicyValidationReference, Rule: rule.Name, Plugin: plugin.Name})
			}
			if units == 0 {
				continue
			}
			// The rule's readable plugins are already in its compiled settings.
			opened, err := s.keyConfigs.acquireEncryptedPlugins(policy.EncryptedPlugins{Document: rule.Encrypted, Units: units}, organizationID, key)
			if err != nil {
				return nil, err
			}
			sources = append(sources, opened)
			if opened.plan != nil {
				if _, err := opened.plan.get(); err != nil {
					return nil, err
				}
			}
			sections = append(sections, opened.value.Config.Plugins)
		}
		if err := policy.CheckSections(sections); err != nil {
			return nil, err
		}
	}
	if _, err := policy.ComposeSources(values); err != nil {
		return nil, err
	}
	return result, nil
}
