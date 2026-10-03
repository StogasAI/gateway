package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// Validation checks execution rules without creating a hold or updating state.
type PolicyValidation struct {
	Scope            string                  `json:"scope"`
	Status           string                  `json:"status"`
	UncheckedPlugins []UncheckedPolicyPlugin `json:"uncheckedPlugins"`
}

type UncheckedPolicyPlugin struct {
	PolicyValidationReference
	Rule string `json:"rule,omitempty"`
}

func (s *Service) AuthorizePolicyValidation(ctx context.Context, rawKey string, dashboard *DashboardCredential) (*APIKeyClaims, error) {
	if s == nil || s.db == nil {
		return nil, ErrGatewayUnavailable
	}
	var hash, dashboardID, actorID, sessionID *string
	var expected *APIKeyClaims
	if dashboard != nil {
		dashboardID, actorID, sessionID = &dashboard.KeyID, &dashboard.ActorUserID, &dashboard.SessionID
	} else {
		signed, keyHash, _, err := s.parseVerifiedAPIKey(rawKey)
		if err != nil {
			return nil, err
		}
		hash, expected = &keyHash, signed
	}
	ctx, cancel := context.WithTimeout(ctx, keyConfigFetchTimeout)
	defer cancel()
	var result string
	var claims *APIKeyClaims
	query := "select result, key_claims from (" + strings.TrimSuffix(s.keyConfigQuery, ";") + ") as policy_authorization"
	if err := s.db.pool.QueryRow(ctx, query, hash, dashboardID, actorID, sessionID, nil).Scan(&result, &claims); err != nil {
		return nil, ErrGatewayUnavailable
	}
	if err := authorizationResultError(result); err != nil {
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
	result := &PolicyValidation{Scope: "execution", Status: "valid", UncheckedPlugins: []UncheckedPolicyPlugin{}}
	var sources []*sharedPolicySource
	defer func() { s.keyConfigs.releaseSources(sources) }()
	values := make([]policy.ScopedSource, 0, len(prepared))
	var plans []*redaction.Policy
	var registered map[string]string
	for _, entry := range prepared {
		source := entry.Config
		if bytes.Equal(bytes.TrimSpace(source), []byte("null")) {
			source = json.RawMessage(`{}`)
		}
		var doc map[string]json.RawMessage
		if json.Unmarshal(source, &doc) != nil {
			return nil, policy.ErrInvalidConfig
		}
		var plugins map[string]json.RawMessage
		if json.Unmarshal(doc["plugins"], &plugins) == nil && plugins["encrypted"] != nil {
			if _, err := policy.ParseSourceDocument(source); err != nil {
				return nil, err
			}
			var envelope customerkey.Envelope
			if json.Unmarshal(plugins["encrypted"], &envelope) != nil {
				return nil, customerkey.ErrEnvelope
			}
			if entry.Scope == policy.OrganizationScope {
				var encryption struct {
					Keys map[string]string `json:"keys"`
				}
				if json.Unmarshal(doc["encryption"], &encryption) != nil {
					return nil, customerkey.ErrKey
				}
				registered = encryption.Keys
			}
			if !customerkey.Registered(registered, envelope.KeyID) {
				return nil, customerkey.ErrKey
			}
			if !key.Matches(envelope.KeyID) {
				delete(doc, "plugins")
				source, _ = json.Marshal(doc)
				result.Status = "partial"
				result.UncheckedPlugins = append(result.UncheckedPlugins, UncheckedPolicyPlugin{PolicyValidationReference: entry.PolicyValidationReference})
			}
		}
		compiled, err := s.keyConfigs.acquireSource(source, organizationID, key)
		if err != nil {
			return nil, err
		}
		sources = append(sources, compiled)
		values = append(values, policy.ScopedSource{Scope: entry.Scope, Value: compiled.value})
		if entry.Scope == policy.OrganizationScope {
			registered = compiled.value.EncryptionKeys
			if err := key.Validate(registered); err != nil {
				return nil, err
			}
		}
		if compiled.plan != nil {
			plan, err := compiled.plan.get()
			if err != nil {
				return nil, err
			}
			plans = append(plans, plan)
		}
		for _, plan := range compiled.rulePlans {
			if _, err := plan.get(); err != nil {
				return nil, err
			}
		}
		for _, rule := range compiled.value.Rules {
			if rule.Encrypted == nil {
				continue
			}
			if !customerkey.Registered(registered, rule.Encrypted.EncryptionKeyID()) {
				return nil, customerkey.ErrKey
			}
			if !key.Matches(rule.Encrypted.EncryptionKeyID()) {
				result.Status = "partial"
				result.UncheckedPlugins = append(result.UncheckedPlugins, UncheckedPolicyPlugin{PolicyValidationReference: entry.PolicyValidationReference, Rule: rule.Name})
				continue
			}
			opened, err := s.keyConfigs.acquireSource(rule.Encrypted.CanonicalJSON(), organizationID, key)
			if err != nil {
				return nil, err
			}
			sources = append(sources, opened)
			if opened.plan != nil {
				if _, err := opened.plan.get(); err != nil {
					return nil, err
				}
			}
		}
	}
	if _, err := policy.ComposeSources(values); err != nil {
		return nil, err
	}
	if _, err := redaction.CombinePolicies(plans); err != nil {
		return nil, err
	}
	return result, nil
}
