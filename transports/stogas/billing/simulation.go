package billing

import (
	"context"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// SimulationConfig reads a key's saved settings for a routing simulation. A
// dashboard user may simulate a key that they can see but not use. A draft
// replaces the key's policy with the same scope and ID; the result reports
// whether the key has one. The cache does not keep the snapshot, and nothing
// opens its encrypted content.
func (s *Service) SimulationConfig(ctx context.Context, credential *DashboardCredential, draft *PolicyValidationSource) (*KeyConfigSnapshot, bool, error) {
	if s == nil || s.db == nil || s.keyConfigQuery == "" || credential == nil {
		return nil, false, ErrGatewayUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, keyConfigFetchTimeout)
	defer cancel()
	row := keyConfigRow{}
	if err := s.queryForTool(ctx, s.keyConfigQuery,
		[]any{nil, credential.KeyID, credential.ActorUserID, credential.SessionID, nil, "view"},
		&row.Result, &row.KeyID, &row.Sources, &row.Claims, &row.CredentialsGeneration, &row.Credentials, &row.CredentialSources,
	); err != nil {
		return nil, false, err
	}
	if err := authorizationResultError(row.Result); err != nil {
		return nil, false, err
	}
	if row.Result != "ok" || row.KeyID == nil || *row.KeyID != credential.KeyID || row.Claims == nil {
		return nil, false, ErrGatewayUnavailable
	}
	applied := draft != nil && row.replacePolicy(*draft)
	snapshot, err := s.composeKeyConfig(row, policySourcePins{}, nil)
	if err != nil {
		return nil, applied, err
	}
	// The snapshot keeps ordinary references to the sources it composed.
	s.keyConfigs.releaseSources(snapshot.sourceRefs)
	snapshot.owner, snapshot.credentialPolicies = &s.keyConfigs, make(map[string]*PolicySnapshot)
	sources := make(map[string]*sharedCredentialPolicy)
	for _, selections := range snapshot.Credentials {
		for _, selection := range selections {
			if credential := selection.Credential; credential != nil {
				raw := credential.Policy.Source
				if sources[string(raw)] == nil {
					sources[string(raw)] = &sharedCredentialPolicy{raw: raw}
				}
				credential.policySource = sources[string(raw)]
			}
		}
	}
	return snapshot, applied, nil
}

// replacePolicy puts a draft in place of the saved policy with its scope and
// ID. A credential's policy applies wherever the key uses the credential.
func (row *keyConfigRow) replacePolicy(draft PolicyValidationSource) bool {
	if draft.Scope == policy.CredentialScope {
		replaced := false
		for _, selections := range row.Credentials {
			for _, selection := range selections {
				if selection.Credential != nil && selection.Credential.ID == draft.ID {
					selection.Credential.Policy.Source, selection.Credential.Policy.SourceIndex = draft.Config, nil
					replaced = true
				}
			}
		}
		return replaced
	}
	for i := range row.Sources {
		if row.Sources[i].Scope == draft.Scope && row.Sources[i].ID == draft.ID {
			row.Sources[i].Source = draft.Config
			return true
		}
	}
	return false
}

// SimulatedPolicyForCredential composes the settings of a credential candidate
// as a request that supplies every registered encryption key would.
func (s *KeyConfigSnapshot) SimulatedPolicyForCredential(provider string, index int, now time.Time, budget *policy.SourceBudget) (*PolicySnapshot, error) {
	if s == nil || s.Config == nil {
		return nil, ErrGatewayUnavailable
	}
	if err := budget.AddConfig(s.Config); err != nil {
		return nil, err
	}
	selections := s.Credentials[provider]
	if index < 0 || index >= len(selections) {
		return nil, ErrByokRequired
	}
	selection := selections[index]
	if selection.Mode == "encrypted" && (selection.Credential == nil || !customerkey.Registered(s.Config.EncryptionKeys, selection.Credential.EncryptionKeyID)) {
		return nil, ErrByokKeyUnregistered
	}
	return s.selectionPolicy(selection, now, budget)
}
