package billing

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// CachedCredential contains only ciphertext and routing metadata. Requests
// decrypt their selected secret once before input transformation and admission.
type CachedCredential struct {
	ID              string                   `json:"id"`
	OrganizationID  string                   `json:"organizationId"`
	Provider        string                   `json:"provider"`
	Kind            string                   `json:"kind"`
	Enabled         bool                     `json:"enabled"`
	EncryptedSecret string                   `json:"encryptedSecret"`
	EncryptionKeyID string                   `json:"encryptionKeyId"`
	Bindings        []AzureCredentialBinding `json:"bindings"`
	Policy          credentialPolicyRecord   `json:"policy"`
	policySource    *sharedCredentialPolicy
	azureBindings   map[azureBindingKey][]*AzureCredentialBinding
}

// AzureCredentialBinding is decoded once with the immutable credential
// snapshot. Routing reads it without reparsing every target on each request.
type AzureCredentialBinding struct {
	AzureBinding
	ModelDeprecationAt *time.Time `json:"modelDeprecationAt"`
}

// Geography, expiry and endpoint safety are checked against each candidate.
// Request controls such as service tier do not change the physical target.
type azureBindingKey struct {
	modelFormat, model, modelVersion, hosting, deploymentType string
}

func indexAzureBindings(bindings []AzureCredentialBinding) map[azureBindingKey][]*AzureCredentialBinding {
	if len(bindings) == 0 {
		return nil
	}
	index := make(map[azureBindingKey][]*AzureCredentialBinding)
	for i := range bindings {
		binding := &bindings[i]
		key := azureBindingKey{binding.ModelFormat, binding.ModelName, binding.ModelVersion, binding.Hosting, binding.DeploymentType}
		index[key] = append(index[key], binding)
	}
	return index
}

// AzureBindingLookup reuses the immutable credential's index across API keys
// and requests. Uncached snapshots build it once for the caller's selection pass.
func (c *CachedCredential) AzureBindingLookup() func(UpstreamTarget) []*AzureCredentialBinding {
	index := c.azureBindings
	if index == nil {
		index = indexAzureBindings(c.Bindings)
	}
	return func(target UpstreamTarget) []*AzureCredentialBinding {
		return index[azureBindingKey{target.ModelFormat, target.Model, target.ModelVersion, target.Hosting, target.DeploymentType}]
	}
}

type credentialPolicyRecord struct {
	SourceIndex *int `json:"sourceIndex,omitempty"`
	policySourceRecord
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expiresAt"`
}

type CredentialSelection struct {
	Mode       string            `json:"mode"`
	ID         string            `json:"byokId"`
	Credential *CachedCredential `json:"credential,omitempty"`
}

// PreparedCredential belongs to one request, never the shared configuration
// cache. Admission verifies its exact snapshot and selected credential again.
type PreparedCredential struct {
	snapshot  *KeyConfigSnapshot
	selection CredentialSelection
	provider  string
	index     int
	Secret    string
}

// UsesBYOK requires a prepared customer-owned credential. Provider file IDs
// must never resolve through a shared managed credential.
func (p *PreparedCredential) UsesBYOK() bool {
	return p != nil && (p.selection.Mode == "stored" || p.selection.Mode == "encrypted")
}

func (p *PreparedCredential) Clear() {
	if p != nil {
		p.Secret = ""
		p.snapshot = nil
		p.selection = CredentialSelection{}
	}
}

// PrepareCredential does local work only. The hold still checks live ownership,
// selection, revocation, policy revisions, and Azure target availability.
func (s *Service) PrepareCredential(snapshot *KeyConfigSnapshot, provider string, index int, key customerkey.Keys) (*PreparedCredential, error) {
	if s == nil || snapshot == nil || snapshot.Claims == nil || snapshot.Config == nil {
		return nil, ErrGatewayUnavailable
	}
	selection, err := snapshot.credentialSelection(provider, index, key)
	if err != nil {
		return nil, err
	}
	prepared := &PreparedCredential{snapshot: snapshot, selection: selection, provider: provider, index: index}
	switch selection.Mode {
	case "managed":
		if provider != "chutes" {
			return nil, ErrByokRequired
		}
		return prepared, nil
	case "stored", "encrypted":
		credential := selection.Credential
		if credential == nil || credential.ID != selection.ID || credential.OrganizationID != snapshot.Claims.OrganizationID || credential.Provider != provider {
			return nil, ErrByok
		}
		if !credential.Enabled {
			return nil, policyResultErrors["credential_disabled"]
		}
		if selection.Mode == "stored" {
			prepared.Secret, err = s.byok.decrypt(credential.EncryptedSecret, credential.ID, credential.OrganizationID, provider)
			if err != nil {
				return nil, ErrByok
			}
		} else {
			var envelope customerkey.Envelope
			if json.Unmarshal([]byte(credential.EncryptedSecret), &envelope) != nil {
				return nil, customerkey.ErrEnvelope
			}
			plaintext, openErr := key.Open(envelope, credential.OrganizationID, "byok/"+provider, 4096)
			if openErr != nil {
				return nil, openErr
			}
			prepared.Secret = string(plaintext)
			clear(plaintext)
		}
		if provider != "azure" {
			valid := len(prepared.Secret) > 0
			for _, character := range prepared.Secret {
				if character < 0x21 || character > 0x7e {
					valid = false
					break
				}
			}
			if !valid {
				prepared.Clear()
				if selection.Mode == "encrypted" {
					return nil, customerkey.ErrEnvelope
				}
				return nil, ErrByok
			}
		}
		return prepared, nil
	default:
		return nil, ErrByok
	}
}

type sharedCredential struct {
	value  *CachedCredential
	digest [32]byte
	bytes  int64
	refs   int
	policy *sharedCredentialPolicy
}

// A credential's identity, status and secret differ even when its policy is
// identical. Retain and parse that source once across those credentials.
type sharedCredentialPolicy struct {
	raw      json.RawMessage
	digest   [32]byte
	bytes    int64
	refs     int
	once     sync.Once
	document *policy.SourceDocument
	err      error
}

func (s *sharedCredentialPolicy) parse() (*policy.SourceDocument, error) {
	s.once.Do(func() {
		raw := s.raw
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			raw = []byte(`{}`)
		}
		s.document, s.err = policy.ParseSourceDocument(raw)
	})
	return s.document, s.err
}

// AvailableCredentials excludes encrypted credentials whose registered root is
// absent. Invalid supplied roots or selected ciphertext are terminal failures,
// even when the policy permits another candidate.
func (s *KeyConfigSnapshot) AvailableCredentials(keys customerkey.Keys) map[string][]int {
	available := make(map[string][]int)
	if s == nil || s.Claims == nil || s.Config == nil {
		return available
	}
	for provider, selections := range s.Credentials {
		for index := range selections {
			if _, err := s.credentialSelection(provider, index, keys); err == nil {
				available[provider] = append(available[provider], index)
			}
		}
	}
	return available
}

func (s *KeyConfigSnapshot) credentialSelection(provider string, index int, keys customerkey.Keys) (CredentialSelection, error) {
	selections := s.Credentials[provider]
	if index < 0 || index >= len(selections) {
		return CredentialSelection{}, ErrByokRequired
	}
	selection := selections[index]
	if selection.Mode == "encrypted" {
		if selection.ID == "" || selection.Credential == nil || selection.Credential.ID != selection.ID || s.Config == nil ||
			keys.Validate(s.Config.EncryptionKeys) != nil || !customerkey.Registered(s.Config.EncryptionKeys, selection.Credential.EncryptionKeyID) || !keys.Matches(selection.Credential.EncryptionKeyID) {
			return CredentialSelection{}, customerkey.ErrKey
		}
	}
	return selection, nil
}

func validateCredentials(claims *APIKeyClaims, credentials map[string][]CredentialSelection) error {
	if claims == nil || len(credentials) > 4 {
		return errors.New("invalid credential snapshot")
	}
	for provider, selections := range credentials {
		if provider != "anthropic" && provider != "azure" && provider != "chutes" && provider != "openai" {
			return errors.New("invalid credential provider")
		}
		if len(selections) > 1001 {
			return errors.New("invalid credential selection count")
		}
		seen := make(map[string]bool, len(selections))
		for _, selection := range selections {
			if seen[selection.ID] {
				return errors.New("duplicate credential selection")
			}
			seen[selection.ID] = true
			switch selection.Mode {
			case "managed":
				if selection.ID != "" || selection.Credential != nil || provider != "chutes" {
					return errors.New("invalid unassigned credential")
				}
			case "stored", "encrypted":
				if selection.ID == "" {
					return errors.New("missing selected credential")
				}
				credential := selection.Credential
				id, err := uuid.Parse(selection.ID)
				if err != nil || id.Version() != 7 || id.String() != selection.ID || credential == nil || credential.ID != selection.ID ||
					credential.OrganizationID != claims.OrganizationID ||
					credential.Provider != provider || credential.Kind != selection.Mode {
					return errors.New("credential scope differs")
				}
				if credential.Kind == "stored" && (credential.EncryptedSecret == "" || credential.EncryptionKeyID != "") ||
					credential.Kind == "encrypted" && (provider == "azure" || credential.EncryptedSecret == "" || !validConfigDigest(credential.EncryptionKeyID)) {
					return errors.New("invalid credential material")
				}
				if credential.Policy.Scope != policy.CredentialScope || credential.Policy.ID != credential.ID || credential.Policy.Revision < 1 || len(credential.Policy.Source) == 0 {
					return errors.New("invalid credential policy")
				}
			default:
				return errors.New("invalid credential selection")
			}
		}
	}
	return nil
}

func restoreCredentialPolicySources(credentials map[string][]CredentialSelection, pins policySourcePins, sources []json.RawMessage) error {
	if len(sources) > 1000 {
		return ErrGatewayUnavailable
	}
	for _, selections := range credentials {
		for _, selection := range selections {
			if selection.Credential == nil {
				continue
			}
			record := &selection.Credential.Policy
			if index := record.SourceIndex; index != nil {
				if len(record.Source) != 0 || *index < 0 || *index >= len(sources) || len(sources[*index]) == 0 {
					return ErrGatewayUnavailable
				}
				record.Source, record.SourceIndex = sources[*index], nil
			}
			if len(record.Source) != 0 {
				continue
			}
			source := pins.byID[record.identity()]
			if source == nil || pins.known[record.identity()] != record.Revision || len(source.raw) == 0 {
				return ErrGatewayUnavailable
			}
			record.Source = source.raw
		}
	}
	return nil
}

// PolicyForCredential composes readable settings for one credential candidate.
// Encrypted dictionaries open only during selected-request transformation.
// The key cache owns successful combinations; failures are never cached.
func (s *KeyConfigSnapshot) PolicyForCredential(provider string, index int, key customerkey.Keys, now time.Time, budget *policy.SourceBudget) (*PolicySnapshot, error) {
	if s == nil || s.Config == nil {
		return nil, ErrGatewayUnavailable
	}
	if err := budget.AddConfig(s.Config); err != nil {
		return nil, err
	}
	selection, err := s.credentialSelection(provider, index, key)
	if err != nil {
		return nil, err
	}
	if selection.ID == "" {
		return &s.PolicySnapshot, s.checkEncryptionKeys(key)
	}
	if selection.Credential == nil {
		return nil, ErrByok
	}
	record := selection.Credential.Policy
	if record.ExpiresAt != nil && !now.Before(*record.ExpiresAt) {
		return nil, policyResultErrors["credential_expired"]
	}
	if !record.Enabled {
		return nil, policyResultErrors["credential_disabled"]
	}
	c := s.owner
	if c == nil || s.Claims == nil || s.Versions == nil || len(s.sourceRefs) != len(*s.Versions) {
		return nil, ErrGatewayUnavailable
	}
	c.mu.Lock()
	compiled := s.credentialPolicies[selection.ID]
	c.mu.Unlock()
	if compiled != nil {
		if err := budget.AddConfig(compiled.Config); err != nil {
			return nil, err
		}
		return compiled, compiled.checkEncryptionKeys(key)
	}
	stored := selection.Credential.policySource
	if stored == nil {
		return nil, ErrGatewayUnavailable
	}
	document, err := stored.parse()
	if err != nil {
		return nil, err
	}
	if err := budget.AddDocument(document); err != nil {
		return nil, err
	}
	source, err := c.acquireSourceDocument(document, record.Source, s.Claims.OrganizationID, key, true)
	if err != nil {
		return nil, err
	}
	defer c.releaseSources([]*sharedPolicySource{source})
	versions := make(PolicyVersions, 0, len(*s.Versions)+1)
	refs := make([]*sharedPolicySource, 0, len(s.sourceRefs)+1)
	for i, version := range *s.Versions {
		if version.Scope == policy.KeyScope {
			versions = append(versions, record.PolicyVersion)
			refs = append(refs, source)
		}
		versions = append(versions, version)
		refs = append(refs, s.sourceRefs[i])
	}
	values := make([]policy.ScopedSource, len(versions))
	for i, version := range versions {
		values[i] = policy.ScopedSource{Scope: version.Scope, Value: refs[i].value}
	}
	digest := policy.ChainDigest(values)
	config, err := c.composeSources(values, digest)
	if err != nil {
		return nil, err
	}
	if err := budget.AddConfig(config); err != nil {
		return nil, err
	}
	compiled = &PolicySnapshot{Versions: &versions, Config: config, Digest: digest, sourceRefs: refs, cacheBytes: config.CompositionBytes()}
	c.mu.Lock()
	defer c.mu.Unlock()
	if previous := s.credentialPolicies[selection.ID]; previous != nil {
		return previous, previous.checkEncryptionKeys(key)
	}
	s.credentialPolicies[selection.ID] = compiled
	if s.retained {
		c.retainPolicyLocked(compiled)
		c.indexSourcesLocked(s.Claims, compiled)
		c.trimLocked()
	} else {
		// A request may finish preparation after its key was evicted. Retain
		// ordinary Go references without repopulating the bounded cache.
		compiled.shared = &sharedKeyPolicy{config: config, digest: digest, redactionID: redactionSourcesDigest(config)}
		seen := map[*sharedRedactionPlan]bool{}
		for _, ref := range refs {
			if ref.plan != nil && !seen[ref.plan] {
				compiled.matchers = append(compiled.matchers, ref.plan)
				seen[ref.plan] = true
			}
		}
	}
	return compiled, compiled.checkEncryptionKeys(key)
}

func credentialContent(value *CachedCredential, source *sharedCredentialPolicy) ([32]byte, int64, error) {
	metadata := *value
	metadata.Policy.Source = nil
	encoded, err := json.Marshal(metadata)
	hash := sha256.New()
	hash.Write(encoded)
	hash.Write(source.digest[:])
	var digest [32]byte
	hash.Sum(digest[:0])
	return digest, int64(len(encoded))*3 + 512, err
}
