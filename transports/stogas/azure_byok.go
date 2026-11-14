package stogas

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	azureByokSchema        = "stogas.azure-byok.v6"
	azureDeploymentNameMax = 256
	azureDataScope         = "https://ai.azure.com/.default"
)

var (
	azureProjectPathPattern = regexp.MustCompile(`^/api/projects/[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$`)
	azureUUIDPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type azureByokCredential struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Schema       string `json:"schema"`
	TenantID     string `json:"tenantId"`
}

// CredentialDeploymentFilter narrows catalog candidates using cached public
// target metadata. It never decrypts secrets or contacts the provider. The hold
// still checks the selected credential and chooses its live binding atomically.
func CredentialDeploymentFilter(snapshot *billing.KeyConfigSnapshot, now time.Time) func(schemas.ModelProvider, int, catalog.Route, catalog.Deployment) bool {
	selections := snapshot.Credentials["azure"]
	lookups := make([]func(billing.UpstreamTarget) []*billing.AzureCredentialBinding, len(selections))
	for index, selection := range selections {
		if selection.Credential != nil {
			lookups[index] = selection.Credential.AzureBindingLookup()
		}
	}
	cloudTargets := make(map[schemas.ModelProvider][]*billing.CloudTarget, 2)
	for _, provider := range []schemas.ModelProvider{catalog.ProviderAWS, catalog.ProviderGoogleCloud} {
		for _, selection := range snapshot.Credentials[string(provider)] {
			var target *billing.CloudTarget
			if selection.Credential != nil {
				target = selection.Credential.Target
			}
			cloudTargets[provider] = append(cloudTargets[provider], target)
		}
	}
	return func(provider schemas.ModelProvider, index int, _ catalog.Route, deployment catalog.Deployment) bool {
		if targets, cloud := cloudTargets[provider]; cloud || provider == catalog.ProviderAWS || provider == catalog.ProviderGoogleCloud {
			return index >= 0 && index < len(targets) && cloudTargetServes(provider, targets[index], deployment)
		}
		if provider != schemas.Azure {
			return true
		}
		if index < 0 || index >= len(lookups) || lookups[index] == nil {
			return false
		}
		for _, item := range lookups[index](credentialTarget(deployment)) {
			if azureRetired(item.ModelDeprecationAt, now) {
				continue
			}
			if validAzureBinding(servingBinding(item.AzureBinding, deployment), deployment) {
				return true
			}
		}
		return false
	}
}

// credentialTarget names a catalog deployment by the fields that select an Azure credential's
// deployments for it.
func credentialTarget(deployment catalog.Deployment) billing.UpstreamTarget {
	upstream := deployment.Upstream
	return billing.UpstreamTarget{
		ModelFormat: upstream.ModelFormat, Model: upstream.Model, ModelVersion: upstream.ModelVersion,
		Hosting: deployment.Hosting, DeploymentType: upstream.DeploymentType,
	}
}

// BindAccount gives a pair the tag of the provider account that its credential reaches
// (billing.KeyConfigSnapshot.AccountTag), which binds the encrypted reasoning that the pair returns
// and takes back. An Azure pair reaches the deployment that the cached credential selects for it,
// of which the database allows one, until its hold chooses the live one (BindHeldAccount).
func BindAccount(snapshot *billing.KeyConfigSnapshot, resolution *catalog.ResolvedRequest) {
	provider, index, endpoint := string(resolution.Provider), resolution.CredentialIndex, ""
	if provider == "azure" && snapshot.UsesBYOK(provider, index) {
		if credential := snapshot.Credentials[provider][index].Credential; credential != nil {
			// The cache holds the one deployment that the owner selected for the target, which the
			// hold also takes, so the body names it before the hold. An invalid name fails there.
			if bindings := credential.AzureBindingLookup()(credentialTarget(resolution.Deployment)); len(bindings) > 0 {
				endpoint = bindings[0].Endpoint
				_ = resolution.SetWireModel(bindings[0].DeploymentName)
			}
		}
	}
	resolution.SetAccountTag(snapshot.AccountTag(provider, index, endpoint))
}

// BindHeldAccount binds an Azure pair to the deployment that its hold chose and reports whether
// that changed the body. After its owner selects another deployment, the cache can name the
// previous one for up to the cache's lifetime; a deployment in another resource also leaves out the
// encrypted reasoning that the pair kept for the previous one.
func BindHeldAccount(snapshot *billing.KeyConfigSnapshot, state *State, wireModel string) bool {
	if state.Authorization == nil || state.Authorization.AzureBinding == nil {
		return false
	}
	resolution := state.Resolution
	rebound := resolution.RebindAccount(snapshot.AccountTag(string(resolution.Provider), resolution.CredentialIndex, state.Authorization.AzureBinding.Endpoint))
	return rebound || resolution.Model != wireModel
}

// ValidatePreparedCredential checks the selected secret before input work. An
// AWS or Google Cloud secret must serve its registered target and the deployment.
func ValidatePreparedCredential(credential *billing.PreparedCredential, provider schemas.ModelProvider, deployment catalog.Deployment) error {
	if credential == nil {
		return billing.ErrByok
	}
	switch provider {
	case schemas.Azure:
		if _, err := parseAzureByokCredential(credential.Secret); err != nil {
			return billing.ErrByok
		}
	case catalog.ProviderAWS, catalog.ProviderGoogleCloud:
		return validateCloudCredential(provider, credential.Secret, credential.Target(), deployment)
	}
	return nil
}

// azureRetired says whether the model version that Azure retires on a date has retired at now:
// once that date has ended everywhere on Earth, at 12:00 UTC on the next day, as the catalog reads
// its own retirement dates. Azure names a date, which can begin or end in any time zone, and a
// deployment that Azure stops earlier answers with a retirement that moves the request on.
// PostgreSQL's azure_target_serves is the same rule.
func azureRetired(retiresAt *time.Time, now time.Time) bool {
	if retiresAt == nil {
		return false
	}
	day := retiresAt.UTC()
	return !now.Before(time.Date(day.Year(), day.Month(), day.Day(), 36, 0, 0, 0, time.UTC))
}

func azureDirectKey(authorization *billing.Authorization, resolution *catalog.ResolvedRequest) (schemas.Key, string, error) {
	if authorization == nil || resolution == nil || resolution.Provider != schemas.Azure || authorization.AzureBinding == nil {
		return schemas.Key{}, "", billing.ErrByok
	}
	credential, err := parseAzureByokCredential(authorization.UpstreamByokSecret)
	if err != nil {
		return schemas.Key{}, "", billing.ErrByok
	}
	binding := servingBinding(*authorization.AzureBinding, resolution.Deployment)
	if !validAzureBinding(binding, resolution.Deployment) {
		return schemas.Key{}, "", billing.ErrByok
	}
	return schemas.Key{
		ID:     authorization.UpstreamByok,
		Name:   authorization.UpstreamByok,
		Value:  literalSecret(""),
		Models: schemas.WhiteList{binding.DeploymentName},
		AzureKeyConfig: &schemas.AzureKeyConfig{
			ClientID:     schemas.Ptr(literalSecret(credential.ClientID)),
			ClientSecret: schemas.Ptr(literalSecret(credential.ClientSecret)),
			Endpoint:     literalSecret(binding.Endpoint),
			Scopes:       []string{binding.TokenScope},
			TenantID:     schemas.Ptr(literalSecret(credential.TenantID)),
		},
		Weight:  1,
		Enabled: schemas.Ptr(true),
	}, binding.DeploymentName, nil
}

func parseAzureByokCredential(raw string) (azureByokCredential, error) {
	credential := azureByokCredential{}
	if err := decodeStrictJSON(raw, &credential); err != nil {
		return azureByokCredential{}, err
	}
	credential.ClientID = strings.ToLower(strings.TrimSpace(credential.ClientID))
	credential.TenantID = strings.ToLower(strings.TrimSpace(credential.TenantID))
	if credential.Schema != azureByokSchema ||
		!azureUUIDPattern.MatchString(credential.ClientID) ||
		!azureUUIDPattern.MatchString(credential.TenantID) ||
		!validUpstreamAPIKey(credential.ClientSecret) {
		return azureByokCredential{}, errors.New("invalid Azure BYOK")
	}
	return credential, nil
}

// servingBinding is a binding as it serves a deployment. A catalog no-storage guarantee makes
// the account's placement inapplicable, so the binding stores nothing either.
func servingBinding(binding billing.AzureBinding, deployment catalog.Deployment) billing.AzureBinding {
	if deployment.DataHandling.StorageLocation == "none" {
		binding.StorageLocation = "none"
	}
	return binding
}

func validAzureBinding(binding billing.AzureBinding, deployment catalog.Deployment) bool {
	upstream, dataHandling, places := deployment.Upstream, deployment.DataHandling, deployment.Locations
	if binding.TokenScope != azureDataScope ||
		!validAzureDeploymentName(binding.DeploymentName) ||
		!places.Valid(binding.ProcessingLocation, false) ||
		!places.Valid(binding.StorageLocation, true) ||
		!places.Within(binding.ProcessingLocation, dataHandling.ProcessingLocation) ||
		!places.Within(binding.StorageLocation, dataHandling.StorageLocation) ||
		binding.DeploymentType != upstream.DeploymentType ||
		binding.Hosting != deployment.Hosting ||
		binding.ModelFormat != upstream.ModelFormat ||
		binding.ModelName != upstream.Model ||
		binding.ModelVersion != upstream.ModelVersion {
		return false
	}
	parsed, err := url.Parse(binding.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if !trustedAzureInferenceHost(host) {
		return false
	}
	isProjectEndpoint := azureProjectPathPattern.MatchString(parsed.Path)
	if binding.DeploymentType == "instant" {
		return isProjectEndpoint && strings.HasSuffix(host, ".services.ai.azure.com")
	}
	return parsed.Path == "" || parsed.Path == "/"
}

func trustedAzureInferenceHost(host string) bool {
	for _, suffix := range []string{".openai.azure.com", ".services.ai.azure.com"} {
		if strings.HasSuffix(host, suffix) {
			name := strings.TrimSuffix(host, suffix)
			return name != "" && !strings.Contains(name, ".")
		}
	}
	return false
}

func validAzureDeploymentName(value string) bool {
	if len(value) == 0 || len(value) > azureDeploymentNameMax {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validUpstreamAPIKey(value string) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
