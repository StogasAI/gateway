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
func CredentialDeploymentFilter(snapshot *billing.KeyConfigSnapshot, now time.Time) func(schemas.ModelProvider, int, catalog.Deployment) bool {
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
	return func(provider schemas.ModelProvider, index int, deployment catalog.Deployment) bool {
		if targets, cloud := cloudTargets[provider]; cloud || provider == catalog.ProviderAWS || provider == catalog.ProviderGoogleCloud {
			return index >= 0 && index < len(targets) && cloudTargetServes(provider, targets[index], deployment)
		}
		if provider != schemas.Azure {
			return true
		}
		if index < 0 || index >= len(lookups) || lookups[index] == nil {
			return false
		}
		for _, item := range lookups[index](billing.UpstreamTarget{
			ModelFormat:    deployment.Upstream.ModelFormat,
			Model:          deployment.Upstream.Model,
			ModelVersion:   deployment.Upstream.ModelVersion,
			Hosting:        deployment.Upstream.Hosting,
			DeploymentType: deployment.Upstream.DeploymentType,
		}) {
			if item.ModelDeprecationAt != nil && !now.Before(*item.ModelDeprecationAt) {
				continue
			}
			if validAzureBinding(servingBinding(item.AzureBinding, deployment), deployment) {
				return true
			}
		}
		return false
	}
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
		binding.Hosting != upstream.Hosting ||
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
