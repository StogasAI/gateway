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
	// The longest served model that a stopped target records.
	azureServedModelMax = 255
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
	return func(provider schemas.ModelProvider, index int, route catalog.Route, deployment catalog.Deployment) bool {
		if targets, cloud := cloudTargets[provider]; cloud || provider == catalog.ProviderAWS || provider == catalog.ProviderGoogleCloud {
			return index >= 0 && index < len(targets) && cloudTargetServes(provider, targets[index], deployment)
		}
		if provider != schemas.Azure {
			return true
		}
		if index < 0 || index >= len(lookups) || lookups[index] == nil {
			return false
		}
		unreported := !azureRepliesNameVersion(route, deployment)
		for _, item := range lookups[index](billing.UpstreamTarget{
			ModelFormat:    deployment.Upstream.ModelFormat,
			Model:          deployment.Upstream.Model,
			ModelVersion:   deployment.Upstream.ModelVersion,
			Hosting:        deployment.Upstream.Hosting,
			DeploymentType: deployment.Upstream.DeploymentType,
		}) {
			if item.ModelDeprecationAt != nil && !now.Before(*item.ModelDeprecationAt) ||
				unreported && !azureKeepsVersion(item.AzureBinding, now) {
				continue
			}
			if validAzureBinding(servingBinding(item.AzureBinding, deployment), deployment) {
				return true
			}
		}
		return false
	}
}

// CredentialTargetChanged reports whether an Azure credential's chosen deployment for a catalog
// deployment now serves another model, version or SKU. A request that only such targets could
// serve then gets byok_target_changed, which tells the owner to choose the new target.
func CredentialTargetChanged(snapshot *billing.KeyConfigSnapshot) func(schemas.ModelProvider, int, catalog.Deployment) bool {
	selections := snapshot.Credentials["azure"]
	return func(provider schemas.ModelProvider, index int, deployment catalog.Deployment) bool {
		if provider != schemas.Azure || index < 0 || index >= len(selections) || selections[index].Credential == nil {
			return false
		}
		upstream := deployment.Upstream
		return selections[index].Credential.AzureTargetChanged(billing.UpstreamTarget{
			ModelFormat: upstream.ModelFormat, Model: upstream.Model, ModelVersion: upstream.ModelVersion,
			Hosting: upstream.Hosting, DeploymentType: upstream.DeploymentType,
		})
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

// azureRepliesNameVersion reports whether Azure's reply to a request names the model version
// that served it. Azure sends x-ms-served-model, the deployment's model name and version, on
// Responses for every model format and on Chat Completions for OpenAI models, and the Chat
// Completions body names the OpenAI model too. Chat Completions for other formats name only the
// deployment. Replies through Anthropic's Messages API were not probed: deploying Claude needs
// the account's legal attestation and a Marketplace order (probed 2026-11-03).
func azureRepliesNameVersion(route catalog.Route, deployment catalog.Deployment) bool {
	switch format := deployment.Upstream.ModelFormat; {
	case format == "Anthropic":
		return false
	case route == catalog.RouteResponses:
		return true
	default:
		return route == catalog.RouteChat && format == "OpenAI"
	}
}

// azureKeepsVersion reports whether Azure keeps a target's model version at now, so that a
// request whose reply names no version may use it. Azure moves a deployment within two weeks of
// another version becoming the default, without notice, unless its upgrade option waits for the
// version to retire or never upgrades. It moves those when the version retires, region by region
// from the retirement date, and it can move a preview version whatever the option, so the target
// stops when that date begins anywhere.
func azureKeepsVersion(binding billing.AzureBinding, now time.Time) bool {
	if binding.AutoUpgrade != "none" && binding.AutoUpgrade != "at_retirement" {
		return false
	}
	return binding.ModelDeprecationAt == nil || now.Before(azureRetirementBegins(*binding.ModelDeprecationAt))
}

// azureRetirementBegins is when a retirement date begins in UTC+14, the first time zone to reach
// it: 10:00 UTC the day before.
func azureRetirementBegins(retiresAt time.Time) time.Time {
	day := retiresAt.UTC()
	return time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC).Add(-14 * time.Hour)
}

// AzureServedModelChanged reports the model that an Azure reply named, served, when it is another
// model or version than the reply's target. Azure names the deployment's model name and version
// joined by a hyphen. A reply that names nothing, or only the model, is no evidence. The result
// keeps only characters that a model name uses.
func AzureServedModelChanged(authorization *billing.Authorization, served string) (string, bool) {
	if authorization == nil || authorization.AzureBinding == nil {
		return "", false
	}
	binding := authorization.AzureBinding
	served = strings.TrimSpace(served)
	if served == "" || strings.EqualFold(served, binding.ModelName) ||
		strings.EqualFold(served, binding.ModelName+"-"+binding.ModelVersion) {
		return "", false
	}
	if len(served) > azureServedModelMax {
		served = served[:azureServedModelMax]
	}
	clean := []byte(served)
	for index, char := range clean {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' ||
			index > 0 && (char == '.' || char == '_' || char == ':' || char == '-')) {
			clean[index] = '_'
		}
	}
	if clean[0] == '_' {
		clean[0] = 'x'
	}
	return string(clean), true
}

func azureDirectKey(authorization *billing.Authorization, resolution *catalog.ResolvedRequest, now time.Time) (schemas.Key, string, error) {
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
	// The hold chose the target for this; the gateway's clock confirms it.
	if !azureRepliesNameVersion(resolution.WireRoute(), resolution.Deployment) && !azureKeepsVersion(binding, now) {
		return schemas.Key{}, "", billing.ErrByokTarget
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
