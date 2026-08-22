package stogas

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	azureByokSchema        = "stogas.azure-byok.v5"
	azureDeploymentNameMax = 256
	azureDataScope         = "https://ai.azure.com/.default"
)

var (
	azureProjectPathPattern = regexp.MustCompile(`^/api/projects/[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$`)
	azureUUIDPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type azureByokCredential struct {
	ClientID        string   `json:"clientId"`
	ClientSecret    string   `json:"clientSecret"`
	Schema          string   `json:"schema"`
	SubscriptionIDs []string `json:"subscriptionIds"`
	TenantID        string   `json:"tenantId"`
}

func azureDirectKey(authorization *billing.Authorization, resolution *catalog.ResolvedRequest) (schemas.Key, string, error) {
	if authorization == nil || resolution == nil || resolution.Provider != schemas.Azure || authorization.AzureBinding == nil {
		return schemas.Key{}, "", billing.ErrByok
	}
	credential, err := parseAzureByokCredential(authorization.UpstreamByokSecret)
	if err != nil {
		return schemas.Key{}, "", billing.ErrByok
	}
	binding := authorization.AzureBinding
	if !validAzureBinding(
		*binding,
		resolution.Deployment.Upstream,
		resolution.Deployment.DataHandling,
	) {
		return schemas.Key{}, "", billing.ErrByok
	}
	return schemas.Key{
		ID:     authorization.UpstreamByok,
		Name:   authorization.UpstreamByok,
		Value:  *schemas.NewSecretVar(""),
		Models: schemas.WhiteList{binding.DeploymentName},
		AzureKeyConfig: &schemas.AzureKeyConfig{
			ClientID:     schemas.NewSecretVar(credential.ClientID),
			ClientSecret: schemas.NewSecretVar(credential.ClientSecret),
			Endpoint:     *schemas.NewSecretVar(binding.Endpoint),
			Scopes:       []string{binding.TokenScope},
			TenantID:     schemas.NewSecretVar(credential.TenantID),
		},
		Weight:  1,
		Enabled: schemas.Ptr(true),
	}, binding.DeploymentName, nil
}

func parseAzureByokCredential(raw string) (azureByokCredential, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	credential := azureByokCredential{}
	if err := decoder.Decode(&credential); err != nil {
		return azureByokCredential{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return azureByokCredential{}, errors.New("invalid Azure BYOK: trailing JSON")
	}
	credential.ClientID = strings.ToLower(strings.TrimSpace(credential.ClientID))
	credential.TenantID = strings.ToLower(strings.TrimSpace(credential.TenantID))
	if credential.Schema != azureByokSchema ||
		!azureUUIDPattern.MatchString(credential.ClientID) ||
		!azureUUIDPattern.MatchString(credential.TenantID) ||
		!validUpstreamAPIKey(credential.ClientSecret) ||
		len(credential.SubscriptionIDs) < 1 || len(credential.SubscriptionIDs) > 64 {
		return azureByokCredential{}, errors.New("invalid Azure BYOK")
	}
	seen := make(map[string]struct{}, len(credential.SubscriptionIDs))
	previous := ""
	for index, subscriptionID := range credential.SubscriptionIDs {
		subscriptionID = strings.ToLower(strings.TrimSpace(subscriptionID))
		if !azureUUIDPattern.MatchString(subscriptionID) || subscriptionID <= previous {
			return azureByokCredential{}, errors.New("invalid Azure BYOK")
		}
		if _, exists := seen[subscriptionID]; exists {
			return azureByokCredential{}, errors.New("invalid Azure BYOK")
		}
		seen[subscriptionID] = struct{}{}
		credential.SubscriptionIDs[index] = subscriptionID
		previous = subscriptionID
	}
	return credential, nil
}

func validAzureBinding(
	binding billing.AzureBinding,
	upstream catalog.Upstream,
	dataHandling catalog.DataHandling,
) bool {
	if binding.TokenScope != azureDataScope ||
		!validAzureDeploymentName(binding.DeploymentName) ||
		!catalog.IsCanonicalDataLocation(binding.ProcessingLocation, false) ||
		!catalog.IsCanonicalDataLocation(binding.StorageLocation, false) ||
		!catalog.DataLocationWithin(binding.ProcessingLocation, dataHandling.ProcessingLocation) ||
		!catalog.DataLocationWithin(binding.StorageLocation, dataHandling.StorageLocation) ||
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
