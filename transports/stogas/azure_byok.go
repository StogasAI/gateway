package stogas

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const azureByokSchema = "stogas.azure-byok.v2"

var (
	azureResourceNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
)

type azureByokCredential struct {
	APIKey       string `json:"apiKey"`
	ResourceName string `json:"resourceName"`
	ResourceType string `json:"resourceType"`
	Schema       string `json:"schema"`
}

func azureDirectKey(authorization *billing.Authorization, resolution *catalog.ResolvedRequest) (schemas.Key, error) {
	if authorization == nil || resolution == nil {
		return schemas.Key{}, billing.ErrByok
	}
	credential, err := parseAzureByokCredential(authorization.UpstreamByokSecret)
	if err != nil {
		return schemas.Key{}, billing.ErrByok
	}
	model := resolution.Deployment.Upstream.Model
	if resolution.Provider != schemas.Azure || model == "" || model != resolution.Deployment.ModelID {
		return schemas.Key{}, billing.ErrByok
	}
	return schemas.Key{
		ID:     authorization.UpstreamByok,
		Name:   authorization.UpstreamByok,
		Value:  *schemas.NewSecretVar(credential.APIKey),
		Models: schemas.WhiteList{model},
		AzureKeyConfig: &schemas.AzureKeyConfig{
			Endpoint: *schemas.NewSecretVar(azureEndpoint(credential)),
		},
		Weight:  1,
		Enabled: schemas.Ptr(true),
	}, nil
}

func parseAzureByokCredential(raw string) (azureByokCredential, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	credential := azureByokCredential{}
	if err := decoder.Decode(&credential); err != nil {
		return azureByokCredential{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return azureByokCredential{}, errors.New("Azure BYOK contains trailing JSON")
	}
	credential.ResourceName = strings.ToLower(strings.TrimSpace(credential.ResourceName))
	if credential.Schema != azureByokSchema ||
		!validUpstreamAPIKey(credential.APIKey) ||
		len(credential.ResourceName) < 2 || len(credential.ResourceName) > 63 ||
		!azureResourceNamePattern.MatchString(credential.ResourceName) ||
		(credential.ResourceType != "azure_openai" && credential.ResourceType != "azure_ai_foundry") {
		return azureByokCredential{}, errors.New("Azure BYOK is invalid")
	}
	return credential, nil
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

func azureEndpoint(credential azureByokCredential) string {
	domain := "openai.azure.com"
	if credential.ResourceType == "azure_ai_foundry" {
		domain = "services.ai.azure.com"
	}
	return "https://" + credential.ResourceName + "." + domain
}
