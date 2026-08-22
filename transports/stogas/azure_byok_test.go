package stogas

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func azureTestCredential(t *testing.T) string {
	t.Helper()
	encoded, err := json.Marshal(azureByokCredential{
		ClientID:        "00000000-0000-4000-8000-000000000002",
		ClientSecret:    "azure-client-secret",
		Schema:          azureByokSchema,
		SubscriptionIDs: []string{"00000000-0000-4000-8000-000000000003"},
		TenantID:        "00000000-0000-4000-8000-000000000001",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func azureTestBinding() billing.AzureBinding {
	return billing.AzureBinding{
		AccountLocation:    "eastus",
		DeploymentName:     "customer-sol",
		DeploymentType:     "global_standard",
		Endpoint:           "https://stogas-ai.openai.azure.com",
		Hosting:            "azure",
		ModelFormat:        "OpenAI",
		ModelName:          "gpt-5.6-sol",
		ModelVersion:       "2026-07-09",
		ProcessingLocation: "global",
		StorageLocation:    "US",
		TokenScope:         azureDataScope,
	}
}

func azureTestResolution() *catalog.ResolvedRequest {
	return &catalog.ResolvedRequest{
		Deployment: catalog.Deployment{
			ID:      "azure-gpt-5.6-sol",
			ModelID: "gpt-5.6-sol",
			DataHandling: catalog.DataHandling{
				ProcessingLocation: "global",
				StorageLocation:    "unknown",
			},
			Upstream: catalog.Upstream{
				DeploymentType: "global_standard",
				Hosting:        "azure",
				Model:          "gpt-5.6-sol",
				ModelFormat:    "OpenAI",
				ModelVersion:   "2026-07-09",
				ServiceTier:    "default",
			},
		},
		Provider: schemas.Azure,
	}
}

func TestParseAzureByokCredential(t *testing.T) {
	valid := azureTestCredential(t)
	parsed, err := parseAzureByokCredential(valid)
	if err != nil || parsed.ClientSecret != "azure-client-secret" || len(parsed.SubscriptionIDs) != 1 {
		t.Fatalf("valid Azure credential = %#v, err=%v", parsed, err)
	}

	tests := map[string]string{
		"empty client secret": strings.Replace(valid, "azure-client-secret", "", 1),
		"secret with space":   strings.Replace(valid, "azure-client-secret", "azure secret", 1),
		"unknown schema":      strings.Replace(valid, azureByokSchema, "unknown", 1),
		"unknown field":       strings.Replace(valid, `"schema"`, `"extra":true,"schema"`, 1),
		"invalid client ID":   strings.Replace(valid, "00000000-0000-4000-8000-000000000002", "client", 1),
		"duplicate subscription": strings.Replace(
			valid,
			`["00000000-0000-4000-8000-000000000003"]`,
			`["00000000-0000-4000-8000-000000000003","00000000-0000-4000-8000-000000000003"]`,
			1,
		),
		"trailing JSON": valid + `{}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, parseErr := parseAzureByokCredential(raw); parseErr == nil {
				t.Fatal("expected Azure credential validation failure")
			}
		})
	}
}

func TestAzureDirectKeyUsesOnlyTheAuthorizedExactBinding(t *testing.T) {
	binding := azureTestBinding()
	authorization := &billing.Authorization{
		AzureBinding:       &binding,
		UpstreamByok:       "00000000-0000-8000-8000-000000000001",
		UpstreamByokSecret: azureTestCredential(t),
	}
	key, deploymentName, err := azureDirectKey(authorization, azureTestResolution())
	if err != nil {
		t.Fatal(err)
	}
	if deploymentName != "customer-sol" || !key.Models.IsAllowed("customer-sol") {
		t.Fatalf("wire model was not bound: key=%#v model=%q", key, deploymentName)
	}
	if key.Value.GetValue() != "" || key.AzureKeyConfig == nil ||
		key.AzureKeyConfig.Endpoint.GetValue() != binding.Endpoint ||
		key.AzureKeyConfig.ClientSecret.GetValue() != "azure-client-secret" ||
		len(key.AzureKeyConfig.Scopes) != 1 || key.AzureKeyConfig.Scopes[0] != azureDataScope {
		t.Fatalf("unexpected Azure direct key: %#v", key)
	}

	for _, upstream := range []catalog.Upstream{
		{DeploymentType: "global_standard", Hosting: "azure", Model: "gpt-5.6-sol", ModelFormat: "OpenAI", ModelVersion: "2026-07-09", ServiceTier: "priority"},
		{DeploymentType: "global_standard", Hosting: "azure", Model: "gpt-5.6-sol", ModelFormat: "OpenAI", ModelVersion: "2026-07-09", ReasoningMode: "pro"},
	} {
		resolution := azureTestResolution()
		resolution.Deployment.Upstream = upstream
		if _, selected, variantErr := azureDirectKey(authorization, resolution); variantErr != nil || selected != "customer-sol" {
			t.Fatalf("request control variant selected %q, err=%v", selected, variantErr)
		}
	}
}

func TestAzureDirectKeyRejectsTargetOrEndpointSubstitution(t *testing.T) {
	baseBinding := azureTestBinding()
	baseResolution := azureTestResolution()
	tests := map[string]func(*billing.AzureBinding, *catalog.ResolvedRequest){
		"deployment type": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.DeploymentType = "data_zone_standard_us"
		},
		"hosting":       func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.Hosting = "fireworks" },
		"model format":  func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.ModelFormat = "Fireworks" },
		"model name":    func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.ModelName = "gpt-5.6-terra" },
		"model version": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.ModelVersion = "2026-07-10" },
		"processing location": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.ProcessingLocation = "ZZ"
		},
		"storage location": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.StorageLocation = "multi-region"
		},
		"processing outside catalog boundary": func(_ *billing.AzureBinding, resolution *catalog.ResolvedRequest) {
			resolution.Deployment.DataHandling.ProcessingLocation = "eu"
		},
		"storage outside catalog boundary": func(_ *billing.AzureBinding, resolution *catalog.ResolvedRequest) {
			resolution.Deployment.DataHandling.StorageLocation = "SE"
		},
		"arbitrary host": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.Endpoint = "https://attacker.example"
		},
		"nested account": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.Endpoint = "https://a.b.openai.azure.com"
		},
		"userinfo": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.Endpoint = "https://user@stogas-ai.openai.azure.com"
		},
		"query": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) { binding.Endpoint += "?x=1" },
		"project on deployment": func(binding *billing.AzureBinding, _ *catalog.ResolvedRequest) {
			binding.Endpoint = "https://stogas-ai.services.ai.azure.com/api/projects/project"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			binding := baseBinding
			resolution := *baseResolution
			resolution.Deployment = baseResolution.Deployment
			mutate(&binding, &resolution)
			_, _, err := azureDirectKey(&billing.Authorization{
				AzureBinding:       &binding,
				UpstreamByok:       "00000000-0000-8000-8000-000000000001",
				UpstreamByokSecret: azureTestCredential(t),
			}, &resolution)
			if err == nil {
				t.Fatal("expected exact Azure binding rejection")
			}
		})
	}
}

func TestAzureDirectKeyAcceptsNarrowerDiscoveredLocations(t *testing.T) {
	binding := azureTestBinding()
	binding.ProcessingLocation = "eu"
	binding.StorageLocation = "SE"
	resolution := azureTestResolution()
	resolution.Deployment.DataHandling.ProcessingLocation = "eu"
	resolution.Deployment.DataHandling.StorageLocation = "europe"

	_, deploymentName, err := azureDirectKey(&billing.Authorization{
		AzureBinding:       &binding,
		UpstreamByok:       "00000000-0000-8000-8000-000000000001",
		UpstreamByokSecret: azureTestCredential(t),
	}, resolution)
	if err != nil || deploymentName != binding.DeploymentName {
		t.Fatalf("narrower Azure binding was rejected: deployment=%q err=%v", deploymentName, err)
	}
}

func TestAzureDirectKeySupportsInstantProjectBinding(t *testing.T) {
	binding := azureTestBinding()
	binding.DeploymentName = "gpt-5.6-sol-2026-07-09"
	binding.DeploymentType = "instant"
	binding.Endpoint = "https://stogas-ai.services.ai.azure.com/api/projects/Project_1"
	resolution := azureTestResolution()
	resolution.Deployment.ID = "azure-gpt-5.6-sol-instant"
	resolution.Deployment.Upstream.DeploymentType = "instant"
	key, wireModel, err := azureDirectKey(&billing.Authorization{
		AzureBinding:       &binding,
		UpstreamByok:       "00000000-0000-8000-8000-000000000001",
		UpstreamByokSecret: azureTestCredential(t),
	}, resolution)
	if err != nil || wireModel != binding.DeploymentName || key.AzureKeyConfig == nil ||
		key.AzureKeyConfig.Endpoint.GetValue() != binding.Endpoint {
		t.Fatalf("instant binding = %#v, model=%q, err=%v", key, wireModel, err)
	}

	binding.Endpoint = "https://stogas-ai.services.ai.azure.com"
	if _, _, err = azureDirectKey(&billing.Authorization{
		AzureBinding:       &binding,
		UpstreamByok:       "00000000-0000-8000-8000-000000000001",
		UpstreamByokSecret: azureTestCredential(t),
	}, resolution); err == nil {
		t.Fatal("instant binding accepted a non-project endpoint")
	}
}

func TestApplyUpstreamCredentialsInstallsAzureBoundKey(t *testing.T) {
	binding := azureTestBinding()
	state := &State{
		Authorization: &billing.Authorization{
			AzureBinding:       &binding,
			UpstreamByok:       "00000000-0000-8000-8000-000000000001",
			UpstreamByokSecret: azureTestCredential(t),
		},
		Resolution: azureTestResolution(),
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	if err := ApplyUpstreamCredentials(ctx, state); err != nil {
		t.Fatal(err)
	}
	directKey, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
	if !ok || directKey.AzureKeyConfig == nil || state.Resolution.Model != "customer-sol" ||
		!directKey.Models.IsAllowed("customer-sol") {
		t.Fatalf("Azure bound key was not installed: key=%#v resolution=%#v", directKey, state.Resolution)
	}
}
