package stogas

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	azureprovider "github.com/maximhq/bifrost/core/providers/azure"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/azureauth"
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

func TestAzureCredentialEligibilityUsesOnlyLiveCompatibleBindings(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		change  func(*billing.AzureBinding)
		expired bool
		want    error
	}{
		{"compatible", func(*billing.AzureBinding) {}, false, nil},
		{"expired", func(*billing.AzureBinding) {}, true, billing.ErrByokTarget},
		{"wrong model", func(b *billing.AzureBinding) { b.ModelName = "other" }, false, billing.ErrByokTarget},
		{"wrong version", func(b *billing.AzureBinding) { b.ModelVersion = "2026-07-10" }, false, billing.ErrByokTarget},
		{"wrong format", func(b *billing.AzureBinding) { b.ModelFormat = "Anthropic" }, false, billing.ErrByokTarget},
		{"wrong hosting", func(b *billing.AzureBinding) { b.Hosting = "anthropic" }, false, billing.ErrByokTarget},
		{"wrong deployment type", func(b *billing.AzureBinding) { b.DeploymentType = "data_zone_standard_us" }, false, billing.ErrByokTarget},
		{"untrusted endpoint", func(b *billing.AzureBinding) { b.Endpoint = "https://example.com" }, false, billing.ErrByokTarget},
		{"wrong scope", func(b *billing.AzureBinding) { b.TokenScope = "https://example.com/.default" }, false, billing.ErrByokTarget},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := azureTestBinding()
			test.change(&binding)
			var expires *time.Time
			if test.expired {
				value := now.Add(-time.Second)
				expires = &value
			}
			snapshot := &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{"azure": {{Credential: &billing.CachedCredential{Bindings: []billing.AzureCredentialBinding{{AzureBinding: binding, ModelDeprecationAt: expires}}}}}}}
			eligible := CredentialDeploymentFilter(snapshot, now)
			if got := eligible(schemas.Azure, 0, azureTestResolution().Deployment); got != (test.want == nil) {
				t.Fatalf("eligible=%v want=%v", got, test.want == nil)
			}
			if !eligible(schemas.OpenAI, 0, catalog.Deployment{}) {
				t.Fatal("Azure target metadata affected another provider")
			}
		})
	}
}

func TestAzureCredentialEligibilityRetainsMultipleTargetsAndRequestVariants(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	bindings := []billing.AzureCredentialBinding{
		{AzureBinding: azureTestBinding(), ModelDeprecationAt: &now},
		{AzureBinding: azureTestBinding()},
	}
	bindings[1].DeploymentName = "another-target"
	snapshot := &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{
		"azure": {{Credential: &billing.CachedCredential{Bindings: bindings}}},
	}}
	eligible := CredentialDeploymentFilter(snapshot, now)
	deployment := azureTestResolution().Deployment
	deployment.Upstream.ServiceTier = "priority"
	deployment.Upstream.ReasoningMode = "pro"
	if !eligible(schemas.Azure, 0, deployment) {
		t.Fatal("an expired target hid a live target supporting the same request variants")
	}
	deployment.DataHandling.ProcessingLocation = "eu"
	if eligible(schemas.Azure, 0, deployment) {
		t.Fatal("matching model identity bypassed the requested processing boundary")
	}
}

func TestAzureOnlyCredentialSelectsItsConfiguredDeploymentWithoutSecretAccess(t *testing.T) {
	snapshot := &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{
		"azure": {{Mode: "stored", Credential: &billing.CachedCredential{Bindings: []billing.AzureCredentialBinding{{AzureBinding: azureTestBinding()}}}}},
	}}
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		body := `{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]}`
		if path == "/v1/responses" {
			body = `{"model":"gpt-5.6-sol","input":"hello"}`
		}
		resolved, err := catalog.ResolveRequest(catalog.RequestInput{
			Body: []byte(body), Method: "POST", Path: path,
			AvailableCredentials: map[string][]int{"azure": {0}},
			DeploymentEligible:   CredentialDeploymentFilter(snapshot, time.Now()),
		})
		if err != nil || resolved == nil || resolved.Deployment.ID != "azure-gpt-5.6-sol" {
			t.Fatalf("result=%v error=%v", resolved, err)
		}
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

func TestAzureDirectKeyAcceptsResolvedNoStorageGuarantee(t *testing.T) {
	binding := azureTestBinding()
	binding.StorageLocation = "none"
	resolution := azureTestResolution()
	resolution.Deployment.DataHandling.StorageLocation = "none"
	if !validAzureBinding(binding, resolution.Deployment.Upstream, resolution.Deployment.DataHandling) {
		t.Fatal("resolved catalog no-storage guarantee was rejected")
	}
	binding.StorageLocation = "unknown"
	if validAzureBinding(binding, resolution.Deployment.Upstream, resolution.Deployment.DataHandling) {
		t.Fatal("unresolved unknown storage must not establish a no-storage guarantee")
	}
	binding.StorageLocation = "none"
	binding.ProcessingLocation = "none"
	if validAzureBinding(binding, resolution.Deployment.Upstream, resolution.Deployment.DataHandling) {
		t.Fatal("no-storage must not be accepted as a processing location")
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

type azureTokenFunc func(context.Context, azureauth.Credential) (string, error)

func (f azureTokenFunc) Token(ctx context.Context, credential azureauth.Credential) (string, error) {
	return f(ctx, credential)
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
	if err := applyUpstreamCredentials(ctx, state, azureTokenFunc(func(_ context.Context, credential azureauth.Credential) (string, error) {
		if credential.Scope != azureDataScope || credential.Secret != "azure-client-secret" {
			t.Fatal("incorrect Azure token credential")
		}
		return "test-access-token", nil
	})); err != nil {
		t.Fatal(err)
	}
	directKey, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
	if !ok || directKey.AzureKeyConfig == nil || state.Resolution.Model != "customer-sol" ||
		!directKey.Models.IsAllowed("customer-sol") {
		t.Fatalf("Azure bound key was not installed: key=%#v resolution=%#v", directKey, state.Resolution)
	}
	if directKey.AzureKeyConfig.ClientID != nil || directKey.AzureKeyConfig.ClientSecret != nil || directKey.AzureKeyConfig.TenantID != nil || ctx.Value(azureprovider.AzureAuthorizationTokenKey) != "test-access-token" {
		t.Fatal("Azure SDK credentials retained or access token missing")
	}
}
