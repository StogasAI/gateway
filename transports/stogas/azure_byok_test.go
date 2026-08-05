package stogas

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestParseAzureByokCredentialRejectsUntrustedConfiguration(t *testing.T) {
	valid := `{"apiKey":"azure-secret","resourceName":"trusted-resource","resourceType":"azure_openai","schema":"stogas.azure-byok.v2"}`
	tests := map[string]string{
		"arbitrary endpoint":    strings.Replace(valid, `"schema"`, `"endpoint":"https://attacker.example","schema"`, 1),
		"domain as resource":    strings.Replace(valid, `"trusted-resource"`, `"trusted-resource.openai.azure.com"`, 1),
		"empty API key":         strings.Replace(valid, `"azure-secret"`, `""`, 1),
		"whitespace in API key": strings.Replace(valid, `"azure-secret"`, `"azure secret"`, 1),
		"leading API key space": strings.Replace(valid, `"azure-secret"`, `" azure-secret"`, 1),
		"API key line break":    strings.Replace(valid, `"azure-secret"`, `"azure\nsecret"`, 1),
		"API key NUL":           strings.Replace(valid, `"azure-secret"`, `"azure\u0000secret"`, 1),
		"API key Unicode":       strings.Replace(valid, `"azure-secret"`, `"azure-é"`, 1),
		"unknown resource type": strings.Replace(valid, `"azure_openai"`, `"other"`, 1),
		"legacy deployment map": strings.Replace(valid, `"schema"`, `"deployments":{"gpt-5.6-sol":"sol-prod"},"schema"`, 1),
		"unknown schema":        strings.Replace(valid, `"stogas.azure-byok.v2"`, `"other"`, 1),
		"trailing JSON":         valid + `{}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseAzureByokCredential(raw); err == nil {
				t.Fatal("expected Azure BYOK validation failure")
			}
		})
	}
}

func TestAzureDirectKeyDerivesTrustedEndpointAndCanonicalModel(t *testing.T) {
	for _, tc := range []struct {
		resourceType string
		wantEndpoint string
	}{
		{resourceType: "azure_openai", wantEndpoint: "https://stogas-ai.openai.azure.com"},
		{resourceType: "azure_ai_foundry", wantEndpoint: "https://stogas-ai.services.ai.azure.com"},
	} {
		t.Run(tc.resourceType, func(t *testing.T) {
			authorization := &billing.Authorization{
				UpstreamByok:       "0198f4cc-6c25-7000-8000-000000000001",
				UpstreamByokSecret: `{"apiKey":"azure-secret","resourceName":"Stogas-AI","resourceType":"` + tc.resourceType + `","schema":"stogas.azure-byok.v2"}`,
			}
			for _, model := range []string{"gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra"} {
				key, err := azureDirectKey(authorization, &catalog.ResolvedRequest{
					Deployment: catalog.Deployment{ModelID: model, Upstream: catalog.Upstream{Model: model}},
					Provider:   schemas.Azure,
				})
				if err != nil {
					t.Fatalf("azureDirectKey returned error: %v", err)
				}
				if key.Value.GetValue() != "azure-secret" || key.AzureKeyConfig == nil || key.AzureKeyConfig.Endpoint.GetValue() != tc.wantEndpoint {
					t.Fatalf("unexpected Azure key: %#v", key)
				}
				if len(key.Aliases) != 0 || len(key.Models) != 1 || key.Models[0] != model {
					t.Fatalf("key for %s added a deployment map: %#v", model, key)
				}
			}
		})
	}
}

func TestAzureBYOKSupportsBothNativeAPIsOnBothResourceOrigins(t *testing.T) {
	routes := []struct {
		body         string
		catalogRoute string
		path         string
		requestKind  string
	}{
		{
			body:         `{"model":"gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}]}`,
			catalogRoute: "azure-chat-completions",
			path:         "/v1/chat/completions",
			requestKind:  "chat",
		},
		{
			body:         `{"model":"gpt-5.6-sol","provider":"azure","input":"hi"}`,
			catalogRoute: "azure-responses",
			path:         "/v1/responses",
			requestKind:  "responses",
		},
	}
	resources := []struct {
		resourceType string
		wantEndpoint string
	}{
		{resourceType: "azure_openai", wantEndpoint: "https://stogas-ai.openai.azure.com"},
		{resourceType: "azure_ai_foundry", wantEndpoint: "https://stogas-ai.services.ai.azure.com"},
	}

	for _, resource := range resources {
		for _, route := range routes {
			t.Run(resource.resourceType+" "+route.requestKind, func(t *testing.T) {
				state := resolveAzureState(t, route.path, route.body)
				if len(state.Resolution.Deployment.RouteIDs) != 1 ||
					state.Resolution.Deployment.RouteIDs[0] != route.catalogRoute {
					t.Fatalf("resolved catalog route = %#v, want %s", state.Resolution.Deployment.RouteIDs, route.catalogRoute)
				}

				authorization := &billing.Authorization{
					UpstreamByok:       "0198f4cc-6c25-7000-8000-000000000001",
					UpstreamByokSecret: `{"apiKey":"azure-secret","resourceName":"stogas-ai","resourceType":"` + resource.resourceType + `","schema":"stogas.azure-byok.v2"}`,
				}
				key, err := azureDirectKey(authorization, state.Resolution)
				if err != nil {
					t.Fatalf("azureDirectKey returned error: %v", err)
				}
				if key.AzureKeyConfig == nil || key.AzureKeyConfig.Endpoint.GetValue() != resource.wantEndpoint ||
					len(key.Aliases) != 0 || !key.Models.IsAllowed("gpt-5.6-sol") {
					t.Fatalf("unexpected Azure key configuration: %#v", key)
				}

				request, err := state.Resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
				if err != nil {
					t.Fatalf("ToBifrost returned error: %v", err)
				}
				switch route.requestKind {
				case "chat":
					if request.ChatRequest == nil || request.ChatRequest.Provider != schemas.Azure || request.ResponsesRequest != nil {
						t.Fatalf("Chat Completions did not use the native Azure chat request: %#v", request)
					}
				case "responses":
					if request.ResponsesRequest == nil || request.ResponsesRequest.Provider != schemas.Azure || request.ChatRequest != nil {
						t.Fatalf("Responses did not use the native Azure responses request: %#v", request)
					}
				}
			})
		}
	}
}

func TestAzureDirectKeyRejectsUpstreamModelMismatch(t *testing.T) {
	_, err := azureDirectKey(&billing.Authorization{
		UpstreamByok:       "0198f4cc-6c25-7000-8000-000000000001",
		UpstreamByokSecret: `{"apiKey":"azure-secret","resourceName":"stogas-ai","resourceType":"azure_openai","schema":"stogas.azure-byok.v2"}`,
	}, &catalog.ResolvedRequest{
		Deployment: catalog.Deployment{
			ModelID:  "gpt-5.6-sol",
			Upstream: catalog.Upstream{Model: "gpt-4o"},
		},
		Provider: schemas.Azure,
	})
	if !errors.Is(err, billing.ErrByok) {
		t.Fatalf("azureDirectKey error = %v, want BYOK rejection", err)
	}
}

func TestApplyUpstreamCredentialsInstallsAzureDirectKey(t *testing.T) {
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	state := &State{
		Authorization: &billing.Authorization{
			UpstreamByok:       "0198f4cc-6c25-7000-8000-000000000001",
			UpstreamByokSecret: `{"apiKey":"azure-secret","resourceName":"stogas-ai","resourceType":"azure_ai_foundry","schema":"stogas.azure-byok.v2"}`,
		},
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{
				ModelID:  "gpt-5.6-sol",
				Upstream: catalog.Upstream{Model: "gpt-5.6-sol"},
			},
			Provider: schemas.Azure,
		},
	}
	if err := ApplyUpstreamCredentials(ctx, state); err != nil {
		t.Fatalf("ApplyUpstreamCredentials returned error: %v", err)
	}
	directKey, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
	if !ok || directKey.AzureKeyConfig == nil || directKey.AzureKeyConfig.Endpoint.GetValue() != "https://stogas-ai.services.ai.azure.com" {
		t.Fatalf("Azure direct key was not installed: %#v", directKey)
	}
}
