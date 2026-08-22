package stogas

import (
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestRuntimeAccountDisablesOpenAIProviderStorage(t *testing.T) {
	account := newAccount(Config{
		ChutesAPIKey: "sk-chutes",
	}, nil)

	config, err := account.GetConfigForProvider(schemas.OpenAI)
	if err != nil {
		t.Fatalf("GetConfigForProvider returned error: %v", err)
	}
	if config == nil || config.OpenAIConfig == nil || !config.OpenAIConfig.DisableStore {
		t.Fatalf("expected OpenAI provider config to force store=false, got %#v", config)
	}

	anthropicConfig, err := account.GetConfigForProvider(schemas.Anthropic)
	if err != nil {
		t.Fatalf("GetConfigForProvider Anthropic returned error: %v", err)
	}
	if anthropicConfig == nil {
		t.Fatal("expected Anthropic provider config")
	}
	if anthropicConfig.OpenAIConfig != nil {
		t.Fatalf("Anthropic config must not carry OpenAI retention settings, got %#v", anthropicConfig.OpenAIConfig)
	}

	chutesConfig, err := account.GetConfigForProvider(catalog.ProviderChutes)
	if err != nil {
		t.Fatalf("GetConfigForProvider Chutes returned error: %v", err)
	}
	if chutesConfig == nil || chutesConfig.CustomProviderConfig == nil {
		t.Fatal("expected Chutes custom provider config")
	}
	custom := chutesConfig.CustomProviderConfig
	if custom.BaseProviderType != schemas.OpenAI || custom.AllowedRequests == nil ||
		!custom.AllowedRequests.ChatCompletion || !custom.AllowedRequests.ChatCompletionStream ||
		custom.AllowedRequests.Responses || custom.AllowedRequests.ResponsesStream {
		t.Fatalf("Chutes must expose only OpenAI-compatible Chat Completions, got %#v", custom)
	}
	if chutesConfig.NetworkConfig.BaseURL != defaultChutesBaseURL {
		t.Fatalf("Chutes base URL = %q, want %q", chutesConfig.NetworkConfig.BaseURL, defaultChutesBaseURL)
	}
	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic, schemas.Azure, catalog.ProviderChutes} {
		providerConfig, err := account.GetConfigForProvider(provider)
		if err != nil {
			t.Fatal(err)
		}
		if providerConfig == nil || providerConfig.NetworkConfig.MaxResponseBodySize != maxProviderResponseBodySize {
			t.Fatalf("%s provider response cap = %#v, want %d", provider, providerConfig, maxProviderResponseBodySize)
		}
	}

	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic, schemas.Azure} {
		keys, err := account.GetKeysForProvider(t.Context(), provider)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 0 {
			t.Fatalf("%s must be BYOK-only, got managed keys %#v", provider, keys)
		}
	}
}

func TestConfidentialRuntimeUsesTheSupportedProviderTransportSecurity(t *testing.T) {
	account := newAccount(Config{
		ChutesAPIKey: "sk-chutes",
		Confidential: ConfidentialConfig{
			Enabled:     true,
			Environment: "staging",
		},
	}, nil)

	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic} {
		config, err := account.GetConfigForProvider(provider)
		if err != nil {
			t.Fatal(err)
		}
		if config == nil || !config.NetworkConfig.RequirePostQuantumTLS {
			t.Fatalf("%s provider does not require post-quantum TLS", provider)
		}
	}
	azureConfig, err := account.GetConfigForProvider(schemas.Azure)
	if err != nil {
		t.Fatal(err)
	}
	if azureConfig == nil || !azureConfig.NetworkConfig.RequireTLS13 || azureConfig.NetworkConfig.RequirePostQuantumTLS {
		t.Fatalf("Azure must require TLS 1.3 with provider-compatible key exchange, got %#v", azureConfig)
	}
	chutesConfig, err := account.GetConfigForProvider(catalog.ProviderChutes)
	if err != nil {
		t.Fatal(err)
	}
	if chutesConfig == nil || chutesConfig.NetworkConfig.RequirePostQuantumTLS {
		t.Fatal("Chutes outer TLS must allow the provider's TLS 1.3 fallback; ML-KEM payload E2EE is mandatory")
	}
}
