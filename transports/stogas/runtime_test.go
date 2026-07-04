package stogas

import (
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestRuntimeAccountDisablesOpenAIProviderStorage(t *testing.T) {
	account := newAccount(Config{
		OpenAIAPIKey:    "sk-openai",
		AnthropicAPIKey: "sk-ant",
	})

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
}
