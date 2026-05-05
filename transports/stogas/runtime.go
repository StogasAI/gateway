package stogas

import (
	"context"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

const openAIProviderKeyID = "stogas-openai"

type Runtime struct {
	client *bifrost.Bifrost
	holds  *HoldService
}

func NewRuntime(ctx context.Context, config Config, logger schemas.Logger) (*Runtime, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	tinybird := NewTinybirdClient(config.TinybirdHost, config.TinybirdToken)
	holds, err := NewHoldService(ctx, config.DatabaseURL, config.AuthSecret, tinybird)
	if err != nil {
		return nil, err
	}

	client, err := bifrost.Init(ctx, schemas.BifrostConfig{
		Account:         newAccount(config),
		InitialPoolSize: schemas.DefaultInitialPoolSize,
		LLMPlugins:      []schemas.LLMPlugin{NewPlugin(holds)},
		Logger:          logger,
		Tracer:          schemas.DefaultTracer(),
	})
	if err != nil {
		holds.Close()
		return nil, err
	}

	return &Runtime{client: client, holds: holds}, nil
}

func (r *Runtime) Client() *bifrost.Bifrost {
	if r == nil {
		return nil
	}
	return r.client
}

func (r *Runtime) Close() {
	if r == nil {
		return
	}
	if r.client != nil {
		r.client.Shutdown()
	}
	if r.holds != nil {
		r.holds.Close()
	}
}

type account struct {
	key            schemas.Key
	providerConfig schemas.ProviderConfig
}

func newAccount(config Config) *account {
	providerConfig := schemas.ProviderConfig{
		ConcurrencyAndBufferSize: schemas.DefaultConcurrencyAndBufferSize,
		NetworkConfig:            schemas.DefaultNetworkConfig,
	}
	if config.OpenAIBaseURL != "" {
		providerConfig.NetworkConfig.BaseURL = config.OpenAIBaseURL
	}
	providerConfig.CheckAndSetDefaults()

	return &account{
		key: schemas.Key{
			ID:      openAIProviderKeyID,
			Name:    openAIProviderKeyID,
			Value:   *schemas.NewEnvVar(config.OpenAIAPIKey),
			Weight:  1,
			Enabled: schemas.Ptr(true),
		},
		providerConfig: providerConfig,
	}
}

func (a *account) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{schemas.OpenAI}, nil
}

func (a *account) GetKeysForProvider(ctx context.Context, providerKey schemas.ModelProvider) ([]schemas.Key, error) {
	if providerKey != schemas.OpenAI {
		return []schemas.Key{}, nil
	}
	return []schemas.Key{a.key}, nil
}

func (a *account) GetConfigForProvider(providerKey schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	if providerKey != schemas.OpenAI {
		return nil, nil
	}
	config := a.providerConfig
	return &config, nil
}
