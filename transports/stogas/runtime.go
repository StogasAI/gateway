package stogas

import (
	"context"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/apikey"
)

const openAIProviderKeyID = "stogas-openai"

type Runtime struct {
	client  *bifrost.Bifrost
	billing *BillingService
	cancel  context.CancelFunc
}

func NewRuntime(ctx context.Context, config Config, logger schemas.Logger) (*Runtime, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	runtimeCtx, cancel := context.WithCancel(ctx)
	tinybird := NewTinybirdClient(config.TinybirdHost, config.TinybirdToken)
	billing, err := NewBillingService(runtimeCtx, config.DatabaseURL, config.DatabaseSchema, config.AuthSecret, config.DatabasePool, tinybird)
	if err != nil {
		cancel()
		return nil, err
	}

	client, err := bifrost.Init(runtimeCtx, schemas.BifrostConfig{
		Account:         newAccount(config),
		InitialPoolSize: schemas.DefaultInitialPoolSize,
		LLMPlugins:      []schemas.LLMPlugin{NewPlugin(billing)},
		Logger:          logger,
		Tracer:          schemas.DefaultTracer(),
	})
	if err != nil {
		billing.Close()
		cancel()
		return nil, err
	}

	return &Runtime{client: client, billing: billing, cancel: cancel}, nil
}

func (r *Runtime) Client() *bifrost.Bifrost {
	if r == nil {
		return nil
	}
	return r.client
}

func (r *Runtime) ValidateAPIKeyFormat(rawAPIKey string) error {
	_, err := r.ParseAPIKey(rawAPIKey)
	return err
}

func (r *Runtime) ParseAPIKey(rawAPIKey string) (*apikey.Claims, error) {
	if r == nil || r.billing == nil {
		return nil, ErrInvalidAPIKey
	}
	return r.billing.ParseAPIKey(rawAPIKey)
}

func (r *Runtime) Close() {
	if r == nil {
		return
	}
	if r.client != nil {
		r.client.Shutdown()
	}
	if r.billing != nil {
		r.billing.Close()
	}
	if r.cancel != nil {
		r.cancel()
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
	providerConfig.NetworkConfig.AllowPrivateNetwork = config.AllowPrivateProviderNetwork
	providerConfig.CheckAndSetDefaults()

	return &account{
		key: schemas.Key{
			ID:      openAIProviderKeyID,
			Name:    openAIProviderKeyID,
			Value:   *schemas.NewEnvVar(config.OpenAIAPIKey),
			Models:  schemas.WhiteList{"*"},
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
