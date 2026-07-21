package stogas

import (
	"context"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

const (
	openAIProviderKeyID    = "stogas-openai"
	anthropicProviderKeyID = "stogas-anthropic"
)

type Runtime struct {
	client  *bifrost.Bifrost
	billing *billing.Service
	cancel  context.CancelFunc
}

func NewRuntime(ctx context.Context, config Config, logger schemas.Logger) (*Runtime, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := validateProviderRuntimeSecretsReady(config); err != nil {
		return nil, err
	}

	runtimeCtx, cancel := context.WithCancel(ctx)
	tinybird := billing.NewTinybirdClient(config.TinybirdHost, config.TinybirdToken)
	billingService, err := billing.NewService(runtimeCtx, config.DatabaseURL, config.DatabaseSchema, config.AuthSecret, config.DatabasePool, tinybird)
	if err != nil {
		cancel()
		return nil, err
	}

	client, err := bifrost.Init(runtimeCtx, schemas.BifrostConfig{
		Account:         newAccount(config),
		InitialPoolSize: schemas.DefaultInitialPoolSize,
		Logger:          logger,
		Tracer:          schemas.DefaultTracer(),
	})
	if err != nil {
		billingService.Close()
		cancel()
		return nil, err
	}

	return &Runtime{client: client, billing: billingService, cancel: cancel}, nil
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

func (r *Runtime) ParseAPIKey(rawAPIKey string) (*billing.APIKeyClaims, error) {
	if r == nil || r.billing == nil {
		return nil, billing.ErrInvalidAPIKey
	}
	return r.billing.ParseAPIKey(rawAPIKey)
}

func (r *Runtime) Billing() *billing.Service {
	if r == nil {
		return nil
	}
	return r.billing
}

func (r *Runtime) ProbeDependencies(ctx context.Context) error {
	if r == nil || r.billing == nil {
		return billing.ErrGatewayUnavailable
	}
	return r.billing.ProbeDatabase(ctx)
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
	keys            map[schemas.ModelProvider]schemas.Key
	providerConfigs map[schemas.ModelProvider]schemas.ProviderConfig
}

func newAccount(config Config) *account {
	openAIConfig := newProviderConfig(config.OpenAIBaseURL, config.AllowPrivateProviderNetwork)
	openAIConfig.OpenAIConfig = &schemas.OpenAIConfig{DisableStore: true}
	anthropicConfig := newProviderConfig(config.AnthropicBaseURL, config.AllowPrivateProviderNetwork)

	return &account{
		keys: map[schemas.ModelProvider]schemas.Key{
			schemas.OpenAI: {
				ID:      openAIProviderKeyID,
				Name:    openAIProviderKeyID,
				Value:   *schemas.NewEnvVar(config.OpenAIAPIKey),
				Models:  schemas.WhiteList{"*"},
				Weight:  1,
				Enabled: schemas.Ptr(true),
			},
			schemas.Anthropic: {
				ID:      anthropicProviderKeyID,
				Name:    anthropicProviderKeyID,
				Value:   *schemas.NewEnvVar(config.AnthropicAPIKey),
				Models:  schemas.WhiteList{"*"},
				Weight:  1,
				Enabled: schemas.Ptr(true),
			},
		},
		providerConfigs: map[schemas.ModelProvider]schemas.ProviderConfig{
			schemas.OpenAI:    openAIConfig,
			schemas.Anthropic: anthropicConfig,
		},
	}
}

func newProviderConfig(baseURL string, allowPrivateNetwork bool) schemas.ProviderConfig {
	config := schemas.ProviderConfig{
		ConcurrencyAndBufferSize: schemas.DefaultConcurrencyAndBufferSize,
		NetworkConfig:            schemas.DefaultNetworkConfig,
	}
	if baseURL != "" {
		config.NetworkConfig.BaseURL = baseURL
	}
	config.NetworkConfig.AllowPrivateNetwork = allowPrivateNetwork
	config.CheckAndSetDefaults()
	return config
}

func (a *account) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic}, nil
}

func (a *account) GetKeysForProvider(ctx context.Context, providerKey schemas.ModelProvider) ([]schemas.Key, error) {
	key, ok := a.keys[providerKey]
	if !ok {
		return []schemas.Key{}, nil
	}
	return []schemas.Key{key}, nil
}

func (a *account) GetConfigForProvider(providerKey schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	config, ok := a.providerConfigs[providerKey]
	if !ok {
		return nil, nil
	}
	return &config, nil
}
