package stogas

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"github.com/valyala/fasthttp"
)

const (
	chutesProviderKeyID = "stogas-chutes"
)

type Runtime struct {
	client     *bifrost.Bifrost
	billing    *billing.Service
	chutesE2EE *chutese2ee.Transport
	cancel     context.CancelFunc
}

func NewRuntime(ctx context.Context, config Config, logger schemas.Logger) (*Runtime, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := validateProviderRuntimeSecretsReady(config); err != nil {
		return nil, err
	}

	runtimeCtx, cancel := context.WithCancel(ctx)
	chutesTransport, err := newChutesE2EETransport(config)
	if err != nil {
		cancel()
		return nil, err
	}
	tinybird, err := billing.NewTinybirdClient(
		config.TinybirdHost,
		config.TinybirdToken,
		config.Confidential.Environment == "local" && config.AllowPrivateProviderNetwork,
	)
	if err != nil {
		chutesTransport.Close()
		cancel()
		return nil, fmt.Errorf("configure Tinybird: %w", err)
	}
	billingService, err := billing.NewService(
		runtimeCtx,
		config.DatabaseURL,
		config.DatabaseSchema,
		config.APIKeyPepper,
		config.BYOKEncryptionSecret,
		config.InferenceTokenPublicKey,
		config.DatabasePool,
		tinybird,
	)
	if err != nil {
		chutesTransport.Close()
		cancel()
		return nil, err
	}

	client, err := bifrost.Init(runtimeCtx, schemas.BifrostConfig{
		Account: newAccount(config, chutesTransport),
		// sync.Pool allocates on demand and Go may clear it during any GC.
		// Do not prewarm a speculative number of request objects.
		Logger: logger,
		Tracer: newProviderAttemptTracer(schemas.DefaultTracer()),
	})
	if err != nil {
		billingService.Close()
		chutesTransport.Close()
		cancel()
		return nil, err
	}

	return &Runtime{client: client, billing: billingService, chutesE2EE: chutesTransport, cancel: cancel}, nil
}

func (r *Runtime) Client() *bifrost.Bifrost {
	if r == nil {
		return nil
	}
	return r.client
}

func (r *Runtime) ParseAPIKey(rawAPIKey string) (*billing.APIKeyClaims, error) {
	if r == nil || r.billing == nil {
		return nil, billing.ErrInvalidAPIKey
	}
	return r.billing.ParseAPIKey(rawAPIKey)
}

func (r *Runtime) ParseDashboardCredential(raw string) (*billing.DashboardCredential, error) {
	if r == nil || r.billing == nil {
		return nil, billing.ErrInvalidAPIKey
	}
	return r.billing.ParseDashboardCredential(raw)
}

func (r *Runtime) Billing() *billing.Service {
	if r == nil {
		return nil
	}
	return r.billing
}

func (r *Runtime) ChutesE2EEDiagnostics() chutese2ee.DiagnosticsSnapshot {
	if r == nil || r.chutesE2EE == nil {
		return chutese2ee.DiagnosticsSnapshot{}
	}
	return r.chutesE2EE.Diagnostics()
}

func (r *Runtime) BillingDiagnostics() billing.DiagnosticsSnapshot {
	if r == nil || r.billing == nil {
		return billing.DiagnosticsSnapshot{}
	}
	return r.billing.Diagnostics()
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
	if r.chutesE2EE != nil {
		r.chutesE2EE.Close()
	}
	if r.cancel != nil {
		r.cancel()
	}
}

type account struct {
	keys            map[schemas.ModelProvider]schemas.Key
	providerConfigs map[schemas.ModelProvider]schemas.ProviderConfig
}

func newAccount(config Config, chutesTransport fasthttp.RoundTripper) *account {
	requirePostQuantumTLS := config.Confidential.Enabled && config.Confidential.Environment != "local"
	openAIConfig := newProviderConfig(
		config.OpenAIBaseURL,
		config.AllowPrivateProviderNetwork,
		requirePostQuantumTLS,
	)
	openAIConfig.OpenAIConfig = &schemas.OpenAIConfig{DisableStore: true}
	anthropicConfig := newProviderConfig(
		config.AnthropicBaseURL,
		config.AllowPrivateProviderNetwork,
		requirePostQuantumTLS,
	)
	azureConfig := newProviderConfig(
		"",
		config.AllowPrivateProviderNetwork,
		false,
	)
	azureConfig.NetworkConfig.RequireTLS13 = requirePostQuantumTLS
	chutesBaseURL := config.ChutesBaseURL
	if chutesBaseURL == "" {
		chutesBaseURL = defaultChutesBaseURL
	}
	chutesConfig := newProviderConfig(
		chutesBaseURL,
		config.AllowPrivateProviderNetwork,
		false,
	)
	chutesConfig.CustomProviderConfig = &schemas.CustomProviderConfig{
		BaseProviderType: schemas.OpenAI,
		AllowedRequests: &schemas.AllowedRequests{
			ChatCompletion:       true,
			ChatCompletionStream: true,
		},
	}
	chutesConfig.NetworkConfig.Transport = chutesTransport

	return &account{
		keys: map[schemas.ModelProvider]schemas.Key{
			catalog.ProviderChutes: {
				ID:      chutesProviderKeyID,
				Name:    chutesProviderKeyID,
				Value:   *schemas.NewSecretVar(config.ChutesAPIKey),
				Models:  schemas.WhiteList{"*"},
				Weight:  1,
				Enabled: schemas.Ptr(true),
			},
		},
		providerConfigs: map[schemas.ModelProvider]schemas.ProviderConfig{
			schemas.OpenAI:         openAIConfig,
			schemas.Anthropic:      anthropicConfig,
			schemas.Azure:          azureConfig,
			catalog.ProviderChutes: chutesConfig,
		},
	}
}

func newChutesE2EETransport(config Config) (*chutese2ee.Transport, error) {
	apiBaseURL, err := chutesE2EEAPIBaseURL(config.ChutesBaseURL)
	if err != nil {
		return nil, err
	}
	confidentialProduction := config.Confidential.Enabled && config.Confidential.Environment != "local"
	return chutese2ee.New(chutese2ee.Options{
		APIKey:                  config.ChutesAPIKey,
		APIBaseURL:              apiBaseURL,
		RequireProductionOrigin: confidentialProduction,
		StreamTimeout:           billing.GatewayRequestLifetime,
		ResolveModel: func(upstreamModel string) (chutese2ee.ModelTarget, bool) {
			deployment, ok := catalog.DeploymentForUpstreamModel(catalog.ProviderChutes, upstreamModel, catalog.RouteChat)
			if !ok || deployment.Upstream.ChuteID == "" || deployment.Upstream.GPUCount < 1 {
				return chutese2ee.ModelTarget{}, false
			}
			return chutese2ee.ModelTarget{
				ChuteID:  deployment.Upstream.ChuteID,
				GPUCount: deployment.Upstream.GPUCount,
			}, true
		},
	})
}

func chutesE2EEAPIBaseURL(chutesBaseURL string) (string, error) {
	baseURL := strings.TrimSpace(chutesBaseURL)
	if baseURL == "" || strings.TrimRight(baseURL, "/") == defaultChutesBaseURL {
		return "https://api.chutes.ai", nil
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("invalid CHUTES_BASE_URL")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func newProviderConfig(baseURL string, allowPrivateNetwork, requirePostQuantumTLS bool) schemas.ProviderConfig {
	config := schemas.ProviderConfig{
		ConcurrencyAndBufferSize: schemas.DefaultConcurrencyAndBufferSize,
		NetworkConfig:            schemas.DefaultNetworkConfig,
	}
	// A transport failure does not prove that the provider did not start work.
	// Stogas never replays an inference request after provider dispatch.
	config.NetworkConfig.DefaultRequestTimeoutInSeconds = int(billing.GatewayRequestLifetime.Seconds())
	config.NetworkConfig.MaxRetries = 0
	if baseURL != "" {
		config.NetworkConfig.BaseURL = baseURL
	}
	config.NetworkConfig.AllowPrivateNetwork = allowPrivateNetwork
	config.NetworkConfig.RequirePostQuantumTLS = requirePostQuantumTLS
	config.NetworkConfig.MaxResponseBodySize = maxProviderResponseBodySize
	config.CheckAndSetDefaults()
	return config
}

func (a *account) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic, schemas.Azure, catalog.ProviderChutes}, nil
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
