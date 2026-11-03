package stogas

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"github.com/maximhq/bifrost/transports/stogas/googleauth"
	"github.com/maximhq/bifrost/transports/stogas/providerio"
	"github.com/valyala/fasthttp"
)

const (
	chutesProviderKeyID = "stogas-chutes"
)

type Runtime struct {
	client       *bifrost.Bifrost
	billing      *billing.Service
	chutesE2EE   *chutese2ee.Transport
	azureTokens  *azureauth.Cache
	azureChecks  *AzureChecks
	googleTokens *googleauth.Cache
	byokChecks   *byokChecker
	cancel       context.CancelFunc
}

// NewRuntime starts the providers and billing. nodeID names the boot that owns
// the holds this runtime creates, or is empty outside a confidential guest.
func NewRuntime(ctx context.Context, config Config, nodeID string) (*Runtime, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := validateProviderRuntimeSecretsReady(config); err != nil {
		return nil, err
	}

	byokChecks, err := newByokChecker(config)
	if err != nil {
		return nil, err
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	chutesTransport, err := newChutesE2EETransport(config)
	if err != nil {
		cancel()
		return nil, err
	}
	billingService, err := billing.NewService(
		runtimeCtx,
		config.DatabaseURL,
		config.DatabaseSchema,
		config.APIKeyPepper,
		config.BYOKEncryptionSecret,
		config.InferenceTokenPublicKey,
		nodeID,
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
		Logger: providerLibraryLogger{emit: writeOperationalLog},
		Tracer: newProviderAttemptTracer(schemas.DefaultTracer()),
	})
	if err != nil {
		billingService.Close()
		chutesTransport.Close()
		cancel()
		return nil, err
	}

	azureTokens := azureauth.New(runtimeCtx)
	googleTokens := googleauth.New(runtimeCtx, confidentialProduction(config))
	byokChecks.google = googleTokens
	byokChecks.azure = azureTokens
	return &Runtime{
		client:       client,
		billing:      billingService,
		chutesE2EE:   chutesTransport,
		azureTokens:  azureTokens,
		azureChecks:  NewAzureChecks(runtimeCtx, billingService, azureTokens),
		googleTokens: googleTokens,
		byokChecks:   byokChecks,
		cancel:       cancel,
	}, nil
}

func (r *Runtime) ApplyUpstreamCredentials(ctx *schemas.BifrostContext, state *State) error {
	if r == nil {
		return billing.ErrGatewayUnavailable
	}
	return applyUpstreamCredentials(ctx, state, r.azureTokens, r.googleTokens, r.azureChecks)
}

// StopAzureTarget stops a request's Azure target in the background after its reply named served,
// another model version than the target's, so later requests move on without calling it.
func (r *Runtime) StopAzureTarget(authorization *billing.Authorization, served string) {
	if r == nil || r.azureChecks == nil || authorization == nil || authorization.AzureBinding == nil {
		return
	}
	r.azureChecks.Stop(azureCheckTarget{ByokID: authorization.UpstreamByok, BindingID: authorization.AzureBinding.ID}, served)
}

// RecheckAzureTarget checks a request's Azure account in the background after a reply showed that
// the target's deployment is gone or retired.
func (r *Runtime) RecheckAzureTarget(authorization *billing.Authorization) {
	if r == nil || r.azureChecks == nil || authorization == nil || authorization.AzureBinding == nil ||
		!azureAccountIDPattern.MatchString(authorization.AzureAccountID) {
		return
	}
	credential, err := parseAzureByokCredential(authorization.UpstreamByokSecret)
	if err != nil {
		return
	}
	r.azureChecks.Recheck(azureCheckTarget{
		ByokID:     authorization.UpstreamByok,
		BindingID:  authorization.AzureBinding.ID,
		AccountID:  authorization.AzureAccountID,
		VerifiedAt: authorization.AzureVerifiedAt,
		Credential: azureauth.Credential{TenantID: credential.TenantID, ClientID: credential.ClientID, Secret: credential.ClientSecret},
	})
}

func (r *Runtime) AzureAuthDiagnostics() azureauth.Diagnostics {
	if r == nil {
		return azureauth.Diagnostics{}
	}
	return r.azureTokens.Diagnostics()
}

func (r *Runtime) GoogleAuthDiagnostics() googleauth.Diagnostics {
	if r == nil {
		return googleauth.Diagnostics{}
	}
	return r.googleTokens.Diagnostics()
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

func (r *Runtime) ParseByokCheckGrant(raw string) (*billing.ByokCheckGrant, error) {
	if r == nil || r.billing == nil {
		return nil, billing.ErrByokCheckGrant
	}
	return r.billing.ParseByokCheckGrant(raw)
}

func (r *Runtime) ParsePolicyCheckGrant(raw string) (*billing.PolicyCheckGrant, error) {
	if r == nil || r.billing == nil {
		return nil, billing.ErrPolicyCheckGrant
	}
	return r.billing.ParsePolicyCheckGrant(raw)
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
	if r.azureTokens != nil {
		r.azureTokens.Close()
	}
	if r.googleTokens != nil {
		r.googleTokens.Close()
	}
	if r.cancel != nil {
		r.cancel()
	}
}

type account struct {
	keys            map[schemas.ModelProvider]schemas.Key
	providerConfigs map[schemas.ModelProvider]schemas.ProviderConfig
}

// confidentialProduction reports whether the gateway runs in a confidential
// guest outside local development, where provider TLS must be post-quantum.
func confidentialProduction(config Config) bool {
	return config.Confidential.Enabled && config.Confidential.Environment != "local"
}

// cloudClaudeConfig serves Claude on AWS or Google Cloud through core's
// Anthropic provider. Each request names its own URL, so the base URL cannot
// resolve: a request without one never reaches Anthropic with a cloud credential.
func cloudClaudeConfig(config Config) schemas.ProviderConfig {
	providerConfig := newProviderConfig("https://upstream-url-required.invalid", config.AllowPrivateProviderNetwork, false)
	providerConfig.CustomProviderConfig = &schemas.CustomProviderConfig{
		BaseProviderType: schemas.Anthropic,
		AllowedRequests: &schemas.AllowedRequests{
			ChatCompletion:       true,
			ChatCompletionStream: true,
			Responses:            true,
			ResponsesStream:      true,
		},
	}
	return providerConfig
}

func newAccount(config Config, chutesTransport fasthttp.RoundTripper) *account {
	requirePostQuantumTLS := confidentialProduction(config)
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
	// Bedrock's runtime endpoint offers only classical key exchange, so AWS
	// requires TLS 1.3 as Azure does. Every Google endpoint offers X25519MLKEM768.
	awsConfig := cloudClaudeConfig(config)
	awsConfig.NetworkConfig.RequireTLS13 = requirePostQuantumTLS
	googleCloudConfig := cloudClaudeConfig(config)
	googleCloudConfig.NetworkConfig.RequirePostQuantumTLS = requirePostQuantumTLS

	return &account{
		keys: map[schemas.ModelProvider]schemas.Key{
			catalog.ProviderChutes: {
				ID:      chutesProviderKeyID,
				Name:    chutesProviderKeyID,
				Value:   literalSecret(config.ChutesAPIKey),
				Models:  schemas.WhiteList{"*"},
				Weight:  1,
				Enabled: schemas.Ptr(true),
			},
		},
		providerConfigs: map[schemas.ModelProvider]schemas.ProviderConfig{
			schemas.OpenAI:              openAIConfig,
			schemas.Anthropic:           anthropicConfig,
			schemas.Azure:               azureConfig,
			catalog.ProviderChutes:      chutesConfig,
			catalog.ProviderAWS:         awsConfig,
			catalog.ProviderGoogleCloud: googleCloudConfig,
		},
	}
}

func newChutesE2EETransport(config Config) (*chutese2ee.Transport, error) {
	apiBaseURL, err := chutesE2EEAPIBaseURL(config.ChutesBaseURL)
	if err != nil {
		return nil, err
	}
	return chutese2ee.New(chutese2ee.Options{
		APIKey:                  config.ChutesAPIKey,
		APIBaseURL:              apiBaseURL,
		RequireProductionOrigin: confidentialProduction(config),
		RequestTimeout:          billing.GatewayRequestLifetime,
		ResolveModel: func(upstreamModel string) (chutese2ee.ModelTarget, bool) {
			deployment, ok := catalog.DeploymentForUpstreamModel(catalog.ProviderChutes, upstreamModel, catalog.RouteChat)
			if !ok || deployment.Upstream.ChuteID == "" || deployment.Upstream.GPUCount == nil {
				return chutese2ee.ModelTarget{}, false
			}
			return chutese2ee.ModelTarget{
				ChuteID:  deployment.Upstream.ChuteID,
				GPUCount: *deployment.Upstream.GPUCount,
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

// ProviderWorkers is how many calls core runs at once for each provider. A
// unary call holds its worker until the provider answers and a stream until
// its response starts; further calls wait in core's queue. One worker per
// provider connection keeps them from waiting while connections are free, and
// an idle worker costs an 8-KiB stack.
const ProviderWorkers = schemas.DefaultMaxConnsPerHost

func newProviderConfig(baseURL string, allowPrivateNetwork, requirePostQuantumTLS bool) schemas.ProviderConfig {
	config := schemas.ProviderConfig{
		ConcurrencyAndBufferSize: schemas.ConcurrencyAndBufferSize{
			Concurrency: ProviderWorkers,
			BufferSize:  schemas.DefaultBufferSize,
		},
		NetworkConfig: schemas.DefaultNetworkConfig,
	}
	config.NetworkConfig.DefaultRequestTimeoutInSeconds = int(billing.GatewayRequestLifetime.Seconds())
	// Core never retries, walks to another key or rewrites a refused body. The
	// gateway makes each retry and fallback itself, so every provider call is an
	// attempt in the request log and carries the body the gateway prepared.
	config.NetworkConfig.MaxRetries = 0
	config.NetworkConfig.SingleAttempt = true
	if baseURL != "" {
		config.NetworkConfig.BaseURL = baseURL
	}
	config.NetworkConfig.AllowPrivateNetwork = allowPrivateNetwork
	config.NetworkConfig.RequirePostQuantumTLS = requirePostQuantumTLS
	config.NetworkConfig.MaxResponseBodySize = maxProviderResponseBodySize
	config.NetworkConfig.Transport = providerio.NewTransport(maxProviderResponseBodySize, false)
	config.CheckAndSetDefaults()
	return config
}

func (a *account) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic, schemas.Azure, catalog.ProviderChutes, catalog.ProviderAWS, catalog.ProviderGoogleCloud}, nil
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
