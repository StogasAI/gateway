package stogas

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	infisical "github.com/infisical/go-sdk"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

const (
	defaultHost               = "127.0.0.1"
	defaultPort               = "5185"
	defaultMaxRequestBodyMiB  = 16
	defaultInfisicalSiteURL   = "https://secrets.stogas.ai"
	defaultFleetAPIURLLocal   = "http://127.0.0.1:5184/api/fleet"
	defaultFleetAPIURLStaging = "https://staging.stogas.ai/api/fleet"
	defaultFleetAPIURLProd    = "https://stogas.ai/api/fleet"
	defaultConfidentialRegion = "global"

	confidentialEntropyTimeout    = 10 * time.Second
	confidentialHeartbeatInterval = 60 * time.Second
	confidentialQuoteRefresh      = 10 * time.Second
	confidentialReadinessInterval = 60 * time.Second

	defaultDatabasePoolMaxConns     int32 = 32
	defaultDatabasePoolMinConns     int32 = 4
	defaultDatabasePoolMinIdleConns int32 = 4
	defaultDatabaseQueryExecMode          = "cache_statement"
)

var confidentialRuntimeSecretNames = []string{
	"AUTH_SECRET",
	"DATABASE_SCHEMA",
	"DATABASE_URL",
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
}

type Config struct {
	AllowPrivateProviderNetwork bool
	AuthSecret                  string
	Confidential                ConfidentialConfig
	DatabasePool                billing.DatabasePoolConfig
	DatabaseSchema              string
	DatabaseURL                 string
	Host                        string
	LogLevel                    string
	LogOutputStyle              string
	MaxRequestBodyMiB           int
	AnthropicAPIKey             string
	AnthropicBaseURL            string
	OpenAIAPIKey                string
	OpenAIBaseURL               string
	Port                        string
	TinybirdHost                string
	TinybirdToken               string
}

type ConfidentialConfig struct {
	AcceptedCertSHA256 []string
	AccessClientID     string
	AccessClientSecret string
	ActiveCertSHA256   string
	AttesterMode       string
	CertExpiresAt      time.Time
	ControlAllowHTTP   bool
	ControlURL         string
	EndpointAddress    string
	EndpointPort       int
	Enabled            bool
	EntropyTimeout     time.Duration
	Environment        string
	HeartbeatInterval  time.Duration
	QuoteRefresh       time.Duration
	ReadinessInterval  time.Duration
	RequestSecrets     bool
}

func LoadFromEnv() (Config, error) {
	if loadRuntimeEnvironment() == "local" {
		loadInfisicalRuntimeSecrets()
	}
	databasePool, err := loadDatabasePoolConfig()
	if err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_ATTESTER_MODE")) != "" {
		return Config{}, fmt.Errorf("STOGAS_CONFIDENTIAL_ATTESTER_MODE is not supported; attester mode is derived from the gateway boot path")
	}
	if err := rejectUnsupportedConfidentialKnobs(); err != nil {
		return Config{}, err
	}
	if err := rejectUnsupportedConfidentialHostOverrides(); err != nil {
		return Config{}, err
	}

	config := Config{
		AllowPrivateProviderNetwork: os.Getenv("STOGAS_ALLOW_PRIVATE_PROVIDER_NETWORK") == "true",
		AuthSecret:                  strings.TrimSpace(os.Getenv("AUTH_SECRET")),
		Confidential:                loadConfidentialConfigFromEnv(),
		DatabasePool:                databasePool,
		DatabaseSchema:              strings.TrimSpace(os.Getenv("DATABASE_SCHEMA")),
		DatabaseURL:                 strings.TrimSpace(os.Getenv("DATABASE_URL")),
		Host:                        defaultHost,
		LogLevel:                    string(schemas.LogLevelInfo),
		LogOutputStyle:              string(schemas.LoggerOutputTypeJSON),
		MaxRequestBodyMiB:           defaultMaxRequestBodyMiB,
		AnthropicAPIKey:             strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")),
		AnthropicBaseURL:            strings.TrimSpace(os.Getenv("ANTHROPIC_BASE_URL")),
		OpenAIAPIKey:                strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		OpenAIBaseURL:               strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")),
		Port:                        defaultPort,
		TinybirdHost:                strings.TrimSpace(os.Getenv("TB_HOST_URL")),
		TinybirdToken:               strings.TrimSpace(os.Getenv("TB_GATEWAY_REQUESTS_TOKEN")),
	}

	if config.Confidential.RequestSecrets {
		if err := config.Confidential.Validate(); err != nil {
			return Config{}, err
		}
	} else if err := config.Validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func loadConfidentialConfigFromEnv() ConfidentialConfig {
	environment := loadRuntimeEnvironment()
	confidentialDeployment := environment == "staging" || environment == "production"
	requestSecrets := confidentialDeployment || os.Getenv("STOGAS_CONFIDENTIAL_REQUEST_SECRETS") == "true"
	activeCertSHA256 := strings.ToLower(strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256")))
	acceptedCertSHA256 := splitCSV(os.Getenv("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256"))
	certExpiresAt := time.Time{}
	if raw := strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT")); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			certExpiresAt = parsed.UTC()
		}
	}
	controlURL := fleetAPIURLForEnvironment(environment, requestSecrets, activeCertSHA256, acceptedCertSHA256)
	config := ConfidentialConfig{
		AcceptedCertSHA256: acceptedCertSHA256,
		AccessClientID:     strings.TrimSpace(os.Getenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID")),
		AccessClientSecret: strings.TrimSpace(os.Getenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET")),
		ActiveCertSHA256:   activeCertSHA256,
		CertExpiresAt:      certExpiresAt,
		ControlAllowHTTP:   environment == "local" || os.Getenv("STOGAS_CONFIDENTIAL_CONTROL_ALLOW_INSECURE_LOCAL") == "true",
		ControlURL:         controlURL,
		EndpointAddress:    strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_ENDPOINT_ADDRESS")),
		EndpointPort:       envInt("STOGAS_CONFIDENTIAL_ENDPOINT_PORT", 0),
		Enabled:            confidentialDeployment || os.Getenv("STOGAS_CONFIDENTIAL_ENABLED") == "true",
		EntropyTimeout:     confidentialEntropyTimeout,
		Environment:        environment,
		HeartbeatInterval:  confidentialHeartbeatInterval,
		QuoteRefresh:       confidentialQuoteRefresh,
		ReadinessInterval:  confidentialReadinessInterval,
		RequestSecrets:     requestSecrets,
	}
	config.AttesterMode = config.DerivedAttesterMode()
	return config
}

func loadRuntimeEnvironment() string {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("STOGAS_ENVIRONMENT")))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(os.Getenv("NODE_ENV")))
	}
	switch value {
	case "local", "testing", "test":
		return "local"
	case "staging":
		return "staging"
	case "production", "prod":
		return "production"
	default:
		return "local"
	}
}

func defaultFleetAPIURLForEnvironment(environment string) string {
	switch environment {
	case "staging":
		return defaultFleetAPIURLStaging
	case "production":
		return defaultFleetAPIURLProd
	default:
		return ""
	}
}

func fleetAPIURLForEnvironment(environment string, requestSecrets bool, activeCertSHA256 string, acceptedCertSHA256 []string) string {
	if environment == "local" {
		if override := strings.TrimSpace(os.Getenv("STOGAS_FLEET_API_URL")); override != "" {
			return override
		}
		if requestSecrets || (strings.TrimSpace(activeCertSHA256) == "" && len(acceptedCertSHA256) == 0) {
			return defaultFleetAPIURLLocal
		}
		return ""
	}
	return defaultFleetAPIURLForEnvironment(environment)
}

func rejectUnsupportedConfidentialHostOverrides() error {
	environment := loadRuntimeEnvironment()
	if strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_CONTROL_URL")) != "" {
		return fmt.Errorf("STOGAS_CONFIDENTIAL_CONTROL_URL is not supported; fleet API URL is derived from STOGAS_ENVIRONMENT")
	}
	if environment != "staging" && environment != "production" {
		return nil
	}
	if strings.TrimSpace(os.Getenv("STOGAS_FLEET_API_URL")) != "" {
		return fmt.Errorf("STOGAS_FLEET_API_URL is only supported for local testing")
	}
	for _, name := range []string{
		"ANTHROPIC_API_KEY",
		"AUTH_SECRET",
		"DATABASE_SCHEMA",
		"DATABASE_URL",
		"INFISICAL_PROJECT_ID",
		"INFISICAL_SITE_URL",
		"INFISICAL_SKIP",
		"INFISICAL_SKIP_DATABASE_URL",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET",
		"OPENAI_API_KEY",
		"TB_GATEWAY_REQUESTS_TOKEN",
		"TB_HOST_URL",
	} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return fmt.Errorf("%s is not supported in staging/prod confidential guests; runtime secrets are released by Control after attestation", name)
		}
	}
	for _, name := range []string{
		"STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256",
		"STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256",
		"STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT",
		"STOGAS_CONFIDENTIAL_CONTROL_ALLOW_INSECURE_LOCAL",
		"STOGAS_CONFIDENTIAL_ENABLED",
		"STOGAS_CONFIDENTIAL_ENDPOINT_ADDRESS",
		"STOGAS_CONFIDENTIAL_ENDPOINT_PORT",
		"STOGAS_CONFIDENTIAL_REQUEST_SECRETS",
	} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return fmt.Errorf("%s is not supported in staging/prod confidential guests; only STOGAS_ENVIRONMENT and Cloudflare Access service credentials are accepted", name)
		}
	}
	return nil
}

func rejectUnsupportedConfidentialKnobs() error {
	for _, name := range []string{
		"STOGAS_IGVM_MODE",
		"STOGAS_CONFIDENTIAL_ENTROPY_TIMEOUT_SECONDS",
		"STOGAS_CONFIDENTIAL_HEARTBEAT_SECONDS",
		"STOGAS_CONFIDENTIAL_QUOTE_REFRESH_SECONDS",
		"STOGAS_CONFIDENTIAL_READINESS_SECONDS",
		"STOGAS_CONFIDENTIAL_RELEASE_ENCRYPTOR",
	} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return fmt.Errorf("%s is not supported; confidential timing, attestation, and release behavior are fixed by the IGVM and Control policy", name)
		}
	}
	return nil
}

func loadInfisicalRuntimeSecrets() {
	if os.Getenv("INFISICAL_SKIP") == "true" {
		return
	}

	infisicalClientID := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID")
	infisicalClientSecret := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")
	projectID := os.Getenv("INFISICAL_PROJECT_ID")
	if infisicalClientID == "" || infisicalClientSecret == "" || projectID == "" {
		return
	}

	siteURL := strings.TrimSpace(os.Getenv("INFISICAL_SITE_URL"))
	if siteURL == "" {
		siteURL = defaultInfisicalSiteURL
	}

	fmt.Printf("[stogas] Connecting to Infisical (%s)...\n", siteURL)
	client := infisical.NewInfisicalClient(context.Background(), infisical.Config{SiteUrl: siteURL})
	if _, err := client.Auth().UniversalAuthLogin(infisicalClientID, infisicalClientSecret); err != nil {
		fmt.Printf("[stogas] Warning: Failed to authenticate with Infisical: %v\n", err)
		return
	}

	required := []string{"AUTH_SECRET", "DATABASE_SCHEMA", "DATABASE_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"}
	if os.Getenv("INFISICAL_SKIP_DATABASE_URL") == "true" || os.Getenv("DATABASE_URL") != "" {
		required = []string{"AUTH_SECRET", "DATABASE_SCHEMA", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"}
	}
	for _, secretName := range required {
		resolveInfisicalSecret(client, projectID, "/gateway", secretName, true)
	}
	for _, secretName := range []string{"TB_GATEWAY_REQUESTS_TOKEN", "TB_HOST_URL"} {
		resolveInfisicalSecret(client, projectID, "/gateway", secretName, false)
	}
}

func resolveInfisicalSecret(client infisical.InfisicalClientInterface, projectID string, secretPath string, secretName string, required bool) {
	if strings.TrimSpace(os.Getenv(secretName)) != "" {
		return
	}

	var lastErr error
	for _, environment := range []string{"prod", "staging"} {
		res, err := client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
			SecretKey:              secretName,
			Environment:            environment,
			ProjectID:              projectID,
			SecretPath:             secretPath,
			ExpandSecretReferences: true,
		})
		if err != nil {
			lastErr = err
			continue
		}
		if strings.TrimSpace(res.SecretValue) == "" {
			lastErr = fmt.Errorf("empty secret value")
			continue
		}
		fmt.Printf("[stogas] Infisical resolved %s from %s %s\n", secretName, environment, secretPath)
		os.Setenv(secretName, res.SecretValue)
		return
	}

	if required {
		fmt.Printf("[stogas] Warning: Failed to retrieve required secret %s: %v\n", secretName, lastErr)
	}
}

func (c Config) Validate() error {
	if c.AuthSecret == "" {
		return fmt.Errorf("AUTH_SECRET is required")
	}
	if len(c.AuthSecret) < 32 {
		return fmt.Errorf("AUTH_SECRET must be at least 32 characters (got %d characters)", len(c.AuthSecret))
	}
	if err := c.DatabasePool.Validate(); err != nil {
		return err
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if c.DatabaseSchema == "" {
		return fmt.Errorf("DATABASE_SCHEMA is required")
	}
	if err := billing.ValidateDatabaseSchema(c.DatabaseSchema); err != nil {
		return err
	}
	if !c.Confidential.RequestSecrets && c.OpenAIAPIKey == "" {
		return fmt.Errorf("OPENAI_API_KEY is required")
	}
	if !c.Confidential.RequestSecrets && c.AnthropicAPIKey == "" {
		return fmt.Errorf("ANTHROPIC_API_KEY is required")
	}
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("host is required")
	}
	if strings.TrimSpace(c.Port) == "" {
		return fmt.Errorf("port is required")
	}
	if c.MaxRequestBodyMiB <= 0 {
		return fmt.Errorf("max request body size must be positive")
	}
	if err := c.Confidential.Validate(); err != nil {
		return err
	}
	return nil
}

type ConfidentialSecretLookup interface {
	Get(name string) (secretstore.Secret, bool)
}

func ApplyConfidentialRuntimeSecrets(config *Config, secrets ConfidentialSecretLookup) error {
	if config == nil || !config.Confidential.RequestSecrets {
		return nil
	}
	if secrets == nil {
		return fmt.Errorf("confidential secret store is required")
	}

	for _, name := range confidentialRuntimeSecretNames {
		secret, ok := secrets.Get(name)
		if !ok || len(secret.Value) == 0 {
			return fmt.Errorf("confidential secret %s is required", name)
		}
		if err := os.Setenv(name, string(secret.Value)); err != nil {
			return fmt.Errorf("failed to install confidential secret %s: %w", name, err)
		}
	}
	for _, name := range []string{"TB_GATEWAY_REQUESTS_TOKEN", "TB_HOST_URL"} {
		if secret, ok := secrets.Get(name); ok && len(secret.Value) > 0 {
			if err := os.Setenv(name, string(secret.Value)); err != nil {
				return fmt.Errorf("failed to install confidential secret %s: %w", name, err)
			}
		}
	}

	applyRuntimeSecretsFromEnv(config)
	return validateProviderRuntimeSecretsReady(*config)
}

func validateProviderRuntimeSecretsReady(config Config) error {
	if strings.TrimSpace(config.OpenAIAPIKey) == "" {
		return fmt.Errorf("OPENAI_API_KEY is required before provider runtime starts")
	}
	if strings.TrimSpace(config.AnthropicAPIKey) == "" {
		return fmt.Errorf("ANTHROPIC_API_KEY is required before provider runtime starts")
	}
	return nil
}

func applyRuntimeSecretsFromEnv(config *Config) {
	config.AuthSecret = strings.TrimSpace(os.Getenv("AUTH_SECRET"))
	config.DatabaseSchema = strings.TrimSpace(os.Getenv("DATABASE_SCHEMA"))
	config.DatabaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	config.OpenAIAPIKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	config.AnthropicAPIKey = strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	config.TinybirdHost = strings.TrimSpace(os.Getenv("TB_HOST_URL"))
	config.TinybirdToken = strings.TrimSpace(os.Getenv("TB_GATEWAY_REQUESTS_TOKEN"))
}

func (c ConfidentialConfig) Validate() error {
	if !c.Enabled {
		if c.RequestSecrets {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_ENABLED=true is required before secret release")
		}
		return nil
	}
	attesterMode := c.AttesterMode
	if attesterMode == "" {
		attesterMode = c.DerivedAttesterMode()
	}
	if attesterMode == "" {
		return fmt.Errorf("confidential attester mode could not be derived")
	}
	switch attesterMode {
	case "mock", "igvm-native", "sev-snp":
	default:
		return fmt.Errorf("unsupported confidential attester mode %q", attesterMode)
	}
	if c.Environment != "local" && c.RequestSecrets && attesterMode != "sev-snp" {
		return fmt.Errorf("confidential secret release requires sev-snp attestation")
	}
	hasConfiguredCertificate := strings.TrimSpace(c.ActiveCertSHA256) != "" || len(c.AcceptedCertSHA256) > 0
	if hasConfiguredCertificate {
		if err := validateHashHex("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", c.ActiveCertSHA256); err != nil {
			return err
		}
		if len(c.AcceptedCertSHA256) == 0 {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256 is required when STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256 is configured")
		}
		activeAccepted := false
		for _, hash := range c.AcceptedCertSHA256 {
			if err := validateHashHex("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256", hash); err != nil {
				return err
			}
			if hash == c.ActiveCertSHA256 {
				activeAccepted = true
			}
		}
		if !activeAccepted {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256 must include STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256")
		}
	}
	if c.QuoteRefresh <= 0 {
		return fmt.Errorf("STOGAS_CONFIDENTIAL_QUOTE_REFRESH_SECONDS must be positive")
	}
	if c.EntropyTimeout < 0 {
		return fmt.Errorf("STOGAS_CONFIDENTIAL_ENTROPY_TIMEOUT_SECONDS must not be negative")
	}
	if c.ControlConfigured() {
		if strings.TrimSpace(c.ControlURL) == "" {
			return fmt.Errorf("fleet API URL is required when Control heartbeats are configured")
		}
		if err := validateControlAccess(c); err != nil {
			return err
		}
		if hasConfiguredCertificate && c.CertExpiresAt.IsZero() {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT is required when Control heartbeats are configured")
		}
		if c.HeartbeatInterval <= 0 {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_HEARTBEAT_SECONDS must be positive")
		}
	}
	if c.ReadinessConfigured() {
		if !c.ControlConfigured() {
			return fmt.Errorf("Control heartbeats must be configured before readiness observations")
		}
		if strings.TrimSpace(c.EndpointAddress) == "" {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_ENDPOINT_ADDRESS is required when readiness observations are configured")
		}
		if c.EndpointPort < 1 || c.EndpointPort > 65535 {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_ENDPOINT_PORT must be between 1 and 65535")
		}
		if c.ReadinessInterval <= 0 {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_READINESS_SECONDS must be positive")
		}
	}
	if c.RequestSecrets && !c.ControlConfigured() {
		return fmt.Errorf("Control heartbeats must be configured before secret release")
	}
	return nil
}

func (c ConfidentialConfig) DerivedAttesterMode() string {
	if !c.Enabled {
		return ""
	}
	if c.Environment == "local" {
		return "igvm-native"
	}
	if c.ControlConfigured() || c.RequestSecrets {
		return "sev-snp"
	}
	return "igvm-native"
}

func (c ConfidentialConfig) ControlConfigured() bool {
	return strings.TrimSpace(c.ControlURL) != ""
}

func (c ConfidentialConfig) ReadinessConfigured() bool {
	return strings.TrimSpace(c.EndpointAddress) != "" || c.EndpointPort != 0
}

func validateControlAccess(c ConfidentialConfig) error {
	parsed, err := url.Parse(strings.TrimSpace(c.ControlURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("fleet API URL must be absolute")
	}
	if c.ControlAllowHTTP && parsed.Scheme == "http" {
		return nil
	}
	if strings.TrimSpace(c.AccessClientID) == "" {
		return fmt.Errorf("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID is required for confidential Control access")
	}
	if strings.TrimSpace(c.AccessClientSecret) == "" {
		return fmt.Errorf("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET is required for confidential Control access")
	}
	return nil
}

func loadDatabasePoolConfig() (billing.DatabasePoolConfig, error) {
	maxConns, err := envInt32("STOGAS_DB_POOL_MAX_CONNS", defaultDatabasePoolMaxConns)
	if err != nil {
		return billing.DatabasePoolConfig{}, err
	}
	minConns, err := envInt32("STOGAS_DB_POOL_MIN_CONNS", defaultDatabasePoolMinConns)
	if err != nil {
		return billing.DatabasePoolConfig{}, err
	}
	minIdleConns, err := envInt32("STOGAS_DB_POOL_MIN_IDLE_CONNS", defaultDatabasePoolMinIdleConns)
	if err != nil {
		return billing.DatabasePoolConfig{}, err
	}

	queryExecMode := strings.TrimSpace(os.Getenv("STOGAS_DB_QUERY_EXEC_MODE"))
	if queryExecMode == "" {
		queryExecMode = defaultDatabaseQueryExecMode
	}

	return billing.DatabasePoolConfig{
		MaxConns:      maxConns,
		MinConns:      minConns,
		MinIdleConns:  minIdleConns,
		QueryExecMode: queryExecMode,
	}, nil
}

func envInt32(name string, defaultValue int32) (int32, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be a 32-bit integer", name)
	}
	return int32(value), nil
}

func envInt(name string, defaultValue int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return defaultValue
	}
	return value
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.ToLower(strings.TrimSpace(part))
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func validateHashHex(name string, value string) error {
	if len(value) != 64 {
		return fmt.Errorf("%s must be 32-byte lowercase hex", name)
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return fmt.Errorf("%s must be 32-byte lowercase hex", name)
		}
	}
	return nil
}

func validateChipID(name string, value string) error {
	if len(value) != 128 {
		return fmt.Errorf("%s must be 64-byte lowercase hex", name)
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return fmt.Errorf("%s must be 64-byte lowercase hex", name)
		}
	}
	return nil
}

func envDurationSeconds(name string, defaultValue int64) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return time.Duration(defaultValue) * time.Second
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}
