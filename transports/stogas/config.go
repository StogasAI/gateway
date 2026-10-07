package stogas

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

const (
	defaultHost                 = "127.0.0.1"
	defaultPort                 = "5185"
	defaultPrivateReadinessPort = "5186"
	defaultMaxRequestBodyMiB    = 128
	maxRequestBodyMiB           = 128
	maxProviderResponseBodySize = 64 << 20
	defaultChutesBaseURL        = "https://llm.chutes.ai"
	defaultFleetAPIURLLocal     = "http://127.0.0.1:5184/api/fleet"
	defaultFleetAPIURLStaging   = "https://staging.stogas.ai/api/fleet"
	defaultFleetAPIURLProd      = "https://stogas.ai/api/fleet"

	confidentialEntropyTimeout = 10 * time.Second

	defaultDatabasePoolMaxConns     int32 = 6
	defaultDatabasePoolMinConns     int32 = 1
	defaultDatabasePoolMinIdleConns int32 = 1
	defaultDatabaseQueryExecMode          = "cache_statement"
)

var confidentialRuntimeSecretNames = []string{
	"API_KEY_PEPPER",
	"BYOK_ENCRYPTION_SECRET",
	"DATABASE_SCHEMA",
	"DATABASE_URL",
	"INFERENCE_TOKEN_PUBLIC_KEY",
	"CHUTES_API_KEY",
	"REQUEST_LOG_QUEUE_TOKEN",
	"TB_HOST_URL",
	"TB_GATEWAY_REQUESTS_TOKEN",
}

type Config struct {
	AllowPrivateProviderNetwork bool
	APIKeyPepper                string
	BYOKEncryptionSecret        string
	Confidential                ConfidentialConfig
	DatabasePool                billing.DatabasePoolConfig
	DatabaseSchema              string
	DatabaseURL                 string
	DiagnosticsClientSPKISHA256 string
	DrainClientSPKISHA256       string
	Host                        string
	InferenceTokenPublicKey     string
	LogLevel                    string
	LogOutputStyle              string
	MaxRequestBodyMiB           int
	AnthropicBaseURL            string
	ChutesAPIKey                string
	ChutesBaseURL               string
	OpenAIBaseURL               string
	Port                        string
	PrivateReadinessPort        string
	RequestLogQueueToken        string
	TinybirdHost                string
	TinybirdToken               string
}

type ConfidentialConfig struct {
	InstanceID         string
	AccessClientID     string
	AccessClientSecret string
	ControlURL         string
	ControlAllowHTTP   bool
	Enabled            bool
	EntropyTimeout     time.Duration
	Environment        string
}

func LoadFromEnv() (Config, error) {
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
		APIKeyPepper:                strings.TrimSpace(os.Getenv("API_KEY_PEPPER")),
		BYOKEncryptionSecret:        strings.TrimSpace(os.Getenv("BYOK_ENCRYPTION_SECRET")),
		Confidential:                loadConfidentialConfigFromEnv(),
		DatabasePool:                databasePool,
		DatabaseSchema:              strings.TrimSpace(os.Getenv("DATABASE_SCHEMA")),
		DatabaseURL:                 strings.TrimSpace(os.Getenv("DATABASE_URL")),
		Host:                        defaultHost,
		InferenceTokenPublicKey:     strings.TrimSpace(os.Getenv("INFERENCE_TOKEN_PUBLIC_KEY")),
		LogLevel:                    string(schemas.LogLevelInfo),
		LogOutputStyle:              string(schemas.LoggerOutputTypeJSON),
		MaxRequestBodyMiB:           defaultMaxRequestBodyMiB,
		AnthropicBaseURL:            strings.TrimSpace(os.Getenv("ANTHROPIC_BASE_URL")),
		ChutesAPIKey:                strings.TrimSpace(os.Getenv("CHUTES_API_KEY")),
		ChutesBaseURL:               strings.TrimSpace(os.Getenv("CHUTES_BASE_URL")),
		OpenAIBaseURL:               strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")),
		Port:                        defaultPort,
		PrivateReadinessPort:        defaultPrivateReadinessPort,
		RequestLogQueueToken:        strings.TrimSpace(os.Getenv("REQUEST_LOG_QUEUE_TOKEN")),
		TinybirdHost:                strings.TrimSpace(os.Getenv("TB_HOST_URL")),
		TinybirdToken:               strings.TrimSpace(os.Getenv("TB_GATEWAY_REQUESTS_TOKEN")),
	}

	if config.Confidential.ControlConfigured() {
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
	enabled := environment == "staging" || environment == "production"
	return ConfidentialConfig{
		InstanceID:         strings.TrimSpace(os.Getenv("STOGAS_INSTANCE_ID")),
		AccessClientID:     strings.TrimSpace(os.Getenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID")),
		AccessClientSecret: strings.TrimSpace(os.Getenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET")),
		ControlURL:         fleetAPIURLForEnvironment(environment, enabled),
		Enabled:            enabled, EntropyTimeout: confidentialEntropyTimeout, Environment: environment,
	}
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

func fleetAPIURLForEnvironment(environment string, confidentialEnabled bool) string {
	if environment == "local" {
		if !confidentialEnabled {
			return ""
		}
		if override := strings.TrimSpace(os.Getenv("STOGAS_FLEET_API_URL")); override != "" {
			return override
		}
		return defaultFleetAPIURLLocal
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
		"API_KEY_PEPPER",
		"BYOK_ENCRYPTION_SECRET",
		"CHUTES_API_KEY",
		"INFERENCE_TOKEN_PUBLIC_KEY",
		"DATABASE_SCHEMA",
		"DATABASE_URL",
		"OPENAI_API_KEY",
		"REQUEST_LOG_QUEUE_TOKEN",
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
			return fmt.Errorf("%s is not supported in staging/prod confidential guests; only environment, instance ID and Cloudflare Access service credentials are accepted", name)
		}
	}
	return nil
}

func rejectUnsupportedConfidentialKnobs() error {
	for _, name := range []string{
		"STOGAS_CONFIDENTIAL_ENABLED",
		"STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256",
		"STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256",
		"STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT",
		"STOGAS_CONFIDENTIAL_CONTROL_ALLOW_INSECURE_LOCAL",
		"STOGAS_IGVM_MODE",
		"STOGAS_CONFIDENTIAL_ENTROPY_TIMEOUT_SECONDS",
		"STOGAS_CONFIDENTIAL_HEARTBEAT_SECONDS",
		"STOGAS_CONFIDENTIAL_ENDPOINT_ADDRESS",
		"STOGAS_CONFIDENTIAL_ENDPOINT_PORT",
		"STOGAS_CONFIDENTIAL_QUOTE_REFRESH_SECONDS",
		"STOGAS_CONFIDENTIAL_READINESS_SECONDS",
		"STOGAS_CONFIDENTIAL_RELEASE_ENCRYPTOR",
		"STOGAS_CONFIDENTIAL_REQUEST_SECRETS",
	} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return fmt.Errorf("%s is not supported; confidential timing, attestation, and release behavior are fixed by the IGVM and Control policy", name)
		}
	}
	return nil
}

func (c Config) Validate() error {
	if err := c.validateOperationalLogging(); err != nil {
		return err
	}
	if c.APIKeyPepper == "" {
		return fmt.Errorf("API_KEY_PEPPER is required")
	}
	if len(c.APIKeyPepper) < 32 {
		return fmt.Errorf("API_KEY_PEPPER must be at least 32 characters (got %d characters)", len(c.APIKeyPepper))
	}
	if len(c.BYOKEncryptionSecret) < 32 {
		return fmt.Errorf("BYOK_ENCRYPTION_SECRET must be at least 32 characters (got %d characters)", len(c.BYOKEncryptionSecret))
	}
	if c.InferenceTokenPublicKey == "" {
		return fmt.Errorf("INFERENCE_TOKEN_PUBLIC_KEY is required")
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
	if err := validateTinybirdConfig(
		c.TinybirdHost,
		c.TinybirdToken,
		c.Confidential.Environment == "local" && c.AllowPrivateProviderNetwork,
	); err != nil {
		return err
	}
	if !c.Confidential.ControlConfigured() && c.ChutesAPIKey == "" {
		return fmt.Errorf("CHUTES_API_KEY is required")
	}
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("host is required")
	}
	if strings.TrimSpace(c.Port) == "" {
		return fmt.Errorf("port is required")
	}
	if strings.TrimSpace(c.PrivateReadinessPort) == "" {
		return fmt.Errorf("private readiness port is required")
	}
	if c.MaxRequestBodyMiB <= 0 {
		return fmt.Errorf("max request body size must be positive")
	}
	if c.MaxRequestBodyMiB > maxRequestBodyMiB {
		return fmt.Errorf("max request body size cannot exceed %d MiB", maxRequestBodyMiB)
	}
	if err := c.Confidential.Validate(); err != nil {
		return err
	}
	return nil
}

func (c Config) validateOperationalLogging() error {
	switch schemas.LogLevel(c.LogLevel) {
	case schemas.LogLevelDebug, schemas.LogLevelInfo, schemas.LogLevelWarn, schemas.LogLevelError:
	default:
		return fmt.Errorf("unsupported log level")
	}
	switch schemas.LoggerOutputType(c.LogOutputStyle) {
	case schemas.LoggerOutputTypeJSON, schemas.LoggerOutputTypePretty:
	default:
		return fmt.Errorf("unsupported log output style")
	}
	if !c.Confidential.Enabled || c.Confidential.Environment == "local" {
		return nil
	}
	if schemas.LogLevel(c.LogLevel) == schemas.LogLevelDebug {
		return fmt.Errorf("debug logging is not permitted in a non-local confidential runtime")
	}
	if schemas.LoggerOutputType(c.LogOutputStyle) != schemas.LoggerOutputTypeJSON {
		return fmt.Errorf("JSON logging is required in a non-local confidential runtime")
	}
	return nil
}

type ConfidentialSecretLookup interface {
	Get(name string) (secretstore.Secret, bool)
}

func ApplyConfidentialRuntimeSecrets(config *Config, secrets ConfidentialSecretLookup) error {
	if config == nil || !config.Confidential.ControlConfigured() {
		return nil
	}
	if secrets == nil {
		return fmt.Errorf("confidential secret store is required")
	}
	if config.Confidential.Environment != "local" {
		secret, ok := secrets.Get("DIAGNOSTICS_CLIENT_SPKI_SHA256")
		if !ok || validateHashHex("DIAGNOSTICS_CLIENT_SPKI_SHA256", string(secret.Value)) != nil {
			return fmt.Errorf("confidential diagnostics client SPKI pin is required")
		}
		config.DiagnosticsClientSPKISHA256 = string(secret.Value)
		secret, ok = secrets.Get("DRAIN_CLIENT_SPKI_SHA256")
		if !ok || validateHashHex("DRAIN_CLIENT_SPKI_SHA256", string(secret.Value)) != nil || string(secret.Value) == config.DiagnosticsClientSPKISHA256 {
			return fmt.Errorf("a distinct confidential drain client SPKI pin is required")
		}
		config.DrainClientSPKISHA256 = string(secret.Value)
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

	applyRuntimeSecretsFromEnv(config)
	return validateProviderRuntimeSecretsReady(*config)
}

func validateProviderRuntimeSecretsReady(config Config) error {
	if len(strings.TrimSpace(config.BYOKEncryptionSecret)) < 32 {
		return fmt.Errorf("BYOK_ENCRYPTION_SECRET must be at least 32 characters before provider runtime starts")
	}
	if strings.TrimSpace(config.ChutesAPIKey) == "" {
		return fmt.Errorf("CHUTES_API_KEY is required before provider runtime starts")
	}
	return validateTinybirdConfig(
		config.TinybirdHost,
		config.TinybirdToken,
		config.Confidential.Environment == "local" && config.AllowPrivateProviderNetwork,
	)
}

func validateTinybirdConfig(host string, token string, allowInsecurePrivateNetwork bool) error {
	host = strings.TrimSpace(host)
	token = strings.TrimSpace(token)
	if host == "" && token == "" {
		return nil
	}
	if host == "" || token == "" {
		return fmt.Errorf("TB_HOST_URL and TB_GATEWAY_REQUESTS_TOKEN must be configured together")
	}
	if _, err := billing.NormalizeTinybirdHost(host, allowInsecurePrivateNetwork); err != nil {
		return fmt.Errorf("invalid TB_HOST_URL: %w", err)
	}
	return nil
}

func applyRuntimeSecretsFromEnv(config *Config) {
	config.APIKeyPepper = strings.TrimSpace(os.Getenv("API_KEY_PEPPER"))
	config.BYOKEncryptionSecret = strings.TrimSpace(os.Getenv("BYOK_ENCRYPTION_SECRET"))
	config.DatabaseSchema = strings.TrimSpace(os.Getenv("DATABASE_SCHEMA"))
	config.DatabaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	config.InferenceTokenPublicKey = strings.TrimSpace(os.Getenv("INFERENCE_TOKEN_PUBLIC_KEY"))
	config.ChutesAPIKey = strings.TrimSpace(os.Getenv("CHUTES_API_KEY"))
	config.RequestLogQueueToken = strings.TrimSpace(os.Getenv("REQUEST_LOG_QUEUE_TOKEN"))
	config.TinybirdHost = strings.TrimSpace(os.Getenv("TB_HOST_URL"))
	config.TinybirdToken = strings.TrimSpace(os.Getenv("TB_GATEWAY_REQUESTS_TOKEN"))
}

func (c ConfidentialConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Environment != "staging" && c.Environment != "production" {
		return fmt.Errorf("confidential startup requires staging or production")
	}
	if c.ControlURL != defaultFleetAPIURLForEnvironment(c.Environment) || c.ControlAllowHTTP {
		return fmt.Errorf("confidential Control origin is fixed by environment")
	}
	if c.EntropyTimeout <= 0 {
		return fmt.Errorf("entropy startup timeout must be positive")
	}
	if strings.TrimSpace(c.AccessClientID) == "" {
		return fmt.Errorf("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID is required for confidential Control access")
	}
	if strings.TrimSpace(c.AccessClientSecret) == "" {
		return fmt.Errorf("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET is required for confidential Control access")
	}
	instance, err := uuid.Parse(c.InstanceID)
	if err != nil || instance.String() != c.InstanceID {
		return fmt.Errorf("STOGAS_INSTANCE_ID must be a canonical instance UUID")
	}
	return nil
}
func (c ConfidentialConfig) ControlConfigured() bool { return strings.TrimSpace(c.ControlURL) != "" }
func (c ConfidentialConfig) WithRuntimeDefaults() ConfidentialConfig {
	if c.EntropyTimeout == 0 {
		c.EntropyTimeout = confidentialEntropyTimeout
	}
	return c
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
