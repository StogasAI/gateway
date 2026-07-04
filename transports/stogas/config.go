package stogas

import (
	"context"
	"fmt"
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
	defaultHost              = "127.0.0.1"
	defaultPort              = "5185"
	defaultMaxRequestBodyMiB = 16
	defaultInfisicalSiteURL  = "https://secrets.stogas.ai"

	defaultDatabasePoolMaxConns     int32 = 32
	defaultDatabasePoolMinConns     int32 = 4
	defaultDatabasePoolMinIdleConns int32 = 4
	defaultDatabaseQueryExecMode          = "cache_statement"
)

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
	ActiveCertSHA256   string
	AttesterMode       string
	CertExpiresAt      time.Time
	ChipID             string
	ControlAllowHTTP   bool
	ControlToken       string
	ControlURL         string
	EndpointAddress    string
	EndpointPort       int
	Enabled            bool
	EntropyTimeout     time.Duration
	HeartbeatInterval  time.Duration
	QuoteRefresh       time.Duration
	ReadinessInterval  time.Duration
	Region             string
	ReleaseMeasurement string
	RequestSecrets     bool
}

func LoadFromEnv() (Config, error) {
	loadInfisicalRuntimeSecrets()
	databasePool, err := loadDatabasePoolConfig()
	if err != nil {
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

	if err := config.Validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func loadConfidentialConfigFromEnv() ConfidentialConfig {
	refresh := envDurationSeconds("STOGAS_CONFIDENTIAL_QUOTE_REFRESH_SECONDS", 30)
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	heartbeat := envDurationSeconds("STOGAS_CONFIDENTIAL_HEARTBEAT_SECONDS", 60)
	if heartbeat <= 0 {
		heartbeat = 60 * time.Second
	}
	readiness := envDurationSeconds("STOGAS_CONFIDENTIAL_READINESS_SECONDS", 60)
	if readiness <= 0 {
		readiness = 60 * time.Second
	}
	entropyTimeout := envDurationSeconds("STOGAS_CONFIDENTIAL_ENTROPY_TIMEOUT_SECONDS", 10)
	if entropyTimeout <= 0 {
		entropyTimeout = 10 * time.Second
	}
	certExpiresAt := time.Time{}
	if raw := strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT")); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			certExpiresAt = parsed.UTC()
		}
	}
	return ConfidentialConfig{
		AcceptedCertSHA256: splitCSV(os.Getenv("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256")),
		ActiveCertSHA256:   strings.ToLower(strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256"))),
		AttesterMode:       strings.ToLower(strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_ATTESTER_MODE"))),
		CertExpiresAt:      certExpiresAt,
		ChipID:             strings.ToLower(strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_CHIP_ID"))),
		ControlAllowHTTP:   os.Getenv("STOGAS_CONFIDENTIAL_CONTROL_ALLOW_INSECURE_LOCAL") == "true",
		ControlToken:       strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_CONTROL_TOKEN")),
		ControlURL:         strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_CONTROL_URL")),
		EndpointAddress:    strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_ENDPOINT_ADDRESS")),
		EndpointPort:       envInt("STOGAS_CONFIDENTIAL_ENDPOINT_PORT", 0),
		Enabled:            os.Getenv("STOGAS_CONFIDENTIAL_ENABLED") == "true",
		EntropyTimeout:     entropyTimeout,
		HeartbeatInterval:  heartbeat,
		QuoteRefresh:       refresh,
		ReadinessInterval:  readiness,
		Region:             strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_REGION")),
		ReleaseMeasurement: strings.ToLower(strings.TrimSpace(os.Getenv("STOGAS_CONFIDENTIAL_RELEASE_MEASUREMENT"))),
		RequestSecrets:     os.Getenv("STOGAS_CONFIDENTIAL_REQUEST_SECRETS") == "true",
	}
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
		resolveInfisicalSecret(client, projectID, "/gateway/tinybird", secretName, false)
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
	openAI, ok := secrets.Get("OPENAI_API_KEY")
	if !ok || len(openAI.Value) == 0 {
		return fmt.Errorf("confidential secret OPENAI_API_KEY is required")
	}
	anthropic, ok := secrets.Get("ANTHROPIC_API_KEY")
	if !ok || len(anthropic.Value) == 0 {
		return fmt.Errorf("confidential secret ANTHROPIC_API_KEY is required")
	}
	config.OpenAIAPIKey = string(openAI.Value)
	config.AnthropicAPIKey = string(anthropic.Value)
	return nil
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

func (c ConfidentialConfig) Validate() error {
	if !c.Enabled {
		if c.RequestSecrets {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_ENABLED=true is required before secret release")
		}
		return nil
	}
	if c.AttesterMode == "" {
		return fmt.Errorf("STOGAS_CONFIDENTIAL_ATTESTER_MODE is required when confidential mode is enabled")
	}
	switch c.AttesterMode {
	case "mock", "igvm-native", "sev-snp":
	default:
		return fmt.Errorf("unsupported STOGAS_CONFIDENTIAL_ATTESTER_MODE %q", c.AttesterMode)
	}
	if err := validateHashHex("STOGAS_CONFIDENTIAL_RELEASE_MEASUREMENT", c.ReleaseMeasurement); err != nil {
		return err
	}
	if strings.TrimSpace(c.Region) == "" {
		return fmt.Errorf("STOGAS_CONFIDENTIAL_REGION is required when confidential mode is enabled")
	}
	if err := validateHashHex("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", c.ActiveCertSHA256); err != nil {
		return err
	}
	if len(c.AcceptedCertSHA256) == 0 {
		return fmt.Errorf("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256 is required when confidential mode is enabled")
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
	if c.QuoteRefresh <= 0 {
		return fmt.Errorf("STOGAS_CONFIDENTIAL_QUOTE_REFRESH_SECONDS must be positive")
	}
	if c.EntropyTimeout < 0 {
		return fmt.Errorf("STOGAS_CONFIDENTIAL_ENTROPY_TIMEOUT_SECONDS must not be negative")
	}
	if c.ControlConfigured() {
		if strings.TrimSpace(c.ControlURL) == "" {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_CONTROL_URL is required when Control heartbeats are configured")
		}
		if strings.TrimSpace(c.ControlToken) == "" {
			return fmt.Errorf("STOGAS_CONFIDENTIAL_CONTROL_TOKEN is required when Control heartbeats are configured")
		}
		if err := validateChipID("STOGAS_CONFIDENTIAL_CHIP_ID", c.ChipID); err != nil {
			return err
		}
		if c.CertExpiresAt.IsZero() {
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

func (c ConfidentialConfig) ControlConfigured() bool {
	return strings.TrimSpace(c.ControlURL) != "" || strings.TrimSpace(c.ControlToken) != ""
}

func (c ConfidentialConfig) ReadinessConfigured() bool {
	return strings.TrimSpace(c.EndpointAddress) != "" || c.EndpointPort != 0
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
