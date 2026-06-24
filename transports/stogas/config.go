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

func LoadFromEnv() (Config, error) {
	loadInfisicalRuntimeSecrets()
	databasePool, err := loadDatabasePoolConfig()
	if err != nil {
		return Config{}, err
	}

	config := Config{
		AllowPrivateProviderNetwork: os.Getenv("STOGAS_ALLOW_PRIVATE_PROVIDER_NETWORK") == "true",
		AuthSecret:                  strings.TrimSpace(os.Getenv("AUTH_SECRET")),
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
	if c.OpenAIAPIKey == "" {
		return fmt.Errorf("OPENAI_API_KEY is required")
	}
	if c.AnthropicAPIKey == "" {
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
