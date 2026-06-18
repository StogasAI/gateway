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

type DatabasePoolConfig struct {
	MaxConns      int32
	MinConns      int32
	MinIdleConns  int32
	QueryExecMode string
}

type Config struct {
	AuthSecret        string
	CatalogBundlePath string
	CatalogRefresh    time.Duration
	CatalogURL        string
	DatabasePool      DatabasePoolConfig
	DatabaseSchema    string
	DatabaseURL       string
	Host              string
	LogLevel          string
	LogOutputStyle    string
	MaxRequestBodyMiB int
	OpenAIAPIKey      string
	OpenAIBaseURL     string
	Port              string
	TinybirdHost      string
	TinybirdToken     string
}

func LoadFromEnv() (Config, error) {
	loadInfisicalRuntimeSecrets()
	databasePool, err := loadDatabasePoolConfig()
	if err != nil {
		return Config{}, err
	}

	config := Config{
		AuthSecret:        strings.TrimSpace(os.Getenv("AUTH_SECRET")),
		CatalogBundlePath: strings.TrimSpace(os.Getenv("STOGAS_CATALOG_BUNDLE_PATH")),
		CatalogRefresh:    envDurationSeconds("STOGAS_CATALOG_REFRESH_SECONDS", 300),
		CatalogURL:        strings.TrimSpace(os.Getenv("STOGAS_CATALOG_URL")),
		DatabasePool:      databasePool,
		DatabaseSchema:    strings.TrimSpace(os.Getenv("DATABASE_SCHEMA")),
		DatabaseURL:       strings.TrimSpace(os.Getenv("DATABASE_URL")),
		Host:              defaultHost,
		LogLevel:          string(schemas.LogLevelInfo),
		LogOutputStyle:    string(schemas.LoggerOutputTypeJSON),
		MaxRequestBodyMiB: defaultMaxRequestBodyMiB,
		OpenAIAPIKey:      strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		OpenAIBaseURL:     strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")),
		Port:              defaultPort,
		TinybirdHost:      strings.TrimSpace(os.Getenv("TB_HOST_URL")),
		TinybirdToken:     strings.TrimSpace(os.Getenv("TB_GATEWAY_REQUESTS_TOKEN")),
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

	required := []string{"AUTH_SECRET", "DATABASE_SCHEMA", "DATABASE_URL", "OPENAI_API_KEY"}
	if os.Getenv("INFISICAL_SKIP_DATABASE_URL") == "true" || os.Getenv("DATABASE_URL") != "" {
		required = []string{"AUTH_SECRET", "DATABASE_SCHEMA", "OPENAI_API_KEY"}
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
	if c.CatalogRefresh <= 0 {
		return fmt.Errorf("STOGAS_CATALOG_REFRESH_SECONDS must be positive")
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if c.DatabaseSchema == "" {
		return fmt.Errorf("DATABASE_SCHEMA is required")
	}
	if _, err := pgrollSearchPath(c.DatabaseSchema); err != nil {
		return err
	}
	if c.OpenAIAPIKey == "" {
		return fmt.Errorf("OPENAI_API_KEY is required")
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

func validatePgrollSchemaName(databaseSchema string) (string, error) {
	schemaName := strings.TrimSpace(databaseSchema)
	if schemaName == "" {
		schemaName = "public"
	}
	for index, r := range schemaName {
		if index == 0 {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_' {
				continue
			}
			return "", fmt.Errorf("invalid DATABASE_SCHEMA: %s", schemaName)
		}
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return "", fmt.Errorf("invalid DATABASE_SCHEMA: %s", schemaName)
	}
	return schemaName, nil
}

func pgrollSearchPath(databaseSchema string) (string, error) {
	schemaName, err := validatePgrollSchemaName(databaseSchema)
	if err != nil {
		return "", err
	}
	if schemaName == "public" {
		return "public", nil
	}
	return schemaName + ",public", nil
}

func loadDatabasePoolConfig() (DatabasePoolConfig, error) {
	maxConns, err := envInt32("STOGAS_DB_POOL_MAX_CONNS", defaultDatabasePoolMaxConns)
	if err != nil {
		return DatabasePoolConfig{}, err
	}
	minConns, err := envInt32("STOGAS_DB_POOL_MIN_CONNS", defaultDatabasePoolMinConns)
	if err != nil {
		return DatabasePoolConfig{}, err
	}
	minIdleConns, err := envInt32("STOGAS_DB_POOL_MIN_IDLE_CONNS", defaultDatabasePoolMinIdleConns)
	if err != nil {
		return DatabasePoolConfig{}, err
	}

	queryExecMode := strings.TrimSpace(os.Getenv("STOGAS_DB_QUERY_EXEC_MODE"))
	if queryExecMode == "" {
		queryExecMode = defaultDatabaseQueryExecMode
	}

	return DatabasePoolConfig{
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

func (c DatabasePoolConfig) Validate() error {
	if c.MaxConns <= 0 {
		return fmt.Errorf("STOGAS_DB_POOL_MAX_CONNS must be positive")
	}
	if c.MinConns < 0 {
		return fmt.Errorf("STOGAS_DB_POOL_MIN_CONNS must be non-negative")
	}
	if c.MinIdleConns < 0 {
		return fmt.Errorf("STOGAS_DB_POOL_MIN_IDLE_CONNS must be non-negative")
	}
	if c.MinConns > c.MaxConns {
		return fmt.Errorf("STOGAS_DB_POOL_MIN_CONNS must be less than or equal to STOGAS_DB_POOL_MAX_CONNS")
	}
	if c.MinIdleConns > c.MaxConns {
		return fmt.Errorf("STOGAS_DB_POOL_MIN_IDLE_CONNS must be less than or equal to STOGAS_DB_POOL_MAX_CONNS")
	}

	switch c.QueryExecMode {
	case "cache_statement", "cache_describe", "describe_exec", "exec", "simple_protocol":
		return nil
	default:
		return fmt.Errorf("STOGAS_DB_QUERY_EXEC_MODE must be one of cache_statement, cache_describe, describe_exec, exec, simple_protocol")
	}
}
