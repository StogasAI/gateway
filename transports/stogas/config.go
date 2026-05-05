package stogas

import (
	"context"
	"fmt"
	"os"
	"strings"

	infisical "github.com/infisical/go-sdk"

	"github.com/maximhq/bifrost/core/schemas"
)

const (
	defaultHost              = "127.0.0.1"
	defaultPort              = "5185"
	defaultMaxRequestBodyMiB = 16
	defaultInfisicalSiteURL  = "https://secrets.stogas.ai"
)

type Config struct {
	AuthSecret        string
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

	config := Config{
		AuthSecret:        strings.TrimSpace(os.Getenv("AUTH_SECRET")),
		DatabaseURL:       strings.TrimSpace(os.Getenv("DATABASE_URL")),
		Host:              defaultHost,
		LogLevel:          string(schemas.LogLevelInfo),
		LogOutputStyle:    string(schemas.LoggerOutputTypeJSON),
		MaxRequestBodyMiB: defaultMaxRequestBodyMiB,
		OpenAIAPIKey:      strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		OpenAIBaseURL:     strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")),
		Port:              defaultPort,
		TinybirdHost:      strings.TrimSpace(os.Getenv("TB_HOST")),
		TinybirdToken:     strings.TrimSpace(os.Getenv("TB_APPEND_ONLY")),
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

	required := []string{"AUTH_SECRET", "DATABASE_URL", "OPENAI_API_KEY"}
	if os.Getenv("INFISICAL_SKIP_DATABASE_URL") == "true" || os.Getenv("DATABASE_URL") != "" {
		required = []string{"AUTH_SECRET", "OPENAI_API_KEY"}
	}
	for _, secretName := range required {
		resolveInfisicalSecret(client, projectID, "/gateway", secretName, true)
	}
	for _, secretName := range []string{"TB_HOST", "TB_APPEND_ONLY"} {
		resolveInfisicalSecret(client, projectID, "/gateway/tinybird", secretName, false)
	}
}

func resolveInfisicalSecret(client infisical.InfisicalClientInterface, projectID string, secretPath string, secretName string, required bool) {
	if strings.TrimSpace(os.Getenv(secretName)) != "" {
		return
	}

	var lastErr error
	for _, environment := range []string{"prod", "staging", "dev"} {
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
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
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
