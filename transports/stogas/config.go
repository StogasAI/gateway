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
}

func LoadFromEnv() (Config, error) {
	infisicalClientID := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID")
	infisicalClientSecret := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")
	projectID := os.Getenv("INFISICAL_PROJECT_ID")

	if infisicalClientID != "" && infisicalClientSecret != "" {
		fmt.Println("[stogas] Connecting to Infisical (secrets.stogas.ai)...")
		client := infisical.NewInfisicalClient(context.Background(), infisical.Config{
			SiteUrl: "https://secrets.stogas.ai",
		})
		_, err := client.Auth().UniversalAuthLogin(infisicalClientID, infisicalClientSecret)
		
		if err == nil {
			secrets := []string{"AUTH_SECRET", "DATABASE_URL", "OPENAI_API_KEY"}
			if os.Getenv("INFISICAL_SKIP_DATABASE_URL") == "true" {
				secrets = []string{"AUTH_SECRET", "OPENAI_API_KEY"}
			}
			for _, secretName := range secrets {
				// 1. Attempt to resolve from Prod boundary
				res, err := client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
					SecretKey:   secretName,
					Environment: "prod",
					ProjectID:   projectID,
					SecretPath:  "/gateway",
					ExpandSecretReferences: true,
				})

				if err != nil {
					res, err = client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
						SecretKey:   secretName,
						Environment: "dev",
						ProjectID:   projectID,
						SecretPath:  "/gateway",
						ExpandSecretReferences: true,
					})
				}

				if err != nil {
					fmt.Printf("[stogas] Warning: Failed to retrieve secret %s: %v\n", secretName, err)
				}

				// Inject if resolved successfully
				if err == nil && res.SecretValue != "" {
					fmt.Printf("[stogas] Infisical successfully retrieved %s (length %d)\n", secretName, len(res.SecretValue))
					os.Setenv(secretName, res.SecretValue)
				}
			}
		} else {
			fmt.Printf("[stogas] Warning: Failed to authenticate with Infisical: %v\n", err)
		}
	}

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
	}

	if err := config.Validate(); err != nil {
		return Config{}, err
	}

	return config, nil
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
