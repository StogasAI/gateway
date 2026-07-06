package stogas

import (
	"os"
	"strings"
	"testing"

	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

func TestLoadFromEnvDatabasePoolDefaults(t *testing.T) {
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("AUTH_SECRET", "01234567890123456789012345678901")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.DatabasePool.MaxConns != defaultDatabasePoolMaxConns {
		t.Fatalf("MaxConns = %d, want %d", config.DatabasePool.MaxConns, defaultDatabasePoolMaxConns)
	}
	if config.DatabasePool.MinConns != defaultDatabasePoolMinConns {
		t.Fatalf("MinConns = %d, want %d", config.DatabasePool.MinConns, defaultDatabasePoolMinConns)
	}
	if config.DatabasePool.MinIdleConns != defaultDatabasePoolMinIdleConns {
		t.Fatalf("MinIdleConns = %d, want %d", config.DatabasePool.MinIdleConns, defaultDatabasePoolMinIdleConns)
	}
	if config.DatabasePool.QueryExecMode != defaultDatabaseQueryExecMode {
		t.Fatalf("QueryExecMode = %s, want %s", config.DatabasePool.QueryExecMode, defaultDatabaseQueryExecMode)
	}
}

func TestLoadFromEnvDatabasePoolOverrides(t *testing.T) {
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("AUTH_SECRET", "01234567890123456789012345678901")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("STOGAS_DB_POOL_MAX_CONNS", "12")
	t.Setenv("STOGAS_DB_POOL_MIN_CONNS", "2")
	t.Setenv("STOGAS_DB_POOL_MIN_IDLE_CONNS", "1")
	t.Setenv("STOGAS_DB_QUERY_EXEC_MODE", "exec")

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.DatabasePool.MaxConns != 12 {
		t.Fatalf("MaxConns = %d, want 12", config.DatabasePool.MaxConns)
	}
	if config.DatabasePool.MinConns != 2 {
		t.Fatalf("MinConns = %d, want 2", config.DatabasePool.MinConns)
	}
	if config.DatabasePool.MinIdleConns != 1 {
		t.Fatalf("MinIdleConns = %d, want 1", config.DatabasePool.MinIdleConns)
	}
	if config.DatabasePool.QueryExecMode != "exec" {
		t.Fatalf("QueryExecMode = %s, want exec", config.DatabasePool.QueryExecMode)
	}
}

func TestLoadFromEnvUsesGatewayRequestsTinybirdToken(t *testing.T) {
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("AUTH_SECRET", "01234567890123456789012345678901")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("TB_HOST_URL", "https://api.tinybird.co")
	t.Setenv("TB_GATEWAY_REQUESTS_TOKEN", "gateway-requests-rw-token")
	t.Setenv("TB_APPEND_ONLY_GATEWAY_REQUESTS", "stale-append-token")

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.TinybirdHost != "https://api.tinybird.co" {
		t.Fatalf("TinybirdHost = %s, want Tinybird host", config.TinybirdHost)
	}
	if config.TinybirdToken != "gateway-requests-rw-token" {
		t.Fatalf("TinybirdToken = %s, want gateway requests token", config.TinybirdToken)
	}
}

func TestLoadFromEnvPrivateProviderNetworkIsExplicitOptIn(t *testing.T) {
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("AUTH_SECRET", "01234567890123456789012345678901")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.AllowPrivateProviderNetwork {
		t.Fatal("AllowPrivateProviderNetwork = true without explicit opt-in")
	}

	t.Setenv("STOGAS_ALLOW_PRIVATE_PROVIDER_NETWORK", "true")
	config, err = LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error after opt-in: %v", err)
	}
	if !config.AllowPrivateProviderNetwork {
		t.Fatal("AllowPrivateProviderNetwork = false with explicit opt-in")
	}
}

func TestLoadFromEnvRejectsInvalidDatabasePool(t *testing.T) {
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("AUTH_SECRET", "01234567890123456789012345678901")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("STOGAS_DB_POOL_MAX_CONNS", "2")
	t.Setenv("STOGAS_DB_POOL_MIN_CONNS", "3")

	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("LoadFromEnv returned nil error for invalid pool config")
	}
}

func TestLoadFromEnvConfidentialModeIsExplicitOptIn(t *testing.T) {
	setRequiredEnv(t)
	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.Confidential.Enabled {
		t.Fatal("confidential mode should be disabled by default")
	}

	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256", strings.Repeat("b", 64)+","+strings.Repeat("c", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT", "2026-12-31T00:00:00Z")
	t.Setenv("STOGAS_CONFIDENTIAL_CONTROL_ALLOW_INSECURE_LOCAL", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_CONTROL_URL", "https://control.stogas.localhost")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID", "access-client-id")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET", "access-client-secret")
	t.Setenv("STOGAS_CONFIDENTIAL_ENDPOINT_ADDRESS", "10.0.0.10")
	t.Setenv("STOGAS_CONFIDENTIAL_ENDPOINT_PORT", "8443")

	config, err = LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error after confidential opt-in: %v", err)
	}
	if !config.Confidential.Enabled ||
		config.Confidential.AttesterMode != "sev-snp" ||
		config.Confidential.ControlURL != "https://control.stogas.localhost" ||
		config.Confidential.EndpointPort != 8443 ||
		config.Confidential.EntropyTimeout != confidentialEntropyTimeout ||
		config.Confidential.HeartbeatInterval != confidentialHeartbeatInterval ||
		config.Confidential.QuoteRefresh != confidentialQuoteRefresh ||
		config.Confidential.ReadinessInterval != confidentialReadinessInterval ||
		len(config.Confidential.AcceptedCertSHA256) != 2 {
		t.Fatalf("unexpected confidential config: %#v", config.Confidential)
	}
}

func TestLoadFromEnvStagingConfidentialDefaultsRequireCloudflareAccess(t *testing.T) {
	setRequiredEnvWithoutProviderKeys(t)
	t.Setenv("STOGAS_ENVIRONMENT", "staging")

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID") {
		t.Fatalf("expected missing Cloudflare Access error, got %v", err)
	}

	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID", "access-client-id")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET", "access-client-secret")
	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error after Access config: %v", err)
	}
	if !config.Confidential.Enabled || !config.Confidential.RequestSecrets {
		t.Fatalf("staging should enable confidential provisioning: %#v", config.Confidential)
	}
	if config.Confidential.ControlURL != defaultControlURLStaging || config.Confidential.AttesterMode != "sev-snp" {
		t.Fatalf("unexpected staging defaults: %#v", config.Confidential)
	}
	if config.OpenAIAPIKey != "" || config.AnthropicAPIKey != "" {
		t.Fatalf("staging should wait for released provider keys: %#v", config)
	}
}

func TestLoadFromEnvDerivesNativeConfidentialModeWithoutControl(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT", "2026-12-31T00:00:00Z")

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.Confidential.AttesterMode != "igvm-native" {
		t.Fatalf("expected direct native mode without Control, got %#v", config.Confidential)
	}
	if config.Confidential.RequestSecrets || config.Confidential.ControlConfigured() {
		t.Fatalf("native direct mode should not request Control provisioning: %#v", config.Confidential)
	}
}

func TestLoadFromEnvRejectsAttesterModeEnvOverride(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_ATTESTER_MODE", "mock")

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_CONFIDENTIAL_ATTESTER_MODE is not supported") {
		t.Fatalf("expected attester env rejection, got %v", err)
	}
}

func TestLoadFromEnvRejectsIncompleteConfidentialConfig(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256", strings.Repeat("c", 64))

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "must include STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256") {
		t.Fatalf("expected accepted cert mismatch error, got %v", err)
	}
}

func TestLoadFromEnvAllowsConfidentialFirstBootWithoutConfiguredCertificate(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_CONTROL_URL", "https://control.stogas.localhost")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID", "access-client-id")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET", "access-client-secret")

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.Confidential.ActiveCertSHA256 != "" || len(config.Confidential.AcceptedCertSHA256) != 0 || !config.Confidential.CertExpiresAt.IsZero() {
		t.Fatalf("first boot should leave cert config empty for runtime provisioning: %#v", config.Confidential)
	}
}

func TestLoadFromEnvRejectsIncompleteConfidentialControlConfig(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_REQUEST_SECRETS", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256", strings.Repeat("b", 64))

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "Control heartbeats must be configured before secret release") {
		t.Fatalf("expected missing Control URL error, got %v", err)
	}
}

func TestLoadFromEnvAllowsProviderKeysFromConfidentialSecretRelease(t *testing.T) {
	setRequiredEnvWithoutProviderKeys(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_REQUEST_SECRETS", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT", "2026-12-31T00:00:00Z")
	t.Setenv("STOGAS_CONFIDENTIAL_CONTROL_URL", "https://control.stogas.localhost")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID", "access-client-id")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET", "access-client-secret")

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if !config.Confidential.RequestSecrets {
		t.Fatal("expected request secrets to be enabled")
	}
	if config.Confidential.AttesterMode != "sev-snp" {
		t.Fatalf("secret release should derive sev-snp attestation, got %#v", config.Confidential)
	}
	if config.OpenAIAPIKey != "" || config.AnthropicAPIKey != "" {
		t.Fatalf("provider keys should not come from host env: %#v", config)
	}
}

func TestLoadFromEnvRejectsSecretReleaseWithoutConfidentialRuntime(t *testing.T) {
	setRequiredEnvWithoutProviderKeys(t)
	t.Setenv("STOGAS_CONFIDENTIAL_REQUEST_SECRETS", "true")

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_CONFIDENTIAL_ENABLED=true is required") {
		t.Fatalf("expected disabled confidential secret release error, got %v", err)
	}
}

func TestApplyConfidentialRuntimeSecretsInstallsInfisicalBootstrapAndRefreshesRuntimeSecrets(t *testing.T) {
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("AUTH_SECRET", "infisical-auth-secret-0123456789")
	t.Setenv("DATABASE_URL", "postgres://infisical:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
	t.Setenv("OPENAI_API_KEY", "infisical-openai")
	t.Setenv("ANTHROPIC_API_KEY", "infisical-anthropic")
	t.Setenv("TB_HOST_URL", "https://tinybird.example")
	t.Setenv("TB_GATEWAY_REQUESTS_TOKEN", "tinybird-token")

	config := Config{
		AnthropicAPIKey: "host-anthropic",
		Confidential:    ConfidentialConfig{RequestSecrets: true},
		OpenAIAPIKey:    "host-openai",
	}
	err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{
		"INFISICAL_PROJECT_ID":                   "project-id",
		"INFISICAL_SITE_URL":                     "https://secrets.example",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":     "client-id",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "client-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("INFISICAL_PROJECT_ID") != "project-id" || os.Getenv("INFISICAL_SITE_URL") != "https://secrets.example" {
		t.Fatalf("released Infisical bootstrap secrets were not installed")
	}
	if config.OpenAIAPIKey != "infisical-openai" || config.AnthropicAPIKey != "infisical-anthropic" {
		t.Fatalf("runtime provider keys did not refresh from Infisical/env: %#v", config)
	}
	if config.TinybirdHost != "https://tinybird.example" || config.TinybirdToken != "tinybird-token" {
		t.Fatalf("runtime service secrets did not refresh from Infisical/env: %#v", config)
	}
}

func TestApplyConfidentialRuntimeSecretsFailsClosedForMissingInfisicalBootstrapSecret(t *testing.T) {
	config := Config{Confidential: ConfidentialConfig{RequestSecrets: true}}
	err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{
		"INFISICAL_PROJECT_ID":               "project-id",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "client-id",
	})
	if err == nil || !strings.Contains(err.Error(), "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET") {
		t.Fatalf("expected missing Infisical bootstrap secret error, got %v", err)
	}
}

func TestValidateProviderRuntimeSecretsReadyRequiresAppliedSecrets(t *testing.T) {
	config := Config{Confidential: ConfidentialConfig{RequestSecrets: true}}
	if err := validateProviderRuntimeSecretsReady(config); err == nil || !strings.Contains(err.Error(), "OPENAI_API_KEY") {
		t.Fatalf("expected missing OpenAI provider key error, got %v", err)
	}

	config.OpenAIAPIKey = "released-openai"
	if err := validateProviderRuntimeSecretsReady(config); err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
		t.Fatalf("expected missing Anthropic provider key error, got %v", err)
	}
}

func TestValidateProviderRuntimeSecretsReadyPassesAfterSecretRelease(t *testing.T) {
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("OPENAI_API_KEY", "infisical-openai")
	t.Setenv("ANTHROPIC_API_KEY", "infisical-anthropic")

	config := Config{Confidential: ConfidentialConfig{RequestSecrets: true}}
	if err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{
		"INFISICAL_PROJECT_ID":                   "project-id",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":     "client-id",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "client-secret",
	}); err != nil {
		t.Fatal(err)
	}
	if err := validateProviderRuntimeSecretsReady(config); err != nil {
		t.Fatalf("provider runtime should accept released secrets: %v", err)
	}
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	setRequiredEnvWithoutProviderKeys(t)
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
}

func setRequiredEnvWithoutProviderKeys(t *testing.T) {
	t.Helper()
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("AUTH_SECRET", "01234567890123456789012345678901")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
}

type fakeSecretLookup map[string]string

func (f fakeSecretLookup) Get(name string) (secretstore.Secret, bool) {
	value, ok := f[name]
	return secretstore.Secret{Name: name, Value: []byte(value), Version: "test"}, ok
}
