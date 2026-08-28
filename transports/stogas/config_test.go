package stogas

import (
	"os"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

func TestConfigRejectsUnsafeNonLocalConfidentialLogging(t *testing.T) {
	base := Config{
		Confidential:   ConfidentialConfig{Enabled: true, Environment: "staging"},
		LogLevel:       string(schemas.LogLevelInfo),
		LogOutputStyle: string(schemas.LoggerOutputTypeJSON),
	}

	debug := base
	debug.LogLevel = string(schemas.LogLevelDebug)
	if err := debug.Validate(); err == nil || !strings.Contains(err.Error(), "debug logging") {
		t.Fatalf("expected debug logging rejection, got %v", err)
	}

	pretty := base
	pretty.LogOutputStyle = string(schemas.LoggerOutputTypePretty)
	if err := pretty.Validate(); err == nil || !strings.Contains(err.Error(), "JSON logging") {
		t.Fatalf("expected pretty logging rejection, got %v", err)
	}

	local := base
	local.Confidential.Environment = "local"
	local.LogLevel = string(schemas.LogLevelDebug)
	local.LogOutputStyle = string(schemas.LoggerOutputTypePretty)
	if err := local.validateOperationalLogging(); err != nil {
		t.Fatalf("local debug logging should remain available: %v", err)
	}
}

func TestLoadFromEnvDatabasePoolDefaults(t *testing.T) {
	setRequiredEnv(t)

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.DatabasePool.MaxConns != 6 {
		t.Fatalf("MaxConns = %d, want 6", config.DatabasePool.MaxConns)
	}
	if config.DatabasePool.MinConns != 1 {
		t.Fatalf("MinConns = %d, want 1", config.DatabasePool.MinConns)
	}
	if config.DatabasePool.MinIdleConns != 1 {
		t.Fatalf("MinIdleConns = %d, want 1", config.DatabasePool.MinIdleConns)
	}
	if config.DatabasePool.QueryExecMode != defaultDatabaseQueryExecMode {
		t.Fatalf("QueryExecMode = %s, want %s", config.DatabasePool.QueryExecMode, defaultDatabaseQueryExecMode)
	}
	if config.MaxRequestBodyMiB != maxRequestBodyMiB {
		t.Fatalf("MaxRequestBodyMiB = %d, want %d", config.MaxRequestBodyMiB, maxRequestBodyMiB)
	}
}

func TestLoadFromEnvDatabasePoolOverrides(t *testing.T) {
	setRequiredEnv(t)
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
	setRequiredEnv(t)
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

func TestLoadFromEnvRejectsUnsafeTinybirdConfiguration(t *testing.T) {
	for _, test := range []struct {
		name  string
		host  string
		token string
	}{
		{name: "host only", host: "https://api.tinybird.co"},
		{name: "token only", token: "gateway-requests-rw-token"},
		{name: "remote HTTP", host: "http://api.tinybird.co", token: "gateway-requests-rw-token"},
		{name: "credentials", host: "https://user:password@api.tinybird.co", token: "gateway-requests-rw-token"},
		{name: "path", host: "https://api.tinybird.co/private", token: "gateway-requests-rw-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("TB_HOST_URL", test.host)
			t.Setenv("TB_GATEWAY_REQUESTS_TOKEN", test.token)

			if _, err := LoadFromEnv(); err == nil {
				t.Fatal("LoadFromEnv returned nil error for unsafe Tinybird configuration")
			}
		})
	}
}

func TestLoadFromEnvPrivateProviderNetworkIsExplicitOptIn(t *testing.T) {
	setRequiredEnv(t)

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
	setRequiredEnv(t)
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
	t.Setenv("STOGAS_FLEET_API_URL", "https://control.stogas.localhost/api/fleet")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID", "access-client-id")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET", "access-client-secret")

	config, err = LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error after confidential opt-in: %v", err)
	}
	if !config.Confidential.Enabled ||
		config.Confidential.AttesterMode != "igvm-native" ||
		config.Confidential.ControlURL != "https://control.stogas.localhost/api/fleet" ||
		config.Confidential.EntropyTimeout != confidentialEntropyTimeout ||
		config.Confidential.HeartbeatInterval != confidentialHeartbeatInterval ||
		config.Confidential.QuoteRefresh != confidentialQuoteRefresh ||
		len(config.Confidential.AcceptedCertSHA256) != 2 {
		t.Fatalf("unexpected confidential config: %#v", config.Confidential)
	}
}

func TestLoadFromEnvStagingConfidentialDefaultsRequireCloudflareAccess(t *testing.T) {
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
	if !config.Confidential.Enabled {
		t.Fatalf("staging should enable confidential provisioning: %#v", config.Confidential)
	}
	if config.Confidential.ControlURL != defaultFleetAPIURLStaging || config.Confidential.AttesterMode != "sev-snp" {
		t.Fatalf("unexpected staging defaults: %#v", config.Confidential)
	}
	if config.PrivateReadinessPort != defaultPrivateReadinessPort {
		t.Fatalf("staging should derive private readiness port %s, got %q", defaultPrivateReadinessPort, config.PrivateReadinessPort)
	}
	if config.ChutesAPIKey != "" {
		t.Fatalf("staging should wait for the released managed Chutes key: %#v", config)
	}
}

func TestLoadFromEnvDerivesNativeConfidentialModeWithControl(t *testing.T) {
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
	if config.Confidential.ControlURL != defaultFleetAPIURLLocal {
		t.Fatalf("native confidential mode should use Control provisioning: %#v", config.Confidential)
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

func TestLoadFromEnvRejectsUnsupportedConfidentialKnobs(t *testing.T) {
	for _, name := range []string{
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
		t.Run(name, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
			t.Setenv(name, "override")

			_, err := LoadFromEnv()
			if err == nil || !strings.Contains(err.Error(), name+" is not supported") {
				t.Fatalf("expected unsupported confidential knob rejection for %s, got %v", name, err)
			}
		})
	}
}

func TestLoadFromEnvRejectsUnsupportedControlURLOverride(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("STOGAS_CONFIDENTIAL_CONTROL_URL", "https://control.stogas.localhost")

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_CONFIDENTIAL_CONTROL_URL is not supported") {
		t.Fatalf("expected unsupported Control URL rejection, got %v", err)
	}
}

func TestLoadFromEnvRejectsStagingFleetAPIOverride(t *testing.T) {
	t.Setenv("STOGAS_ENVIRONMENT", "staging")
	t.Setenv("STOGAS_FLEET_API_URL", "https://attacker.example/api/fleet")

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_FLEET_API_URL is only supported for local testing") {
		t.Fatalf("expected staging fleet API override rejection, got %v", err)
	}
}

func TestLoadFromEnvRejectsStagingHostCertOverrides(t *testing.T) {
	t.Setenv("STOGAS_ENVIRONMENT", "staging")
	t.Setenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", strings.Repeat("b", 64))

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256 is not supported") {
		t.Fatalf("expected staging host cert override rejection, got %v", err)
	}
}

func TestLoadFromEnvRejectsStagingHostRuntimeSecrets(t *testing.T) {
	for _, name := range []string{
		"ANTHROPIC_API_KEY",
		"API_KEY_PEPPER",
		"CHUTES_API_KEY",
		"INFERENCE_TOKEN_PUBLIC_KEY",
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
		t.Run(name, func(t *testing.T) {
			t.Setenv("STOGAS_ENVIRONMENT", "staging")
			t.Setenv(name, "host-secret")

			_, err := LoadFromEnv()
			if err == nil || !strings.Contains(err.Error(), name+" is not supported") {
				t.Fatalf("expected staging host runtime secret rejection for %s, got %v", name, err)
			}
		})
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

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.Confidential.ActiveCertSHA256 != "" || len(config.Confidential.AcceptedCertSHA256) != 0 || !config.Confidential.CertExpiresAt.IsZero() {
		t.Fatalf("first boot should leave cert config empty for runtime provisioning: %#v", config.Confidential)
	}
	if config.Confidential.ControlURL != defaultFleetAPIURLLocal {
		t.Fatalf("local first boot should default to local fleet API, got %#v", config.Confidential)
	}
	if config.Confidential.AttesterMode != "igvm-native" {
		t.Fatalf("local first boot should use native attester mode, got %#v", config.Confidential)
	}
}

func TestLoadFromEnvAllowsLocalFleetAPIOverride(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_FLEET_API_URL", "http://127.0.0.1:5999/api/fleet")

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if config.Confidential.ControlURL != "http://127.0.0.1:5999/api/fleet" {
		t.Fatalf("local fleet API override was not honored: %#v", config.Confidential)
	}
}

func TestLoadFromEnvRejectsConfiguredCertWithoutExpiryForControlConfig(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256", strings.Repeat("b", 64))

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT") {
		t.Fatalf("expected missing certificate expiry error, got %v", err)
	}
}

func TestLoadFromEnvAllowsProviderKeysFromConfidentialSecretRelease(t *testing.T) {
	setRequiredEnvWithoutProviderKeys(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ENABLED", "true")
	t.Setenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_ACCEPTED_CERT_SHA256", strings.Repeat("b", 64))
	t.Setenv("STOGAS_CONFIDENTIAL_CERT_EXPIRES_AT", "2026-12-31T00:00:00Z")
	t.Setenv("STOGAS_FLEET_API_URL", "https://control.stogas.localhost/api/fleet")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID", "access-client-id")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET", "access-client-secret")

	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if !config.Confidential.ControlConfigured() {
		t.Fatal("expected confidential Control provisioning to be enabled")
	}
	if config.Confidential.AttesterMode != "igvm-native" {
		t.Fatalf("local secret release should derive native attestation, got %#v", config.Confidential)
	}
	if config.ChutesAPIKey != "" {
		t.Fatalf("the managed Chutes key should not come from host env: %#v", config)
	}
}

func TestLoadFromEnvRejectsRemovedSecretReleaseSwitch(t *testing.T) {
	setRequiredEnvWithoutProviderKeys(t)
	t.Setenv("STOGAS_CONFIDENTIAL_REQUEST_SECRETS", "true")

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_CONFIDENTIAL_REQUEST_SECRETS is not supported") {
		t.Fatalf("expected removed secret release switch error, got %v", err)
	}
}

func TestApplyConfidentialRuntimeSecretsInstallsReleasedRuntimeSecrets(t *testing.T) {
	preserveConfidentialRuntimeEnv(t)
	t.Setenv("INFISICAL_SKIP", "true")

	config := Config{
		ChutesAPIKey: "host-chutes",
		Confidential: ConfidentialConfig{
			ControlURL: "https://control.stogas.localhost/api/fleet",
		},
	}
	err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{
		"API_KEY_PEPPER":             "released-api-key-pepper-0123456789",
		"BYOK_ENCRYPTION_SECRET":     "released-byok-encryption-secret-at-least-32-characters",
		"CHUTES_API_KEY":             "released-chutes",
		"INFERENCE_TOKEN_PUBLIC_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"DATABASE_SCHEMA":            "public_0001_initial_schema",
		"DATABASE_URL":               "postgres://released:pass@localhost:5432/postgres",
		"TB_GATEWAY_REQUESTS_TOKEN":  "tinybird-token",
		"TB_HOST_URL":                "https://tinybird.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("API_KEY_PEPPER") != "released-api-key-pepper-0123456789" || os.Getenv("DATABASE_SCHEMA") != "public_0001_initial_schema" {
		t.Fatalf("released runtime secrets were not installed")
	}
	if config.ChutesAPIKey != "released-chutes" {
		t.Fatalf("the managed Chutes key did not refresh from released secrets: %#v", config)
	}
	if config.TinybirdHost != "https://tinybird.example" || config.TinybirdToken != "tinybird-token" {
		t.Fatalf("runtime service secrets did not refresh from released secrets: %#v", config)
	}
}

func TestApplyConfidentialRuntimeSecretsFailsClosedForMissingRuntimeSecret(t *testing.T) {
	preserveConfidentialRuntimeEnv(t)
	config := Config{Confidential: ConfidentialConfig{ControlURL: "https://control.stogas.localhost/api/fleet"}}
	err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{
		"API_KEY_PEPPER":             "released-api-key-pepper-0123456789",
		"BYOK_ENCRYPTION_SECRET":     "released-byok-encryption-secret-at-least-32-characters",
		"INFERENCE_TOKEN_PUBLIC_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"DATABASE_SCHEMA":            "public_0001_initial_schema",
	})
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("expected missing runtime secret error, got %v", err)
	}
}

func TestValidateProviderRuntimeSecretsReadyRequiresAppliedSecrets(t *testing.T) {
	config := Config{
		BYOKEncryptionSecret: "released-byok-encryption-secret-at-least-32-characters",
		Confidential:         ConfidentialConfig{ControlURL: "https://control.stogas.localhost/api/fleet"},
	}
	if err := validateProviderRuntimeSecretsReady(config); err == nil || !strings.Contains(err.Error(), "CHUTES_API_KEY") {
		t.Fatalf("expected missing Chutes provider key error, got %v", err)
	}
}

func TestValidateProviderRuntimeSecretsReadyPassesAfterSecretRelease(t *testing.T) {
	preserveConfidentialRuntimeEnv(t)
	t.Setenv("INFISICAL_SKIP", "true")

	config := Config{Confidential: ConfidentialConfig{ControlURL: "https://control.stogas.localhost/api/fleet"}}
	if err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{
		"API_KEY_PEPPER":             "released-api-key-pepper-0123456789",
		"BYOK_ENCRYPTION_SECRET":     "released-byok-encryption-secret-at-least-32-characters",
		"CHUTES_API_KEY":             "released-chutes",
		"INFERENCE_TOKEN_PUBLIC_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"DATABASE_SCHEMA":            "public_0001_initial_schema",
		"DATABASE_URL":               "postgres://released:pass@localhost:5432/postgres",
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
	t.Setenv("CHUTES_API_KEY", "test-chutes-key")
}

func setRequiredEnvWithoutProviderKeys(t *testing.T) {
	t.Helper()
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("API_KEY_PEPPER", "01234567890123456789012345678901")
	t.Setenv("BYOK_ENCRYPTION_SECRET", "test-byok-encryption-secret-at-least-32-characters")
	t.Setenv("INFERENCE_TOKEN_PUBLIC_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
}

func preserveConfidentialRuntimeEnv(t *testing.T) {
	t.Helper()
	for _, name := range append(
		append([]string{}, confidentialRuntimeSecretNames...),
		"TB_GATEWAY_REQUESTS_TOKEN",
		"TB_HOST_URL",
	) {
		t.Setenv(name, os.Getenv(name))
	}
}

type fakeSecretLookup map[string]string

func (f fakeSecretLookup) Get(name string) (secretstore.Secret, bool) {
	value, ok := f[name]
	return secretstore.Secret{Name: name, Value: []byte(value), Version: "test"}, ok
}
