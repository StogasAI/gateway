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

func TestLoadFromEnvStagingConfidentialDefaultsRequireCloudflareAccess(t *testing.T) {
	t.Setenv("STOGAS_ENVIRONMENT", "staging")

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID") {
		t.Fatalf("expected missing Cloudflare Access error, got %v", err)
	}

	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID", "access-client-id")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET", "access-client-secret")
	t.Setenv("STOGAS_INSTANCE_ID", "00000000-0000-4000-8000-000000000001")
	config, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error after Access config: %v", err)
	}
	if !config.Confidential.Enabled {
		t.Fatalf("staging should enable confidential provisioning: %#v", config.Confidential)
	}
	if config.Confidential.ControlURL != defaultFleetAPIURLStaging {
		t.Fatalf("unexpected staging defaults: %#v", config.Confidential)
	}
	if config.PrivateReadinessPort != defaultPrivateReadinessPort {
		t.Fatalf("staging should derive private readiness port %s, got %q", defaultPrivateReadinessPort, config.PrivateReadinessPort)
	}
	if config.ChutesAPIKey != "" {
		t.Fatalf("staging should wait for the released managed Chutes key: %#v", config)
	}
}

func TestLoadFromEnvRejectsAttesterModeEnvOverride(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("STOGAS_CONFIDENTIAL_ATTESTER_MODE", "mock")

	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STOGAS_CONFIDENTIAL_ATTESTER_MODE is not supported") {
		t.Fatalf("expected attester env rejection, got %v", err)
	}
}

func TestLoadFromEnvRejectsUnsupportedConfidentialKnobs(t *testing.T) {
	for _, name := range []string{
		"STOGAS_CONFIDENTIAL_ENABLED",
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
		"OPENAI_API_KEY",
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

	config := Config{
		ChutesAPIKey: "host-chutes",
		Confidential: ConfidentialConfig{
			ControlURL: "https://control.stogas.localhost/api/fleet",
		},
	}
	err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{
		"API_KEY_PEPPER":                 "released-api-key-pepper-0123456789",
		"BYOK_ENCRYPTION_SECRET":         "released-byok-encryption-secret-at-least-32-characters",
		"CHUTES_API_KEY":                 "released-chutes",
		"DIAGNOSTICS_CLIENT_SPKI_SHA256": strings.Repeat("d", 64),
		"DRAIN_CLIENT_SPKI_SHA256":       strings.Repeat("e", 64),
		"INFERENCE_TOKEN_PUBLIC_KEY":     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"DATABASE_SCHEMA":                "public_0001_initial_schema",
		"DATABASE_URL":                   "postgres://released:pass@localhost:5432/postgres",
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
	if config.DiagnosticsClientSPKISHA256 != strings.Repeat("d", 64) {
		t.Fatal("diagnostics client pin was not installed from the confidential release")
	}
}

func TestApplyConfidentialRuntimeSecretsFailsClosedForMissingRuntimeSecret(t *testing.T) {
	preserveConfidentialRuntimeEnv(t)
	config := Config{Confidential: ConfidentialConfig{ControlURL: "https://control.stogas.localhost/api/fleet"}}
	err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{
		"DIAGNOSTICS_CLIENT_SPKI_SHA256": strings.Repeat("d", 64),
		"DRAIN_CLIENT_SPKI_SHA256":       strings.Repeat("e", 64),
		"API_KEY_PEPPER":                 "released-api-key-pepper-0123456789",
		"BYOK_ENCRYPTION_SECRET":         "released-byok-encryption-secret-at-least-32-characters",
		"INFERENCE_TOKEN_PUBLIC_KEY":     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"DATABASE_SCHEMA":                "public_0001_initial_schema",
	})
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("expected missing runtime secret error, got %v", err)
	}
}

func TestApplyConfidentialRuntimeSecretsRequiresReleasedDiagnosticsPin(t *testing.T) {
	for _, pin := range []string{"", "host-selected-pin", strings.Repeat("d", 63)} {
		config := Config{DiagnosticsClientSPKISHA256: strings.Repeat("a", 64), Confidential: ConfidentialConfig{Environment: "staging", ControlURL: "https://control.example/api/fleet"}}
		if err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{"DIAGNOSTICS_CLIENT_SPKI_SHA256": pin}); err == nil || !strings.Contains(err.Error(), "diagnostics client SPKI pin") {
			t.Fatal("missing or invalid released pin accepted a host-configured identity")
		}
	}
}

func TestApplyConfidentialRuntimeSecretsRequiresDistinctDrainIdentity(t *testing.T) {
	for _, pin := range []string{"", "invalid", strings.Repeat("d", 64)} {
		config := Config{DrainClientSPKISHA256: strings.Repeat("a", 64), Confidential: ConfidentialConfig{Environment: "staging", ControlURL: "https://control.example/api/fleet"}}
		if err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{"DIAGNOSTICS_CLIENT_SPKI_SHA256": strings.Repeat("d", 64), "DRAIN_CLIENT_SPKI_SHA256": pin}); err == nil || !strings.Contains(err.Error(), "distinct confidential drain") {
			t.Fatal("invalid or shared drain identity accepted", err)
		}
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

	config := Config{Confidential: ConfidentialConfig{ControlURL: "https://control.stogas.localhost/api/fleet"}}
	if err := ApplyConfidentialRuntimeSecrets(&config, fakeSecretLookup{
		"DIAGNOSTICS_CLIENT_SPKI_SHA256": strings.Repeat("d", 64),
		"DRAIN_CLIENT_SPKI_SHA256":       strings.Repeat("e", 64),
		"API_KEY_PEPPER":                 "released-api-key-pepper-0123456789",
		"BYOK_ENCRYPTION_SECRET":         "released-byok-encryption-secret-at-least-32-characters",
		"CHUTES_API_KEY":                 "released-chutes",
		"INFERENCE_TOKEN_PUBLIC_KEY":     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"DATABASE_SCHEMA":                "public_0001_initial_schema",
		"DATABASE_URL":                   "postgres://released:pass@localhost:5432/postgres",
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
	t.Setenv("API_KEY_PEPPER", "01234567890123456789012345678901")
	t.Setenv("BYOK_ENCRYPTION_SECRET", "test-byok-encryption-secret-at-least-32-characters")
	t.Setenv("INFERENCE_TOKEN_PUBLIC_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
}

func preserveConfidentialRuntimeEnv(t *testing.T) {
	t.Helper()
	for _, name := range confidentialRuntimeSecretNames {
		t.Setenv(name, os.Getenv(name))
	}
}

type fakeSecretLookup map[string]string

func (f fakeSecretLookup) Get(name string) (secretstore.Secret, bool) {
	value, ok := f[name]
	return secretstore.Secret{Name: name, Value: []byte(value)}, ok
}

func TestConfidentialConfigRequiresFixedOriginAndInstance(t *testing.T) {
	base := ConfidentialConfig{Enabled: true, Environment: "staging", ControlURL: defaultFleetAPIURLStaging, EntropyTimeout: confidentialEntropyTimeout, AccessClientID: "id", AccessClientSecret: "secret", InstanceID: "00000000-0000-4000-8000-000000000001"}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ConfidentialConfig){
		func(c *ConfidentialConfig) { c.InstanceID = "" }, func(c *ConfidentialConfig) { c.ControlURL = "https://other.test" }, func(c *ConfidentialConfig) { c.ControlAllowHTTP = true }, func(c *ConfidentialConfig) { c.Environment = "local" },
	} {
		bad := base
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe bootstrap config accepted")
		}
	}
}
