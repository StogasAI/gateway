package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestForwardConfigEnvIsWhitelisted(t *testing.T) {
	t.Setenv("STOGAS_ENVIRONMENT", "")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID", "")
	t.Setenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET", "")
	t.Setenv("STOGAS_IGVM_MODE", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256", "")

	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte(`
STOGAS_ENVIRONMENT=staging
STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID=access-client
STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET=access-secret
STOGAS_IGVM_MODE=sev-snp
OPENAI_API_KEY=host-openai
STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256=host-cert
`), 0o600); err != nil {
		t.Fatal(err)
	}

	loadEnv(path, forwardConfigKeys)

	if got := os.Getenv("STOGAS_ENVIRONMENT"); got != "staging" {
		t.Fatalf("STOGAS_ENVIRONMENT = %q, want staging", got)
	}
	if got := os.Getenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID"); got != "access-client" {
		t.Fatalf("STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID = %q, want access-client", got)
	}
	if got := os.Getenv("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET"); got != "access-secret" {
		t.Fatalf("STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET = %q, want access-secret", got)
	}
	if got := os.Getenv("STOGAS_IGVM_MODE"); got != "" {
		t.Fatalf("STOGAS_IGVM_MODE should not be accepted from forward config, got %q", got)
	}
	if got := os.Getenv("OPENAI_API_KEY"); got != "" {
		t.Fatalf("OPENAI_API_KEY should not be accepted from forward config, got %q", got)
	}
	if got := os.Getenv("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256"); got != "" {
		t.Fatalf("STOGAS_CONFIDENTIAL_ACTIVE_CERT_SHA256 should not be accepted, got %q", got)
	}
}

func TestFallbackEnvIsLocalOnly(t *testing.T) {
	if !localEnvironment("") || !localEnvironment("local") || !localEnvironment("testing") {
		t.Fatal("expected empty/local/testing environments to allow fallback env")
	}
	if localEnvironment("staging") || localEnvironment("production") || localEnvironment("prod") {
		t.Fatal("production-like environments must not load fallback env")
	}
}
