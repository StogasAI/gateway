package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
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

	loadEnv(io.Discard, path, forwardConfigKeys)

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
	if !localEnvironment("local") || !localEnvironment(" LOCAL ") {
		t.Fatal("expected the explicit local environment to allow fallback env")
	}
	if localEnvironment("") || localEnvironment("test") || localEnvironment("testing") || localEnvironment("staging") || localEnvironment("production") || localEnvironment("prod") {
		t.Fatal("non-local environments must not load fallback env")
	}
}

func TestLoadEnvReportsInvalidEnvironmentValues(t *testing.T) {
	t.Setenv("STOGAS_ENVIRONMENT", "local")
	var output bytes.Buffer

	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("STOGAS_ENVIRONMENT=staging\x00invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	loadEnv(&output, path, forwardConfigKeys)

	if got := os.Getenv("STOGAS_ENVIRONMENT"); got != "local" {
		t.Fatalf("STOGAS_ENVIRONMENT = %q, want unchanged local value", got)
	}
	const invalid = "{\"errorType\":\"Error\",\"event\":\"guest_init_warning\",\"reasonCode\":\"invalid_configuration_line\",\"severity\":\"warn\"}\n"
	if got := output.String(); got != invalid {
		t.Fatalf("init log = %q, want %q", got, invalid)
	}
}

func TestInitLogsContainOnlyFixedFields(t *testing.T) {
	var output bytes.Buffer

	path := filepath.Join(t.TempDir(), "secret-config-path")
	contents := "secret malformed line\nSECRET_KEY=secret-value\nOTHER_SECRET=other-value\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	loadEnv(&output, path, forwardConfigKeys)

	const invalid = "{\"errorType\":\"Error\",\"event\":\"guest_init_warning\",\"reasonCode\":\"invalid_configuration_line\",\"severity\":\"warn\"}\n"
	const unsupported = "{\"errorType\":\"Error\",\"event\":\"guest_init_warning\",\"reasonCode\":\"unsupported_configuration_key\",\"severity\":\"warn\"}\n"
	if got, want := output.String(), invalid+unsupported; got != want {
		t.Fatalf("init log = %q, want %q", got, want)
	}
	for _, secret := range []string{"secret-config-path", "secret malformed line", "SECRET_KEY", "secret-value", "OTHER_SECRET", "other-value"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("init log exposed %q: %s", secret, output.String())
		}
	}
}

func TestInitSuccessLogOmitsErrorType(t *testing.T) {
	var output bytes.Buffer

	writeInitEvent(&output, "guest_init_probe", "info", initUpstreamConnectionOK)

	const expected = "{\"event\":\"guest_init_probe\",\"reasonCode\":\"upstream_connection_succeeded\",\"severity\":\"info\"}\n"
	if output.String() != expected {
		t.Fatalf("init log = %q, want %q", output.String(), expected)
	}
}

func TestProbeAddressRequiresAnHTTPOrigin(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "http://127.0.0.1/v1", want: "127.0.0.1:80"},
		{input: "https://api.example/v1", want: "api.example:443"},
		{input: "https://[2001:db8::1]:8443/v1", want: "[2001:db8::1]:8443"},
	} {
		got, err := probeAddress(test.input)
		if err != nil || got != test.want {
			t.Fatalf("probeAddress(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
	for _, input := range []string{"api.example/v1", "file:///etc/passwd", "http:///v1"} {
		if _, err := probeAddress(input); err == nil {
			t.Fatalf("probeAddress(%q) accepted an invalid upstream URL", input)
		}
	}
}
