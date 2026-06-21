package stogas

import "testing"

func TestLoadFromEnvDatabasePoolDefaults(t *testing.T) {
	t.Setenv("INFISICAL_SKIP", "true")
	t.Setenv("AUTH_SECRET", "01234567890123456789012345678901")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/postgres")
	t.Setenv("DATABASE_SCHEMA", "public")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")

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
	t.Setenv("STOGAS_DB_POOL_MAX_CONNS", "2")
	t.Setenv("STOGAS_DB_POOL_MIN_CONNS", "3")

	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("LoadFromEnv returned nil error for invalid pool config")
	}
}

func TestPgrollSearchPathAddsPublicFallback(t *testing.T) {
	searchPath, err := pgrollSearchPath("public_001_initial")
	if err != nil {
		t.Fatalf("pgrollSearchPath returned error: %v", err)
	}
	if searchPath != "public_001_initial,public" {
		t.Fatalf("searchPath = %s, want public_001_initial,public", searchPath)
	}
}

func TestPgrollSearchPathDoesNotDuplicatePublic(t *testing.T) {
	searchPath, err := pgrollSearchPath("public")
	if err != nil {
		t.Fatalf("pgrollSearchPath returned error: %v", err)
	}
	if searchPath != "public" {
		t.Fatalf("searchPath = %s, want public", searchPath)
	}
}

func TestPgrollSearchPathRejectsMalformedSchema(t *testing.T) {
	if _, err := pgrollSearchPath("public;drop schema public"); err == nil {
		t.Fatal("pgrollSearchPath returned nil error for malformed schema")
	}
}
