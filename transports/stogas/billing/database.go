package billing

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrSchemaIncompatible reports a database schema without a function, argument
// type, result column or privilege that this release uses.
var ErrSchemaIncompatible = errors.New("database schema is incompatible with this gateway")

const (
	poolHealthCheckPeriod     = 30 * time.Second
	poolMaxConnIdleTime       = 5 * time.Minute
	poolMaxConnLifetime       = 30 * time.Minute
	poolMaxConnLifetimeJitter = 5 * time.Minute
)

type DatabasePoolConfig struct {
	MaxConns      int32
	MinConns      int32
	MinIdleConns  int32
	QueryExecMode string
}

type GatewayDB struct {
	pool       *pgxpool.Pool
	schemaName string
}

type DatabaseDiagnostics struct {
	AcquireCount            int64 `json:"acquireCount"`
	AcquireDurationMS       int64 `json:"acquireDurationMs"`
	AcquiredConnections     int32 `json:"acquiredConnections"`
	CanceledAcquireCount    int64 `json:"canceledAcquireCount"`
	ConstructingConnections int32 `json:"constructingConnections"`
	EmptyAcquireCount       int64 `json:"emptyAcquireCount"`
	IdleConnections         int32 `json:"idleConnections"`
	MaxConnections          int32 `json:"maxConnections"`
	MaxIdleDestroyed        int64 `json:"maxIdleDestroyed"`
	MaxLifetimeDestroyed    int64 `json:"maxLifetimeDestroyed"`
	NewConnections          int64 `json:"newConnections"`
	TotalConnections        int32 `json:"totalConnections"`
}

func ValidateDatabaseSchema(databaseSchema string) error {
	_, err := validatePgrollSchemaName(databaseSchema)
	return err
}

func NewGatewayDB(ctx context.Context, databaseURL string, databaseSchema string, databasePool DatabasePoolConfig) (*GatewayDB, error) {
	if err := databasePool.Validate(); err != nil {
		return nil, err
	}
	schemaName, err := validatePgrollSchemaName(databaseSchema)
	if err != nil {
		return nil, err
	}

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse postgres config: %w", err)
	}
	if poolConfig.ConnConfig.TLSConfig != nil {
		poolConfig.ConnConfig.TLSConfig.MinVersion = tls.VersionTLS13
		poolConfig.ConnConfig.TLSConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
		// A TLS-configured connection must never retry through plaintext or classical TLS.
		fallbacks := poolConfig.ConnConfig.Fallbacks[:0]
		for _, fallback := range poolConfig.ConnConfig.Fallbacks {
			if fallback.TLSConfig == nil {
				continue
			}
			fallback.TLSConfig.MinVersion = tls.VersionTLS13
			fallback.TLSConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
			fallbacks = append(fallbacks, fallback)
		}
		poolConfig.ConnConfig.Fallbacks = fallbacks
	}
	poolConfig.MaxConns = databasePool.MaxConns
	poolConfig.MinConns = databasePool.MinConns
	poolConfig.MinIdleConns = databasePool.MinIdleConns
	poolConfig.HealthCheckPeriod = poolHealthCheckPeriod
	poolConfig.MaxConnIdleTime = poolMaxConnIdleTime
	poolConfig.MaxConnLifetime = poolMaxConnLifetime
	poolConfig.MaxConnLifetimeJitter = poolMaxConnLifetimeJitter
	poolConfig.ConnConfig.DefaultQueryExecMode = queryExecMode(databasePool.QueryExecMode)
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = map[string]string{}
	}
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "stogas-gateway"

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return &GatewayDB{pool: pool, schemaName: schemaName}, nil
}

// functionQuery selects the result columns the caller scans by name, so a function
// that adds or reorders columns cannot shift a scan. A scalar result passes "*".
func (db *GatewayDB) functionQuery(functionName string, columns string, arguments string) string {
	return "select " + columns + " from " + pgx.Identifier{db.schemaName, functionName}.Sanitize() + "(\n" + arguments + "\n);"
}

// checkQueries parses each query without running it. Control chooses the schema
// at boot, so a schema that lacks a function, argument type or result column this
// release uses stops the gateway here instead of failing its requests.
func (db *GatewayDB) checkQueries(ctx context.Context, queries ...string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := db.pool.Acquire(checkCtx)
	if err != nil {
		return fmt.Errorf("acquire postgres connection: %w", err)
	}
	defer conn.Release()
	for _, query := range queries {
		if _, err := conn.Conn().Prepare(checkCtx, "", query); err != nil {
			// Class 42 covers missing routines, types, columns and privileges, and
			// 3F000 a missing schema. Other errors, such as a lost connection, are
			// not schema problems.
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && (strings.HasPrefix(pgErr.Code, "42") || pgErr.Code == "3F000") {
				return fmt.Errorf("%w: %s: %w", ErrSchemaIncompatible, db.schemaName, err)
			}
			return fmt.Errorf("check database schema %s: %w", db.schemaName, err)
		}
	}
	return nil
}

func (db *GatewayDB) Close() {
	if db != nil && db.pool != nil {
		db.pool.Close()
	}
}

func (db *GatewayDB) Diagnostics() *DatabaseDiagnostics {
	if db == nil || db.pool == nil {
		return nil
	}
	stats := db.pool.Stat()
	return &DatabaseDiagnostics{
		AcquireCount:            stats.AcquireCount(),
		AcquireDurationMS:       stats.AcquireDuration().Milliseconds(),
		AcquiredConnections:     stats.AcquiredConns(),
		CanceledAcquireCount:    stats.CanceledAcquireCount(),
		ConstructingConnections: stats.ConstructingConns(),
		EmptyAcquireCount:       stats.EmptyAcquireCount(),
		IdleConnections:         stats.IdleConns(),
		MaxConnections:          stats.MaxConns(),
		MaxIdleDestroyed:        stats.MaxIdleDestroyCount(),
		MaxLifetimeDestroyed:    stats.MaxLifetimeDestroyCount(),
		NewConnections:          stats.NewConnsCount(),
		TotalConnections:        stats.TotalConns(),
	}
}

func queryExecMode(mode string) pgx.QueryExecMode {
	switch mode {
	case "cache_describe":
		return pgx.QueryExecModeCacheDescribe
	case "describe_exec":
		return pgx.QueryExecModeDescribeExec
	case "exec":
		return pgx.QueryExecModeExec
	case "simple_protocol":
		return pgx.QueryExecModeSimpleProtocol
	default:
		return pgx.QueryExecModeCacheStatement
	}
}

func validatePgrollSchemaName(databaseSchema string) (string, error) {
	schemaName := strings.TrimSpace(databaseSchema)
	if schemaName == "" {
		return "", fmt.Errorf("DATABASE_SCHEMA is required")
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
