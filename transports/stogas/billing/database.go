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
	// Six connections serve about 1,000 authorizations a second. A transaction
	// pooler shares its few server connections among all gateways, so more
	// would add no database capacity. All six stay open: an idle client
	// connection holds no server connection, and a burst then waits for no
	// new ones.
	poolConns                 = 6
	poolHealthCheckPeriod     = 30 * time.Second
	poolMaxConnLifetime       = 30 * time.Minute
	poolMaxConnLifetimeJitter = 5 * time.Minute
	// pgx pings a connection idle for over a second before handing it out,
	// which adds a round trip to most requests on a quiet gateway. Network
	// devices drop idle connections after minutes, such as AWS load balancers
	// after 350 seconds, so a minute still checks every connection they may
	// have dropped.
	poolPingAfterIdle = time.Minute
)

type GatewayDB struct {
	pool *pgxpool.Pool
	// settlement holds one more connection for the settlement worker alone.
	// pgxpool serves waiters in arrival order, so on the shared pool each call
	// would wait behind every queued authorization, and an overloaded gateway
	// would settle too slowly to free its settlement places.
	settlement *pgxpool.Pool
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
	MaxLifetimeDestroyed    int64 `json:"maxLifetimeDestroyed"`
	NewConnections          int64 `json:"newConnections"`
	TotalConnections        int32 `json:"totalConnections"`
}

func ValidateDatabaseSchema(databaseSchema string) error {
	_, err := validatePgrollSchemaName(databaseSchema)
	return err
}

func NewGatewayDB(ctx context.Context, databaseURL string, databaseSchema string) (*GatewayDB, error) {
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
	poolConfig.MaxConns, poolConfig.MinConns = poolConns, poolConns
	poolConfig.HealthCheckPeriod = poolHealthCheckPeriod
	poolConfig.MaxConnLifetime = poolMaxConnLifetime
	poolConfig.MaxConnLifetimeJitter = poolMaxConnLifetimeJitter
	poolConfig.ShouldPing = func(_ context.Context, params pgxpool.ShouldPingParams) bool {
		return params.IdleDuration > poolPingAfterIdle
	}
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = map[string]string{}
	}
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "stogas-gateway"
	settlementConfig := poolConfig.Copy()
	settlementConfig.MaxConns, settlementConfig.MinConns = 1, 1

	pool, err := openPool(ctx, poolConfig)
	if err != nil {
		return nil, err
	}
	settlement, err := openPool(ctx, settlementConfig)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &GatewayDB{pool: pool, settlement: settlement, schemaName: schemaName}, nil
}

func openPool(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}

// functionQuery selects the result columns the caller scans by name, so a function
// that adds or reorders columns cannot shift a scan. A scalar result passes "*".
func (db *GatewayDB) functionQuery(functionName string, columns string, arguments string) string {
	return "select " + columns + " from " + pgx.Identifier{db.schemaName, functionName}.Sanitize() + "(\n" + arguments + "\n);"
}

// checkQueries plans each query without running it. Control chooses the schema
// at boot, so a schema that lacks a function, argument type, result column or
// execute privilege this release uses stops the gateway here instead of failing
// its requests. Preparing would miss the privilege, which PostgreSQL checks
// only when a plan starts; EXPLAIN starts the plan and runs nothing.
func (db *GatewayDB) checkQueries(ctx context.Context, queries ...string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := db.pool.Acquire(checkCtx)
	if err != nil {
		return fmt.Errorf("acquire postgres connection: %w", err)
	}
	defer conn.Release()
	for _, query := range queries {
		// GENERIC_PLAN accepts the parameter symbols without values, which only
		// the simple query protocol sends.
		if _, err := conn.Conn().PgConn().Exec(checkCtx, "explain (generic_plan) "+query).ReadAll(); err != nil {
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
	if db == nil {
		return
	}
	if db.pool != nil {
		db.pool.Close()
	}
	if db.settlement != nil {
		db.settlement.Close()
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
		MaxLifetimeDestroyed:    stats.MaxLifetimeDestroyCount(),
		NewConnections:          stats.NewConnsCount(),
		TotalConnections:        stats.TotalConns(),
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
