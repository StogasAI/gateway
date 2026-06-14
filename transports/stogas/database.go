package stogas

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	poolHealthCheckPeriod     = 30 * time.Second
	poolMaxConnIdleTime       = 5 * time.Minute
	poolMaxConnLifetime       = 30 * time.Minute
	poolMaxConnLifetimeJitter = 5 * time.Minute
	poolWarmupTimeout         = 5 * time.Second
	poolWarmupPerConnTimeout  = 2 * time.Second
)

type GatewayDB struct {
	pool *pgxpool.Pool
}

func NewGatewayDB(ctx context.Context, databaseURL string, databaseSchema string, databasePool DatabasePoolConfig) (*GatewayDB, error) {
	if err := databasePool.Validate(); err != nil {
		return nil, err
	}
	searchPath, err := pgrollSearchPath(databaseSchema)
	if err != nil {
		return nil, err
	}

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse postgres config: %w", err)
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
	poolConfig.ConnConfig.RuntimeParams["search_path"] = searchPath
	poolConfig.ConnConfig.RuntimeParams["TimeZone"] = "UTC"

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
	if err := warmPool(ctx, pool, int(poolConfig.MinConns)); err != nil {
		pool.Close()
		return nil, err
	}

	return &GatewayDB{pool: pool}, nil
}

func (db *GatewayDB) Close() {
	if db != nil && db.pool != nil {
		db.pool.Close()
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

func warmPool(parent context.Context, pool *pgxpool.Pool, target int) error {
	if target <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, poolWarmupTimeout)
	defer cancel()
	conns := make([]*pgxpool.Conn, 0, target)
	for i := 0; i < target; i++ {
		acquireCtx, acquireCancel := context.WithTimeout(ctx, poolWarmupPerConnTimeout)
		conn, err := pool.Acquire(acquireCtx)
		acquireCancel()
		if err != nil {
			for _, acquired := range conns {
				acquired.Release()
			}
			return fmt.Errorf("warm postgres pool: %w", err)
		}
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		conn.Release()
	}
	return nil
}
