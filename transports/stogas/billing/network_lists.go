package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// A country or AS list is a few megabytes of gzip text.
const networkListFetchTimeout = 30 * time.Second

// NetworkListSources names the version of each list that Control has loaded,
// by kind.
func (s *Service) NetworkListSources(ctx context.Context) (map[string]string, error) {
	if s == nil || s.db == nil {
		return nil, ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, sanctionedNetworksFetchTimeout)
	defer cancel()
	rows, err := s.db.pool.Query(queryCtx, s.networkListSourcesQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	sources, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) ([2]string, error) {
		var kind, source string
		err := row.Scan(&kind, &source)
		return [2]string{kind, source}, err
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	out := make(map[string]string, len(sources))
	for _, entry := range sources {
		out[entry[0]] = entry[1]
	}
	return out, nil
}

// NetworkList reads one list as gzip text, with the source that names its
// version.
func (s *Service) NetworkList(ctx context.Context, kind string) (string, []byte, error) {
	if s == nil || s.db == nil {
		return "", nil, ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, networkListFetchTimeout)
	defer cancel()
	var source string
	var data []byte
	if err := s.db.pool.QueryRow(queryCtx, s.networkListQuery, kind).Scan(&source, &data); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, fmt.Errorf("network list %s is not loaded", kind)
		}
		return "", nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	return source, data, nil
}
