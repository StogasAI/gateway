package billing

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

const sanctionedNetworksFetchTimeout = 10 * time.Second

// NetworkRange is an inclusive client address range in one address family.
type NetworkRange struct{ First, Last netip.Addr }

// SanctionedNetworksSource names the DB-IP month and places of the current list.
func (s *Service) SanctionedNetworksSource(ctx context.Context) (string, error) {
	if s == nil || s.db == nil {
		return "", ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, sanctionedNetworksFetchTimeout)
	defer cancel()
	var source string
	if err := s.db.pool.QueryRow(queryCtx, s.sanctionedSourceQuery).Scan(&source); err != nil {
		return "", fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	return source, nil
}

// SanctionedNetworks reads the client networks that Control refreshes monthly.
func (s *Service) SanctionedNetworks(ctx context.Context) ([]NetworkRange, error) {
	if s == nil || s.db == nil {
		return nil, ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, sanctionedNetworksFetchTimeout)
	defer cancel()
	rows, err := s.db.pool.Query(queryCtx, s.sanctionedNetworksQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	defer rows.Close()
	var ranges []NetworkRange
	for rows.Next() {
		var first, last string
		if err := rows.Scan(&first, &last); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
		}
		item := NetworkRange{}
		if item.First, err = netip.ParseAddr(first); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
		}
		if item.Last, err = netip.ParseAddr(last); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
		}
		ranges = append(ranges, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	return ranges, nil
}
