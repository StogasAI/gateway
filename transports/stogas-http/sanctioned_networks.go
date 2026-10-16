package stogashttp

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// Control loads each monthly list once a day, so checking more often finds
// nothing new.
const sanctionedNetworksRefreshInterval = 24 * time.Hour

// sanctionedNetworkList reads the list and the source that names its version.
type sanctionedNetworkList interface {
	SanctionedNetworksSource(context.Context) (string, error)
	SanctionedNetworks(context.Context) ([]billing.NetworkRange, error)
}

// A failed reload keeps the previous list, so a database outage never admits a
// network that was already refused.
type sanctionedNetworks struct {
	ranges atomic.Pointer[[]billing.NetworkRange]
	// source is written only by start and the refresh goroutine.
	source string
	stop   context.CancelFunc
	done   chan struct{}
}

// startSanctionedNetworks loads the list before the gateway accepts requests.
func startSanctionedNetworks(ctx context.Context, list sanctionedNetworkList, logger schemas.Logger) (*sanctionedNetworks, error) {
	n := &sanctionedNetworks{done: make(chan struct{})}
	if err := n.load(ctx, list); err != nil {
		return nil, err
	}
	refresh, stop := context.WithCancel(context.Background())
	n.stop = stop
	go func() {
		defer close(n.done)
		ticker := time.NewTicker(sanctionedNetworksRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-refresh.Done():
				return
			case <-ticker.C:
				if err := n.load(refresh, list); err != nil && refresh.Err() == nil && logger != nil {
					logger.Warn("sanctioned network refresh failed: %s", err)
				}
			}
		}
	}()
	return n, nil
}

// load reads the full list only when its source changed.
func (n *sanctionedNetworks) load(ctx context.Context, list sanctionedNetworkList) error {
	source, err := list.SanctionedNetworksSource(ctx)
	if err != nil || (n.ranges.Load() != nil && source == n.source) {
		return err
	}
	ranges, err := list.SanctionedNetworks(ctx)
	if err != nil {
		return err
	}
	if ranges, err = mergeNetworkRanges(ranges); err != nil {
		return err
	}
	n.ranges.Store(&ranges)
	n.source = source
	return nil
}

func (n *sanctionedNetworks) close() {
	if n != nil && n.stop != nil {
		n.stop()
		<-n.done
	}
}

// mergeNetworkRanges sorts the ranges and joins overlapping or adjacent ones,
// so one binary search finds any address.
func mergeNetworkRanges(ranges []billing.NetworkRange) ([]billing.NetworkRange, error) {
	for i, item := range ranges {
		item.First, item.Last = item.First.Unmap(), item.Last.Unmap()
		if !item.First.IsValid() || item.First.Zone() != "" || item.Last.Zone() != "" ||
			item.First.BitLen() != item.Last.BitLen() || item.Last.Less(item.First) {
			return nil, errors.New("invalid sanctioned network range")
		}
		ranges[i] = item
	}
	slices.SortFunc(ranges, func(a, b billing.NetworkRange) int { return a.First.Compare(b.First) })
	merged := ranges[:0]
	for _, item := range ranges {
		if n := len(merged); n > 0 && (item.First.Compare(merged[n-1].Last) <= 0 || item.First == merged[n-1].Last.Next()) {
			if merged[n-1].Last.Less(item.Last) {
				merged[n-1].Last = item.Last
			}
			continue
		}
		merged = append(merged, item)
	}
	return merged, nil
}

func (n *sanctionedNetworks) contains(ip netip.Addr) bool {
	if n == nil {
		return false
	}
	_, found := slices.BinarySearchFunc(*n.ranges.Load(), ip, func(item billing.NetworkRange, ip netip.Addr) int {
		if item.Last.Less(ip) {
			return -1
		}
		if ip.Less(item.First) {
			return 1
		}
		return 0
	})
	return found
}

// admitLocation refuses clients in sanctioned places before reading their
// requests. admitIP rejects addresses that do not parse.
func (s *Server) admitLocation(ctx *requestContext) bool {
	peer, err := netip.ParseAddrPort(ctx.request.RemoteAddr)
	if err != nil || !s.sanctionedNetworks.contains(peer.Addr().Unmap()) {
		return true
	}
	closeUnreadRequest(ctx)
	ctx.writer.Header().Set("Cache-Control", "no-store")
	ctx.writer.Header().Set("Access-Control-Allow-Origin", "*")
	s.writeError(ctx, http.StatusUnavailableForLegalReasons, map[string]any{"error": map[string]any{
		"type": "permission_denied", "code": "region_unavailable", "message": "Our service is not available in your region",
	}})
	return false
}
