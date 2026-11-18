package stogashttp

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// Control replaces the Tor exit list every hour and the other lists monthly or
// when it deploys. A check every five minutes is one small query, and it keeps
// a gateway at most five minutes behind Control.
const networkListsRefreshInterval = 5 * time.Minute

// The largest list, DB-IP's AS numbers, is about 30 MiB of text. A list four
// times larger is not one that Control stored.
const maxNetworkListBytes = 128 << 20

// networkListKinds are the lists that access policies read, by the kind that
// Control stores each one as.
var networkListKinds = map[string]policy.NetworkLists{
	"countries": policy.CountryList, "asns": policy.ASList, "tor": policy.TorExitList,
	"vpn": policy.VPNList, "hosting": policy.HostingList,
}

// networkListSource reads the lists and the sources that name their versions.
type networkListSource interface {
	NetworkListSources(context.Context) (map[string]string, error)
	NetworkList(context.Context, string) (string, []byte, error)
}

// networkLists holds the lists that access policies read. A failed reload
// keeps the previous version of a list, and a list that never loaded leaves
// the requests whose policies read it to fail until it does.
type networkLists struct {
	tables atomic.Pointer[networkTables]
	status atomic.Pointer[networkListsStatus]
	stop   context.CancelFunc
	done   chan struct{}
}

// networkTables is one immutable set of loaded lists. A nil table is a list
// that has not loaded.
type networkTables struct {
	sources map[string]string
	// countries gives each address the index of its code in countryCodes,
	// where 0 is no country.
	countries    *addressTable[uint8]
	countryCodes []string
	asns         *addressTable[uint32]
	torExits     map[netip.Addr]struct{}
	vpn, hosting map[uint32]struct{}
}

// networkListsStatus names the version of each list in use and when a check
// of every list last succeeded. A failing check leaves CheckedAt behind, and
// it stays empty until every list has loaded, which the monitor reports.
type networkListsStatus struct {
	Sources   map[string]string `json:"sources"`
	CheckedAt time.Time         `json:"checkedAt,omitzero"`
}

// startNetworkLists loads the lists before the gateway accepts requests. Only
// a failed database read stops the start: a list that Control has not stored,
// or one that does not parse, fails only the requests whose policies read it.
func startNetworkLists(ctx context.Context, source networkListSource, logger schemas.Logger) (*networkLists, error) {
	n := &networkLists{done: make(chan struct{})}
	n.tables.Store(&networkTables{sources: map[string]string{}})
	n.status.Store(&networkListsStatus{Sources: map[string]string{}})
	sources, err := source.NetworkListSources(ctx)
	if err != nil {
		return nil, err
	}
	if err := n.install(ctx, source, sources); err != nil && logger != nil {
		logger.Warn("network lists: %s", err)
	}
	refresh, stop := context.WithCancel(context.Background())
	n.stop = stop
	go func() {
		defer close(n.done)
		ticker := time.NewTicker(networkListsRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-refresh.Done():
				return
			case <-ticker.C:
				if err := n.load(refresh, source); err != nil && refresh.Err() == nil && logger != nil {
					logger.Warn("network list refresh failed: %s", err)
				}
			}
		}
	}()
	return n, nil
}

func (n *networkLists) load(ctx context.Context, source networkListSource) error {
	sources, err := source.NetworkListSources(ctx)
	if err != nil {
		return err
	}
	return n.install(ctx, source, sources)
}

// install reads each list whose source changed. A kind that Control no longer
// stores keeps its loaded version.
func (n *networkLists) install(ctx context.Context, source networkListSource, sources map[string]string) error {
	current := n.tables.Load()
	next := *current
	next.sources = maps.Clone(current.sources)
	var failures []error
	for _, kind := range slices.Sorted(maps.Keys(sources)) {
		if _, known := networkListKinds[kind]; !known || current.sources[kind] == sources[kind] {
			continue
		}
		loaded, data, err := source.NetworkList(ctx, kind)
		if err == nil {
			err = next.read(kind, data)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", kind, err))
			continue
		}
		next.sources[kind] = loaded
	}
	n.tables.Store(&next)
	status := &networkListsStatus{Sources: next.sources, CheckedAt: n.status.Load().CheckedAt}
	if len(failures) == 0 {
		status.CheckedAt = time.Now().UTC()
	}
	n.status.Store(status)
	return errors.Join(failures...)
}

// read replaces one list with gzip text: lines of first,last,value for the
// countries and AS numbers, of which DB-IP adds further fields to the AS
// numbers; one address a line for the Tor exits; one AS number a line for
// VPN and hosting networks. A list that does not parse leaves t unchanged.
func (t *networkTables) read(kind string, data []byte) error {
	unzipped, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	limited := &io.LimitedReader{R: unzipped, N: maxNetworkListBytes + 1}
	lines := bufio.NewScanner(limited)
	lines.Buffer(make([]byte, 0, 64<<10), 64<<10)
	next := *t
	switch kind {
	case "countries":
		codes := []string{""}
		index := map[string]uint8{"": 0}
		next.countries, err = readAddressTable(lines, func(value string) (uint8, error) {
			if value == "ZZ" {
				return 0, nil
			}
			if len(value) != 2 || value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' {
				return 0, fmt.Errorf("%q is not a country code", value)
			}
			if _, ok := index[value]; !ok {
				if len(codes) == 256 {
					return 0, errors.New("too many country codes")
				}
				index[value] = uint8(len(codes))
				codes = append(codes, value)
			}
			return index[value], nil
		})
		next.countryCodes = codes
	case "asns":
		next.asns, err = readAddressTable(lines, parseASN)
	case "tor":
		exits := map[netip.Addr]struct{}{}
		for err == nil && lines.Scan() {
			address, parseErr := netip.ParseAddr(lines.Text())
			if parseErr != nil || address.Zone() != "" {
				err = fmt.Errorf("%q is not an address", lines.Text())
			}
			exits[address.Unmap()] = struct{}{}
		}
		next.torExits = exits
	case "vpn", "hosting":
		numbers := map[uint32]struct{}{}
		for err == nil && lines.Scan() {
			number, parseErr := parseASN(lines.Text())
			if parseErr != nil || number == 0 {
				err = fmt.Errorf("%q is not an AS number", lines.Text())
			}
			numbers[number] = struct{}{}
		}
		if kind == "vpn" {
			next.vpn = numbers
		} else {
			next.hosting = numbers
		}
	}
	if err == nil {
		err = lines.Err()
	}
	if err == nil && limited.N == 0 {
		err = errors.New("list exceeds its size limit")
	}
	if err == nil {
		err = unzipped.Close()
	}
	if err == nil {
		*t = next
	}
	return err
}

func parseASN(value string) (uint32, error) {
	number, err := strconv.ParseUint(value, 10, 32)
	return uint32(number), err
}

// client returns what the lists say about an address.
func (n *networkLists) client(address netip.Addr) policy.Client {
	client := policy.Client{Address: address}
	if n == nil {
		client.Missing = policy.CountryList | policy.ASList | policy.TorExitList | policy.VPNList | policy.HostingList
		return client
	}
	t := n.tables.Load()
	if t.countries == nil {
		client.Missing |= policy.CountryList
	} else {
		client.Country = t.countryCodes[t.countries.lookup(address)]
	}
	if t.asns == nil {
		client.Missing |= policy.ASList
	} else {
		client.AS = t.asns.lookup(address)
	}
	if t.torExits == nil {
		client.Missing |= policy.TorExitList
	} else {
		_, client.TorExit = t.torExits[address]
	}
	if t.vpn == nil {
		client.Missing |= policy.VPNList
	} else if client.AS != 0 {
		_, client.VPN = t.vpn[client.AS]
	}
	if t.hosting == nil {
		client.Missing |= policy.HostingList
	} else if client.AS != 0 {
		_, client.Hosting = t.hosting[client.AS]
	}
	return client
}

func (n *networkLists) diagnostics() *networkListsStatus {
	if n == nil {
		return nil
	}
	return n.status.Load()
}

func (n *networkLists) close() {
	if n != nil && n.stop != nil {
		n.stop()
		<-n.done
	}
}

// addressTable gives each address the value of the range that holds it. It
// keeps the first address of each range and of each gap between ranges, in
// order, so the last first address at or before an address gives its value.
// A gap has the zero value.
type addressTable[V comparable] struct {
	v4       []uint32
	v4Values []V
	v6       [][2]uint64
	v6Values []V
}

// readAddressTable reads lines of first,last,value, in order of first address
// and without overlaps, as DB-IP lists them. Further fields are ignored.
func readAddressTable[V comparable](lines *bufio.Scanner, parse func(string) (V, error)) (*addressTable[V], error) {
	table := &addressTable[V]{}
	var zero V
	// next4 and next6 are the first addresses after the last range, from which
	// a gap starts.
	var next4 uint64
	var next6 [2]uint64
	var end6 bool
	for lines.Scan() {
		fields := strings.SplitN(lines.Text(), ",", 4)
		if len(fields) < 3 {
			return nil, fmt.Errorf("%q is not first,last,value", lines.Text())
		}
		first, errFirst := netip.ParseAddr(fields[0])
		last, errLast := netip.ParseAddr(fields[1])
		if errFirst != nil || errLast != nil || first.Zone() != "" || last.Zone() != "" || first.Is4() != last.Is4() ||
			last.Less(first) || first.Is4In6() || last.Is4In6() {
			return nil, fmt.Errorf("%q is not a range", lines.Text())
		}
		value, err := parse(fields[2])
		if err != nil {
			return nil, err
		}
		if first.Is4() {
			start := uint64(binary.BigEndian.Uint32(first.AsSlice()))
			if start < next4 {
				return nil, fmt.Errorf("%s overlaps or precedes the range before it", first)
			}
			if start > next4 {
				table.v4, table.v4Values = append(table.v4, uint32(next4)), append(table.v4Values, zero)
			}
			table.v4, table.v4Values = append(table.v4, uint32(start)), append(table.v4Values, value)
			next4 = uint64(binary.BigEndian.Uint32(last.AsSlice())) + 1
			continue
		}
		start := key6(first)
		if end6 || compare6(start, next6) < 0 {
			return nil, fmt.Errorf("%s overlaps or precedes the range before it", first)
		}
		if compare6(start, next6) > 0 {
			table.v6, table.v6Values = append(table.v6, next6), append(table.v6Values, zero)
		}
		table.v6, table.v6Values = append(table.v6, start), append(table.v6Values, value)
		next6, end6 = key6(last.Next()), !last.Next().IsValid()
	}
	if len(table.v4) > 0 && next4 <= math.MaxUint32 {
		table.v4, table.v4Values = append(table.v4, uint32(next4)), append(table.v4Values, zero)
	}
	if len(table.v6) > 0 && !end6 {
		table.v6, table.v6Values = append(table.v6, next6), append(table.v6Values, zero)
	}
	return table, lines.Err()
}

func key6(address netip.Addr) [2]uint64 {
	bytes := address.As16()
	return [2]uint64{binary.BigEndian.Uint64(bytes[:8]), binary.BigEndian.Uint64(bytes[8:])}
}

func compare6(a, b [2]uint64) int {
	if order := cmp.Compare(a[0], b[0]); order != 0 {
		return order
	}
	return cmp.Compare(a[1], b[1])
}

func (t *addressTable[V]) lookup(address netip.Addr) V {
	var zero V
	if address.Is4() {
		index, found := slices.BinarySearch(t.v4, binary.BigEndian.Uint32(address.AsSlice()))
		if !found {
			index--
		}
		if index < 0 {
			return zero
		}
		return t.v4Values[index]
	}
	index, found := slices.BinarySearchFunc(t.v6, key6(address), compare6)
	if !found {
		index--
	}
	if index < 0 {
		return zero
	}
	return t.v6Values[index]
}
