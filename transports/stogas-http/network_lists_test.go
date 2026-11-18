package stogashttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"maps"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func gzipLines(t *testing.T, lines ...string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write([]byte(strings.Join(lines, "\n") + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

type storedLists struct {
	mu      sync.Mutex
	sources map[string]string
	data    map[string][]byte
	err     error
	reads   int
}

func (s *storedLists) NetworkListSources(context.Context) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.sources), s.err
}

func (s *storedLists) NetworkList(_ context.Context, kind string) (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return s.sources[kind], s.data[kind], nil
}

func (s *storedLists) store(kind, source string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources[kind], s.data[kind] = source, data
}

func testLists(t *testing.T) *storedLists {
	return &storedLists{
		sources: map[string]string{"countries": "dbip-country-lite-2026-11", "asns": "dbip-asn-lite-2026-11", "tor": "sha256-1", "vpn": "x4bnet-1", "hosting": "x4bnet-1"},
		data: map[string][]byte{
			// DB-IP's files start at the first address, leave gaps and end with IPv6.
			"countries": gzipLines(t,
				"0.0.0.0,0.255.255.255,ZZ", "1.0.0.0,1.0.0.255,AU", "198.51.100.0,198.51.100.127,US",
				"198.51.100.128,198.51.100.255,DE", "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,FR"),
			"asns": gzipLines(t,
				`1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."`, `198.51.100.0,198.51.100.255,64496,"Example"`,
				`203.0.113.0,203.0.113.255,64497,"Hosting, Inc."`, `2001:db8::,2001:db8::ffff,64498,"Six"`),
			"tor":     gzipLines(t, "198.51.100.7", "2001:db8::7"),
			"vpn":     gzipLines(t, "64496"),
			"hosting": gzipLines(t, "64497", "64498"),
		},
	}
}

func TestNetworkListsGiveEachAddressItsFacts(t *testing.T) {
	n, err := startNetworkLists(t.Context(), testLists(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	for address, want := range map[string]policy.Client{
		// A gap between ranges and the space after the last range have no facts.
		"0.0.0.1":         {},
		"1.0.0.0":         {Country: "AU", AS: 13335},
		"1.0.1.0":         {},
		"198.51.100.7":    {Country: "US", AS: 64496, TorExit: true, VPN: true},
		"198.51.100.127":  {Country: "US", AS: 64496, VPN: true},
		"198.51.100.128":  {Country: "DE", AS: 64496, VPN: true},
		"198.51.100.255":  {Country: "DE", AS: 64496, VPN: true},
		"198.51.101.0":    {},
		"203.0.113.9":     {AS: 64497, Hosting: true},
		"255.255.255.255": {},
		"2001:db8::7":     {Country: "FR", AS: 64498, TorExit: true, Hosting: true},
		"2001:db8::1:0":   {Country: "FR"},
		"2001:db9::":      {},
		"::":              {},
	} {
		want.Address = netip.MustParseAddr(address)
		if got := n.client(want.Address); got != want {
			t.Errorf("%s: %+v, want %+v", address, got, want)
		}
	}
	status := n.diagnostics()
	if len(status.Sources) != 5 || status.CheckedAt.IsZero() {
		t.Fatalf("status %+v", status)
	}
	// Without its lists the gateway knows nothing about an address.
	var none *networkLists
	if got := none.client(netip.MustParseAddr("198.51.100.7")); got.Missing != policy.CountryList|policy.ASList|policy.TorExitList|policy.VPNList|policy.HostingList {
		t.Fatalf("no lists: %+v", got)
	}
}

func TestNetworkListsRefuseMalformedLists(t *testing.T) {
	for kind, lines := range map[string][]string{
		"countries": {"198.51.100.0,198.51.100.255,us"},
		"asns":      {"198.51.100.0,198.51.100.255,AS64496"},
		"tor":       {"198.51.100.7", "exit"},
		"vpn":       {"0"},
		"hosting":   {"AS64496"},
	} {
		if err := (&networkTables{}).read(kind, gzipLines(t, lines...)); err == nil {
			t.Errorf("%s accepted %q", kind, lines)
		}
	}
	for name, lines := range map[string][]string{
		"overlap":  {"198.51.100.0,198.51.100.255,US", "198.51.100.255,198.51.101.0,US"},
		"order":    {"198.51.101.0,198.51.101.255,US", "198.51.100.0,198.51.100.255,US"},
		"reversed": {"198.51.100.255,198.51.100.0,US"},
		"families": {"198.51.100.0,2001:db8::,US"},
		"mapped":   {"::ffff:198.51.100.0,::ffff:198.51.100.255,US"},
		"fields":   {"198.51.100.0,198.51.100.255"},
	} {
		if err := (&networkTables{}).read("countries", gzipLines(t, lines...)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := (&networkTables{}).read("countries", []byte("not gzip")); err == nil {
		t.Fatal("read text that is not gzip")
	}
}

// A list that fails to load keeps its last version, and a list that never
// loaded stays missing, while the other lists load.
func TestNetworkListsKeepTheirLastVersion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lists := testLists(t)
		lists.store("tor", "sha256-bad", gzipLines(t, "exit"))
		n, err := startNetworkLists(t.Context(), lists, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer n.close()
		address := netip.MustParseAddr("198.51.100.7")
		if got := n.client(address); got.Missing != policy.TorExitList || got.Country != "US" {
			t.Fatalf("a malformed list loaded: %+v", got)
		}
		if !n.diagnostics().CheckedAt.IsZero() {
			t.Fatal("a failed check counted as a success")
		}
		reads := lists.reads

		lists.store("tor", "sha256-2", gzipLines(t, "198.51.100.7"))
		lists.store("countries", "dbip-country-lite-2026-12", gzipLines(t, "198.51.100.0,198.51.100.255,CA"))
		time.Sleep(networkListsRefreshInterval)
		synctest.Wait()
		if got := n.client(address); got.Missing != 0 || !got.TorExit || got.Country != "CA" {
			t.Fatalf("changed lists did not load: %+v", got)
		}
		// Only the changed lists were read again.
		if lists.reads-reads != 2 || n.diagnostics().CheckedAt.IsZero() {
			t.Fatalf("reads %d after %d, status %+v", lists.reads, reads, n.diagnostics())
		}

		lists.store("countries", "dbip-country-lite-2027-01", gzipLines(t, "bad"))
		lists.mu.Lock()
		delete(lists.sources, "tor")
		lists.mu.Unlock()
		checked := n.diagnostics().CheckedAt
		time.Sleep(networkListsRefreshInterval)
		synctest.Wait()
		if got := n.client(address); got.Country != "CA" || !got.TorExit {
			t.Fatalf("a failed reload replaced a list: %+v", got)
		}
		if status := n.diagnostics(); !status.CheckedAt.Equal(checked) || status.Sources["countries"] != "dbip-country-lite-2026-12" {
			t.Fatalf("status %+v", status)
		}

		// A failed database read stops only the start.
		lists.mu.Lock()
		lists.err = errors.New("database down")
		lists.mu.Unlock()
		time.Sleep(networkListsRefreshInterval)
		synctest.Wait()
		if got := n.client(address); got.Country != "CA" {
			t.Fatalf("a failed check dropped the lists: %+v", got)
		}
		if _, err := startNetworkLists(t.Context(), lists, nil); err == nil {
			t.Fatal("started without the database")
		}
	})
}
