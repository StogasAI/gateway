package stogashttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func networkRange(first, last string) billing.NetworkRange {
	return billing.NetworkRange{First: netip.MustParseAddr(first), Last: netip.MustParseAddr(last)}
}

type networkList struct {
	mu        sync.Mutex
	source    string
	ranges    []billing.NetworkRange
	err, read error
	reads     int
}

func (l *networkList) set(source string, ranges []billing.NetworkRange, err, read error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.source, l.ranges, l.err, l.read = source, ranges, err, read
}

func (l *networkList) SanctionedNetworksSource(context.Context) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.source, l.err
}

func (l *networkList) SanctionedNetworks(context.Context) ([]billing.NetworkRange, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reads++
	return slices.Clone(l.ranges), l.read
}

func (l *networkList) readCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reads
}

func TestSanctionedNetworksMergeRangesAndFindBoundaries(t *testing.T) {
	n, err := startSanctionedNetworks(t.Context(), &networkList{ranges: []billing.NetworkRange{
		networkRange("2001:db8::", "2001:db8::ffff"),
		networkRange("198.51.100.16", "198.51.100.31"),
		networkRange("198.51.100.0", "198.51.100.15"),
		networkRange("198.51.100.8", "198.51.100.20"),
		networkRange("::ffff:192.0.2.0", "::ffff:192.0.2.255"),
		networkRange("255.255.255.255", "255.255.255.255"),
		networkRange("::", "::"),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	if got := len(*n.ranges.Load()); got != 5 {
		t.Fatalf("merged ranges = %d, want 5", got)
	}
	for address, want := range map[string]bool{
		"192.0.1.255": false, "192.0.2.0": true, "192.0.2.255": true, "192.0.3.0": false,
		"198.51.100.0": true, "198.51.100.31": true, "198.51.100.32": false,
		"255.255.255.254": false, "255.255.255.255": true, "::": true, "::1": false,
		"2001:db8::ffff": true, "2001:db8::1:0": false,
	} {
		if got := n.contains(netip.MustParseAddr(address)); got != want {
			t.Errorf("contains(%s) = %v, want %v", address, got, want)
		}
	}
	for _, invalid := range [][]billing.NetworkRange{
		{networkRange("198.51.100.1", "198.51.100.0")},
		{networkRange("198.51.100.0", "2001:db8::")},
		{{Last: netip.MustParseAddr("198.51.100.0")}},
	} {
		if _, err := mergeNetworkRanges(invalid); err == nil {
			t.Errorf("accepted invalid range %v", invalid)
		}
	}
}

func TestSanctionedNetworksStartFailsAndRefreshReadsOnlyChangedLists(t *testing.T) {
	failure := errors.New("database unavailable")
	for _, list := range []*networkList{{err: failure}, {read: failure}} {
		if _, err := startSanctionedNetworks(t.Context(), list, nil); !errors.Is(err, failure) {
			t.Fatalf("start error = %v", err)
		}
	}
	synctest.Test(t, func(t *testing.T) {
		september := []billing.NetworkRange{networkRange("198.51.100.0", "198.51.100.15")}
		october := []billing.NetworkRange{networkRange("203.0.113.0", "203.0.113.255")}
		list := &networkList{source: "september", ranges: september}
		n, err := startSanctionedNetworks(t.Context(), list, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer n.close()
		blocked := netip.MustParseAddr("198.51.100.1")
		refresh := func() {
			time.Sleep(sanctionedNetworksRefreshInterval)
			synctest.Wait()
		}
		refresh()
		if list.readCount() != 1 || !n.contains(blocked) {
			t.Fatal("refresh read an unchanged list")
		}
		for _, failed := range []*networkList{{err: failure}, {source: "october", read: failure}} {
			list.set(failed.source, nil, failed.err, failed.read)
			refresh()
			if !n.contains(blocked) {
				t.Fatal("failed refresh dropped the previous list")
			}
		}
		list.set("october", october, nil, nil)
		refresh()
		if list.readCount() != 3 || n.contains(blocked) || !n.contains(netip.MustParseAddr("203.0.113.1")) {
			t.Fatal("refresh did not replace the changed list")
		}
	})
}

func TestSanctionedNetworksRefuseClientsBeforeReadingRequests(t *testing.T) {
	n, err := startSanctionedNetworks(t.Context(), &networkList{ranges: []billing.NetworkRange{
		networkRange("198.51.100.0", "198.51.100.15"),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	s := &Server{ipAdmission: newIPAdmission(), sanctionedNetworks: n}
	called := false
	handler := s.ipRequestAdmission(func(*requestContext) { called = true })

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	request.RemoteAddr = "[::ffff:198.51.100.15]:9000"
	response := &testResponseWriter{httptest.NewRecorder()}
	handler.ServeHTTP(response, request)
	var body struct {
		Error struct{ Type, Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if called || response.Code != http.StatusUnavailableForLegalReasons || body.Error.Code != "region_unavailable" ||
		response.Header().Get("Access-Control-Allow-Origin") != "*" || response.Header().Get("Connection") != "close" {
		t.Fatalf("sanctioned client: %d %s", response.Code, response.Body)
	}
	if s.ipAdmission.diagnostics().Request.Attempts != 0 {
		t.Fatal("sanctioned client used the IP rate limit")
	}

	request.RemoteAddr = "198.51.100.16:9000"
	handler.ServeHTTP(&testResponseWriter{httptest.NewRecorder()}, request)
	if !called {
		t.Fatal("client outside the list was refused")
	}
}
