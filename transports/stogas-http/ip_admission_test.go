package stogashttp

import (
	"encoding/json"
	"fmt"
	"hash/maphash"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestIPAdmissionBudgetsCanonicalAddressesAndRefill(t *testing.T) {
	l := newIPAdmission()
	now := time.Unix(100, 0)
	for i := range ipRequestBurst {
		address := "192.0.2.1:80"
		if i%2 == 0 {
			address = "[::ffff:192.0.2.1]:9000"
		}
		if wait, err := l.allow(address, false, now); wait != 0 || err != nil {
			t.Fatalf("burst %d: %v %v", i, wait, err)
		}
	}
	for _, at := range []time.Time{now, now.Add(-time.Second)} {
		if wait, err := l.allow("192.0.2.1:99", false, at); wait != time.Millisecond || err != nil {
			t.Fatalf("exhausted bucket: %v %v", wait, err)
		}
	}
	if wait, err := l.allow("192.0.2.1:80", false, now.Add(time.Millisecond)); wait != 0 || err != nil {
		t.Fatalf("refill: %v %v", wait, err)
	}
	for _, address := range []string{"192.0.2.2:80", "[2001:db8::1]:80", "[2001:db8:0:1::1]:80"} {
		if wait, err := l.allow(address, false, now); wait != 0 || err != nil {
			t.Fatalf("independent address: %v %v", wait, err)
		}
	}
	for i := range ipRequestBurst - 1 {
		if wait, err := l.allow(fmt.Sprintf("[2001:db8::%x]:80", i+2), false, now); wait != 0 || err != nil {
			t.Fatalf("IPv6 /64 burst %d: %v %v", i, wait, err)
		}
	}
	if wait, err := l.allow("[2001:db8::ffff:ffff:ffff:ffff]:80", false, now); wait != time.Millisecond || err != nil {
		t.Fatalf("another address in an exhausted /64: %v %v", wait, err)
	}
	for range ipSetupBurst {
		if wait, err := l.allow("192.0.2.1:80", true, now); wait != 0 || err != nil {
			t.Fatalf("independent setup budget: %v %v", wait, err)
		}
	}
	if wait, err := l.allow("192.0.2.1:80", true, now); wait != 10*time.Millisecond || err != nil {
		t.Fatalf("setup exhaustion: %v %v", wait, err)
	}
	for _, address := range []string{"", "load-balancer", "0.0.0.0:80", "[::]:80", "[::ffff:0.0.0.0]:80", "[fe80::1%eth0]:80", "224.0.0.1:80", "[::ffff:224.0.0.1]:80"} {
		if _, err := l.allow(address, false, now); err == nil {
			t.Fatalf("accepted invalid source %q", address)
		}
	}
	encoded, err := json.Marshal(l.diagnostics())
	if err != nil || strings.Contains(string(encoded), "192.0.2") || l.diagnostics().Entries != 4 {
		t.Fatalf("diagnostics retained addresses or incorrect occupancy: %s %v", encoded, err)
	}
}

func TestIPAdmissionConcurrencyAndBoundedChurn(t *testing.T) {
	l := newIPAdmission()
	now := time.Unix(100, 0)
	var admitted atomic.Int64
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 200 {
				if wait, err := l.allow("192.0.2.1:80", false, now); wait == 0 && err == nil {
					admitted.Add(1)
				}
			}
		})
	}
	workers.Wait()
	if admitted.Load() != ipRequestBurst {
		t.Fatalf("concurrent admission = %d", admitted.Load())
	}
	key := netip.MustParseAddr("192.0.2.1")
	index := maphash.Comparable(l.seed, key) % ipAdmissionShards
	var candidate string
	for i := uint32(1); ; i++ {
		ip := netip.AddrFrom4([4]byte{198, byte(i >> 16), byte(i >> 8), byte(i)})
		if maphash.Comparable(l.seed, ip)%ipAdmissionShards != index {
			continue
		}
		candidate = netip.AddrPortFrom(ip, 80).String()
		if len(l.shards[index].entries) == ipAdmissionEntriesPerShard {
			break
		}
		if wait, err := l.allow(candidate, false, now); wait != 0 || err != nil {
			t.Fatalf("fill: %v %v", wait, err)
		}
	}
	if wait, err := l.allow(candidate, false, now); wait != time.Second || err == nil {
		t.Fatalf("full table: %v %v", wait, err)
	}
	if wait, err := l.allow("192.0.2.1:80", false, now); wait == 0 || err != nil {
		t.Fatalf("churn reset depleted allowance: %v %v", wait, err)
	}
	if wait, err := l.allow("192.0.2.1:80", true, now); wait != 0 || err != nil {
		t.Fatalf("capacity blocked existing source: %v %v", wait, err)
	}
	if wait, err := l.allow(candidate, false, now.Add(2*time.Second)); wait != 0 || err != nil {
		t.Fatalf("full allowance eviction: %v %v", wait, err)
	}
	if l.diagnostics().Entries != 1 || l.diagnostics().CapacityRejected != 1 {
		t.Fatal("table did not recover within its bound")
	}
}

func TestIPAdmissionPrecedesBodiesAndCannotUseForwardingHeaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Server{ipAdmission: newIPAdmission()}
		for range ipRequestBurst {
			_, _ = s.ipAdmission.allow("192.0.2.1:80", false, time.Now())
		}
		called := false
		handler := s.ipRequestAdmission(func(*requestContext) { called = true })
		for _, protocol := range []int{1, 2} {
			request := httptest.NewRequest("OPTIONS", "/v1/session", nil)
			request.RemoteAddr, request.ProtoMajor = "[::ffff:192.0.2.1]:9000", protocol
			request.Header.Set("X-Forwarded-For", "203.0.113.5")
			request.Header.Set("Forwarded", "for=203.0.113.6")
			response := &testResponseWriter{httptest.NewRecorder()}
			handler.ServeHTTP(response, request)
			if called || response.Code != http.StatusTooManyRequests || !slices.Contains([]string{"1", "2"}, response.Header().Get("Retry-After")) || !strings.Contains(response.Body.String(), "ip_rate_limit_exceeded") {
				t.Fatalf("IP rejection: %d %s", response.Code, response.Body)
			}
			if (response.Header().Get("Connection") == "close") != (protocol == 1) {
				t.Fatal("wrong rejected-stream connection handling")
			}
		}
		time.Sleep(time.Millisecond)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/models", nil))
		if !called {
			t.Fatal("request allowance did not recover")
		}
	})
}

func TestIPRequestBudgetAllowsSharedNetworkBurst(t *testing.T) {
	l := newIPAdmission()
	now := time.Unix(100, 0)
	// Eight organizations at the platform's 120-RPS rate share one IP.
	for second := range 5 {
		for account := range 8 {
			for range 120 {
				wait, err := l.allow(fmt.Sprintf("192.0.2.1:%d", 1000+account), false, now.Add(time.Duration(second)*time.Second))
				if wait != 0 || err != nil {
					t.Fatalf("shared network denied: %v %v", wait, err)
				}
			}
		}
	}
}
