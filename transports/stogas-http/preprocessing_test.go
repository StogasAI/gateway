package stogashttp

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestPreprocessingAdmissionBoundsAndReleases(t *testing.T) {
	var admission preprocessingAdmission
	for _, capacity := range []int{1, 2, 4, 8} {
		for index := range capacity {
			if !admission.acquire(fmt.Sprint(index), capacity) {
				t.Fatal("rejected free slot")
			}
		}
		if admission.acquire("extra", capacity) {
			t.Fatal("exceeded global capacity")
		}
		for index := range capacity {
			admission.release(fmt.Sprint(index))
		}
		if admission.active != 0 || len(admission.organizations) != 0 {
			t.Fatal("retained idle state")
		}
	}
	if !admission.acquire("same-org", 4) || admission.acquire("same-org", 4) {
		t.Fatal("organization share not enforced")
	}
	if !admission.acquire("another-org", 4) {
		t.Fatal("one organization blocked another")
	}
	admission.release("same-org")
	admission.release("another-org")
}

func TestPreprocessingAdmissionConcurrent(t *testing.T) {
	var admission preprocessingAdmission
	var workers sync.WaitGroup
	for index := range 100 {
		workers.Go(func() {
			organization := fmt.Sprint(index % 7)
			for range 100 {
				if !admission.acquire(organization, 4) {
					continue
				}
				admission.mu.Lock()
				if admission.active > 4 || admission.organizations[organization] != 1 {
					t.Error("admission invariant broken")
				}
				admission.mu.Unlock()
				admission.release(organization)
			}
		})
	}
	workers.Wait()
	if admission.active != 0 || len(admission.organizations) != 0 {
		t.Fatal("leaked admission")
	}
}

func TestPreprocessingRejectsBeforeResolutionAndReleasesAfterError(t *testing.T) {
	server := &Server{}
	claims := &billing.APIKeyClaims{OrganizationID: "org"}
	capacity := max(1, runtime.GOMAXPROCS(0)/2)
	share := max(1, (capacity+3)/4)
	for range share {
		if !server.preprocessing.acquire("org", capacity) {
			t.Fatal("acquire")
		}
	}
	_, err := server.resolveRequests(claims, catalog.RequestInput{Path: "/not-a-route"})
	var apiError catalog.APIError
	if !errors.As(err, &apiError) || apiError.StatusCode != http.StatusServiceUnavailable || apiError.Code != "gateway_capacity_exceeded" {
		t.Fatalf("expected capacity rejection before route lookup: %v", err)
	}
	for range share {
		server.preprocessing.release("org")
	}
	_, err = server.resolveRequests(claims, catalog.RequestInput{Path: "/not-a-route"})
	if !errors.Is(err, catalog.ErrRouteUnavailable) {
		t.Fatalf("unexpected error: %v", err)
	}
	if server.preprocessing.active != 0 || len(server.preprocessing.organizations) != 0 {
		t.Fatal("failed resolution leaked capacity")
	}
	if _, err := server.resolveRequests(nil, catalog.RequestInput{}); !errors.Is(err, billing.ErrGatewayUnavailable) {
		t.Fatal("missing identity was accepted")
	}
}
