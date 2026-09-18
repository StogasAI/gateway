package stogashttp

import (
	"net/http"
	"runtime"
	"sync"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// Bound synchronous pre-dispatch CPU work separately from long-lived provider
// requests. Keep only active organization IDs, with no queue or retained history.
type preprocessingAdmission struct {
	mu            sync.Mutex
	active        int
	organizations map[string]int
}

func (a *preprocessingAdmission) acquire(organization string, capacity int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if capacity < 1 || a.active >= capacity || a.organizations[organization] >= max(1, (capacity+3)/4) {
		return false
	}
	if a.organizations == nil {
		a.organizations = make(map[string]int)
	}
	a.active++
	a.organizations[organization]++
	return true
}

func (a *preprocessingAdmission) release(organization string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active--
	a.organizations[organization]--
	if a.organizations[organization] == 0 {
		delete(a.organizations, organization)
	}
}

func (s *Server) resolveRequests(claims *billing.APIKeyClaims, input catalog.RequestInput) ([]*catalog.ResolvedRequest, error) {
	if claims == nil || claims.OrganizationID == "" {
		return nil, billing.ErrGatewayUnavailable
	}
	organization := claims.OrganizationID
	// Half the execution slots is an initial admission setting, not a CPU
	// isolation guarantee. Leave room for active streams and control traffic.
	if !s.preprocessing.acquire(organization, max(1, runtime.GOMAXPROCS(0)/2)) {
		return nil, catalog.APIError{
			Code:       "gateway_capacity_exceeded",
			StatusCode: http.StatusServiceUnavailable,
			Type:       "service_unavailable",
			Message:    "Gateway preprocessing capacity is temporarily exhausted",
		}
	}
	defer s.preprocessing.release(organization)
	return catalog.ResolveRequests(input)
}
