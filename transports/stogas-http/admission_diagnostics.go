package stogashttp

import (
	"sync/atomic"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"

	"net/http"
)

type requestAdmissionCounters struct {
	admitted, authentication, billing, permission, rateLimit, invalidRequest, unavailable, internal atomic.Uint64
}

type requestAdmissionDiagnostics struct {
	Admitted       uint64 `json:"admitted"`
	Authentication uint64 `json:"authenticationRejected"`
	Billing        uint64 `json:"billingRejected"`
	Permission     uint64 `json:"permissionRejected"`
	RateLimit      uint64 `json:"rateLimitRejected"`
	InvalidRequest uint64 `json:"invalidRequestRejected"`
	Unavailable    uint64 `json:"unavailableRejected"`
	Internal       uint64 `json:"internalRejected"`
}

func (counters *requestAdmissionCounters) diagnostics() requestAdmissionDiagnostics {
	return requestAdmissionDiagnostics{
		Admitted: counters.admitted.Load(), Authentication: counters.authentication.Load(),
		Billing: counters.billing.Load(), Permission: counters.permission.Load(),
		RateLimit: counters.rateLimit.Load(), InvalidRequest: counters.invalidRequest.Load(),
		Unavailable: counters.unavailable.Load(), Internal: counters.internal.Load(),
	}
}

func (s *Server) recordAdmission(ctx *requestContext) {
	if ctx.admissionCounted {
		return
	}
	ctx.admissionCounted = true
	s.admission.admitted.Add(1)
}

// Capture the inner status before E2EE wraps it in an HTTP 200 response.
// Fixed counters retain neither identities nor client/provider-controlled labels.
func (s *Server) recordAdmissionRejection(ctx *requestContext, status int, code string) {
	if !(ctx.request.Method == http.MethodPost) || !isInferencePath(ctx.request.URL.Path) || status < 400 || ctx.admissionCounted {
		return
	}
	ctx.admissionCounted = true
	var counter *atomic.Uint64
	switch status {
	case http.StatusUnauthorized:
		counter = &s.admission.authentication
	case http.StatusPaymentRequired:
		counter = &s.admission.billing
	case http.StatusForbidden:
		counter = &s.admission.permission
	case http.StatusTooManyRequests:
		counter = &s.admission.rateLimit
	case http.StatusServiceUnavailable:
		counter = &s.admission.unavailable
	default:
		if status < 500 {
			counter = &s.admission.invalidRequest
		} else {
			counter = &s.admission.internal
		}
	}
	counter.Add(1)
	claims := ctx.claims
	if s.runtime == nil || s.runtime.Billing() == nil {
		return
	}
	dashboard := ctx.dashboard
	s.runtime.Billing().RecordCallerFailure(claims, dashboard, status, code)
	if claims == nil {
		return
	}
	requestType := ctx.requestType
	if requestType == "" {
		requestType = "responses_request"
		if ctx.request.URL.Path == "/v1/chat/completions" {
			requestType = "chat_completion_request"
		}
	}
	requestID, err := inferenceRequestID(ctx)
	if err != nil {
		return
	}
	startedAt := ctx.startedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	nodeID := ""
	if s.secure != nil {
		nodeID = s.secure.NodeID()
	}
	s.runtime.Billing().RecordRejection(billing.RejectionInput{
		PolicyVersions: ctx.policyVersions, Claims: claims, RequestID: requestID, RequestType: requestType, Code: code,
		StatusCode: status, CreatedAt: startedAt, NodeID: nodeID, GatewayVersion: stogas.GatewayVersion,
	})
}
