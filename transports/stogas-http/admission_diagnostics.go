package stogashttp

import (
	"sync/atomic"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"

	"github.com/valyala/fasthttp"
)

const requestAdmissionCountedKey = "stogas.admission-counted"
const requestLogClaimsKey = "stogas.request-log-claims"
const requestLogTypeKey = "stogas.request-log-type"

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

func (s *Server) recordAdmission(ctx *fasthttp.RequestCtx) {
	if ctx.UserValue(requestAdmissionCountedKey) != nil {
		return
	}
	ctx.SetUserValue(requestAdmissionCountedKey, true)
	s.admission.admitted.Add(1)
}

// Capture the inner status before E2EE wraps it in an HTTP 200 response.
// Fixed counters retain neither identities nor client/provider-controlled labels.
func (s *Server) recordAdmissionRejection(ctx *fasthttp.RequestCtx, status int, code string) {
	if !ctx.IsPost() || !isInferencePath(ctx.Path()) || status < 400 || ctx.UserValue(requestAdmissionCountedKey) != nil {
		return
	}
	ctx.SetUserValue(requestAdmissionCountedKey, true)
	var counter *atomic.Uint64
	switch status {
	case fasthttp.StatusUnauthorized:
		counter = &s.admission.authentication
	case fasthttp.StatusPaymentRequired:
		counter = &s.admission.billing
	case fasthttp.StatusForbidden:
		counter = &s.admission.permission
	case fasthttp.StatusTooManyRequests:
		counter = &s.admission.rateLimit
	case fasthttp.StatusServiceUnavailable:
		counter = &s.admission.unavailable
	default:
		if status < 500 {
			counter = &s.admission.invalidRequest
		} else {
			counter = &s.admission.internal
		}
	}
	counter.Add(1)
	claims, _ := ctx.UserValue(requestLogClaimsKey).(*billing.APIKeyClaims)
	if claims == nil || s.runtime == nil || s.runtime.Billing() == nil {
		return
	}
	requestType, _ := ctx.UserValue(requestLogTypeKey).(string)
	if requestType == "" {
		requestType = "responses_request"
		if string(ctx.Path()) == "/v1/chat/completions" {
			requestType = "chat_completion_request"
		}
	}
	requestID, err := inferenceRequestID(ctx)
	if err != nil {
		return
	}
	startedAt := ctx.Time()
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	nodeID := ""
	if s.secure != nil && s.secure.Control != nil {
		nodeID = s.secure.Control.NodeID()
	}
	s.runtime.Billing().RecordRejection(billing.RejectionInput{
		Claims: claims, RequestID: requestID, RequestType: requestType, Code: code,
		StatusCode: status, CreatedAt: startedAt, NodeID: nodeID, GatewayVersion: stogas.GatewayVersion,
	})
}
