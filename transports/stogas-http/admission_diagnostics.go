package stogashttp

import (
	"sync/atomic"

	"github.com/valyala/fasthttp"
)

const requestAdmissionCountedKey = "stogas.admission-counted"

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
func (s *Server) recordAdmissionRejection(ctx *fasthttp.RequestCtx, status int) {
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
}
