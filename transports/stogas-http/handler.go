package stogashttp

import (
	"net/http"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// Request state belongs to one handler. Provider work receives its own state
// before it can outlive the handler; it must never retain the response writer.
type requestContext struct {
	request          *http.Request
	writer           http.ResponseWriter
	body             []byte
	requestDigest    *[32]byte
	memory           *requestMemoryLease
	credential       *apiCredential
	claims           *billing.APIKeyClaims
	policyVersions   *billing.PolicyVersions
	dashboard        *billing.DashboardCredential
	encrypted        bool
	requestID        string
	requestType      string
	admissionCounted bool
	startedAt        time.Time
	deliveryDeadline time.Time
	pendingStream    <-chan providerStreamStart
}

type requestHandler func(*requestContext)

func (handler requestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler(&requestContext{request: request, writer: writer, startedAt: time.Now()})
}
