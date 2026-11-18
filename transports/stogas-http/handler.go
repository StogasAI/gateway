package stogashttp

import (
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// Request state belongs to one handler. Provider work receives its own state
// before it can outlive the handler; it must never retain the response writer.
type requestContext struct {
	request        *http.Request
	writer         http.ResponseWriter
	body           []byte
	requestDigest  *[64]byte
	memory         *requestMemoryLease
	response       *publicResponse
	credential     *apiCredential
	claims         *billing.APIKeyClaims
	policyVersions *billing.LoggedPolicyVersions
	dashboard      *billing.DashboardCredential
	encrypted      bool
	requestID      string
	requestType    string
	// encryptionKeyIDs are the roots the request needs, or, when it lacks one,
	// those it lacks.
	encryptionKeyIDs      []string
	admissionCounted      bool
	startedAt             time.Time
	deliveryDeadline      time.Time
	responseWait          *responseDeadline
	stopClientObservation func()
	// providerRan reports that a provider ran the request or may still be
	// running it, so that a retry by the client could run it twice.
	providerRan atomic.Bool
	// finalize settles a finished inference after its response is complete.
	finalize func()
}

// clientAddress is the address that the client connected from. Behind the
// load balancer it is the PROXY header's source, and forwarding headers never
// set it. Clients of the onion service share its relay's address, so they have
// none, which no network holds.
func (s *Server) clientAddress(ctx *requestContext) netip.Addr {
	peer, err := netip.ParseAddrPort(ctx.request.RemoteAddr)
	if err != nil || peer.Addr().Unmap() == s.config.OnionRelayAddress {
		return netip.Addr{}
	}
	return peer.Addr().Unmap()
}

// transport names how the client reached the gateway.
func (ctx *requestContext) transport() string {
	if ctx.encrypted {
		return policy.TransportE2EE
	}
	if conn, ok := ctx.request.Context().Value(httpConnectionKey{}).(*ingressTLSConn); ok && conn.attested {
		return policy.TransportAttestedTLS
	}
	return policy.TransportHTTPS
}

type requestHandler func(*requestContext)

func (handler requestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler(&requestContext{request: request, writer: writer, startedAt: time.Now()})
}
