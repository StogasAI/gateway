package stogashttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// Control uses a secret before it stores the secret through these paths, so every call to a
// provider comes from the fleet's addresses. Control sends the grant that it signed for the one use
// as the API key, and the secret sealed as it would store it.
const (
	storedByokProbePath     = "/v1/byok/stored/probe"
	storedAzureAccountsPath = "/v1/byok/stored/azure-accounts"
	// A sealed secret of 8 KiB with 64 subscription IDs fits with room to spare.
	storedByokMaxBody = 16 << 10
)

func isStoredByokPath(path string) bool {
	return path == storedByokProbePath || path == storedAzureAccountsPath
}

func (s *Server) probeStoredByok(ctx *requestContext) {
	credential, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return
	}
	var request stogas.StoredByokProbeRequest
	if !s.decodeStoredByokRequest(ctx, &request) {
		return
	}
	if s.runtime == nil || credential.Stored == nil {
		s.writeBillingError(ctx, billing.ErrGatewayUnavailable)
		return
	}
	result, err := s.runtime.ProbeStoredByok(ctx.request.Context(), credential.Stored, request)
	if err != nil {
		s.writeBillingError(ctx, err)
		return
	}
	s.writeJSON(ctx, http.StatusOK, result)
}

func (s *Server) listStoredAzureAccounts(ctx *requestContext) {
	credential, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return
	}
	var request stogas.StoredAzureAccountsRequest
	if !s.decodeStoredByokRequest(ctx, &request) {
		return
	}
	if s.runtime == nil || credential.Stored == nil {
		s.writeBillingError(ctx, billing.ErrGatewayUnavailable)
		return
	}
	result, err := s.runtime.ListStoredAzureAccounts(ctx.request.Context(), credential.Stored, request)
	if err != nil {
		s.writeBillingError(ctx, err)
		return
	}
	s.writeJSON(ctx, http.StatusOK, result)
}

// decodeStoredByokRequest reads one JSON object with only the fields of target, and no query.
func (s *Server) decodeStoredByokRequest(ctx *requestContext, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(ctx.body))
	decoder.DisallowUnknownFields()
	if ctx.request.URL.RawQuery != "" || len(ctx.body) > storedByokMaxBody ||
		decoder.Decode(target) != nil || !errors.Is(decoder.Decode(new(json.RawMessage)), io.EOF) {
		s.writeBillingError(ctx, billing.ErrStoredByokRequest)
		return false
	}
	return true
}
