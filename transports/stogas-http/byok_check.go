package stogashttp

import (
	"errors"
	"net/http"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// byokCheckPath checks a customer-encrypted credential, which only a gateway can open. The caller
// sends the check grant that Control signed for the credential as its API key, and the key that
// sealed the credential in encryption_keys under its registered label.
const byokCheckPath = "/v1/byok/check"

func (s *Server) checkByok(ctx *requestContext) {
	credential, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return
	}
	if ctx.request.URL.RawQuery != "" {
		s.writeCatalogError(ctx, catalog.ErrInvalidJSON)
		return
	}
	fields, err := catalog.DecodeRequestBody(ctx.body, ctx.memory.admitJSON)
	if err != nil {
		if errors.Is(err, errRequestMemoryCapacity) {
			s.writeRequestMemoryCapacity(ctx)
			return
		}
		s.writeCatalogError(ctx, err)
		return
	}
	keys, err := takeEncryptionKeys(fields)
	if err != nil {
		s.writeBillingError(ctx, err)
		return
	}
	defer keys.Clear()
	if len(fields) != 0 || len(keys) == 0 {
		s.writeError(ctx, http.StatusBadRequest, map[string]any{"error": map[string]any{
			"code": "invalid_request", "type": "invalid_request_error",
			"message": "Send only encryption_keys, with the key that sealed the credential under its registered label",
		}})
		return
	}
	if s.runtime == nil || credential.Check == nil {
		s.writeBillingError(ctx, billing.ErrGatewayUnavailable)
		return
	}
	result, err := s.runtime.CheckByok(ctx.request.Context(), credential.Check, keys)
	if err != nil {
		s.writeBillingError(ctx, err)
		return
	}
	s.writeJSON(ctx, http.StatusOK, result)
}
