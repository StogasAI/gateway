package stogashttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

const policyValidationPath = "/v1/policies/validate"

func takeEncryptionKeys(fields map[string]json.RawMessage) (customerkey.Keys, error) {
	raw, present := fields["encryption_keys"]
	delete(fields, "encryption_keys")
	if _, removed := fields["encryption_key"]; removed {
		delete(fields, "encryption_key")
		return nil, customerkey.ErrKey
	}
	if !present {
		return nil, nil
	}
	var encoded map[string]string
	if len(raw) > policy.MaxSourceBytes || json.Unmarshal(raw, &encoded) != nil || encoded == nil {
		return nil, customerkey.ErrKey
	}
	return customerkey.ParseKeys(encoded)
}

func (s *Server) validatePolicy(ctx *requestContext) {
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
	key, err := takeEncryptionKeys(fields)
	if err != nil {
		s.writeBillingError(ctx, err)
		return
	}
	defer key.Clear()
	var sources []billing.PolicyValidationSource
	decoder := json.NewDecoder(bytes.NewReader(fields["policySources"]))
	decoder.DisallowUnknownFields()
	if len(fields) != 1 || decoder.Decode(&sources) != nil || len(sources) < 2 || len(sources) > 36 {
		s.writeError(ctx, 400, map[string]any{"error": map[string]any{"code": "invalid_policy", "message": "Provide policySources as scoped policy objects including organization and key", "type": "invalid_request_error"}})
		return
	}
	if s.runtime == nil || s.runtime.Billing() == nil {
		s.writeBillingError(ctx, billing.ErrGatewayUnavailable)
		return
	}
	claims, err := s.runtime.Billing().AuthorizePolicyValidation(ctx.request.Context(), credential.Raw, credential.Dashboard)
	if err != nil {
		s.writeBillingError(ctx, err)
		return
	}
	result, err := s.runtime.Billing().ValidatePolicySources(sources, claims.OrganizationID, key)
	if err != nil {
		if errors.Is(err, customerkey.ErrKey) || errors.Is(err, billing.ErrGatewayUnavailable) {
			s.writeBillingError(ctx, err)
			return
		}
		// A decrypted error may contain private patterns or member names.
		s.writeError(ctx, 400, map[string]any{"error": map[string]any{"code": "invalid_policy", "message": "Policy execution configuration is invalid", "type": "invalid_request_error"}})
		return
	}
	s.writeJSON(ctx, http.StatusOK, result)
}
