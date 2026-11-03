package stogashttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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
	// Control let the member of a grant check policy text for the organization, so their check
	// reads nothing from the database.
	var organizationID string
	if credential.PolicyCheck != nil {
		organizationID = credential.PolicyCheck.OrganizationID
	} else {
		claims, err := s.runtime.Billing().AuthorizePolicyValidation(ctx.request.Context(), credential.Raw, credential.Dashboard)
		if err != nil {
			s.writeBillingError(ctx, err)
			return
		}
		organizationID = claims.OrganizationID
	}
	result, err := s.runtime.Billing().ValidatePolicySources(sources, organizationID, key)
	if err != nil {
		if errors.Is(err, customerkey.ErrKey) || errors.Is(err, billing.ErrGatewayUnavailable) {
			s.writeBillingError(ctx, err)
			return
		}
		s.writeError(ctx, 400, map[string]any{"error": map[string]any{"code": "invalid_policy", "message": invalidPolicyMessage(err, len(key) > 0), "type": "invalid_request_error"}})
		return
	}
	s.writeJSON(ctx, http.StatusOK, result)
}

// invalidPolicyMessage says what is wrong with the sources unless the request sent keys: then
// the error may come from decrypted settings, and could repeat a private pattern or member name.
// Without keys nothing opened, so the error names only what the caller sent.
func invalidPolicyMessage(err error, opened bool) string {
	const message = "Policy configuration is invalid"
	detail, ok := strings.CutPrefix(err.Error(), policy.ErrInvalidConfig.Error()+": ")
	if opened || !errors.Is(err, policy.ErrInvalidConfig) || !ok || detail == "" {
		return message
	}
	return message + ": " + detail
}
