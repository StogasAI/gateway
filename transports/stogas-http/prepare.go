package stogashttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

type candidateFailureKind uint8

const (
	candidateFailureCatalog candidateFailureKind = iota
	candidateFailureBilling
	candidateFailureRequest
)

type candidateFailure struct {
	err  error
	kind candidateFailureKind
}

type preparedCandidate struct {
	adapter    stogas.Adapter
	bifrostCtx *schemas.BifrostContext
	bifrostReq *schemas.BifrostRequest
	cancel     context.CancelFunc
	resolution *catalog.ResolvedRequest
	state      *stogas.State
}

func (s *Server) prepareInference(ctx *requestContext, requestStartedAt time.Time) *preparedCandidate {
	lease := ctx.memory
	credential, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return nil
	}
	ctx.credential = nil
	decodeStarted := time.Now()
	s.jsonDecode.start()
	fields, err := catalog.DecodeRequestBody(ctx.body, lease.admitJSON)
	s.jsonDecode.finish(time.Since(decodeStarted), uint64(len(ctx.body)))
	if err != nil {
		if errors.Is(err, errRequestMemoryCapacity) {
			s.writeRequestMemoryCapacity(ctx)
			return nil
		}
		s.writeCatalogError(ctx, err)
		return nil
	}
	credential.EncryptionKeys, err = takeEncryptionKeys(fields)
	if err != nil {
		s.writeBillingError(ctx, err)
		return nil
	}
	defer credential.EncryptionKeys.Clear()
	nodeID := ""
	if s.secure != nil {
		nodeID = s.secure.NodeID()
	}
	keyConfig, err := s.keyConfigForCredential(credential)
	if keyConfig != nil {
		ctx.policyVersions = keyConfig.Versions
	}
	if credential.Dashboard != nil && keyConfig != nil && keyConfig.Claims != nil {
		ctx.claims = keyConfig.Claims
	}
	if err != nil {
		s.writeBillingError(ctx, err)
		return nil
	}
	policyMemory := s.memory.newLease(requestLifetimeMemory)
	defer policyMemory.release()
	policyBytes := keyConfig.MemoryBytes()
	if !policyMemory.grow(int(policyBytes)) {
		s.writeRequestMemoryCapacity(ctx)
		return nil
	}
	if keyConfig.Config.DeniedAt(requestStartedAt.UTC()) {
		s.writeError(ctx, http.StatusForbidden, map[string]any{
			"error": map[string]any{
				"message": "Request is not allowed at this time",
				"type":    "permission_denied",
				"code":    "schedule_denied",
			},
		})
		return nil
	}
	var preparedCredential *billing.PreparedCredential
	var candidateBudget policy.SourceBudget
	defer func() { preparedCredential.Clear() }()
	finishPreprocessing := s.preprocessing.begin(len(ctx.body))
	defer finishPreprocessing()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Body:                 ctx.body,
		Fields:               fields,
		Method:               ctx.request.Method,
		Path:                 ctx.request.URL.Path,
		Policy:               keyConfig.Config,
		AvailableCredentials: keyConfig.AvailableCredentials(credential.EncryptionKeys),
		DeploymentEligible:   stogas.CredentialDeploymentFilter(keyConfig, requestStartedAt),
		LoadRedactionPolicy:  keyConfig.RedactionPolicy,
		ReserveBody: func(bytes int) error {
			if !lease.resize(max(cap(ctx.body), bytes)) {
				return errRequestMemoryCapacity
			}
			return nil
		},
		CompileRequestPolicy: func(raw []byte) (*policy.Request, error) {
			return policy.CompileRequest(raw, keyConfig.Claims.OrganizationID, credential.EncryptionKeys)
		},
		CheckCandidate: func(provider schemas.ModelProvider, index int, _ catalog.Deployment) error {
			candidate, err := s.runtime.Billing().PrepareCredential(keyConfig, string(provider), index, credential.EncryptionKeys)
			if err == nil {
				err = stogas.ValidatePreparedCredential(candidate, provider)
			}
			if err != nil {
				candidate.Clear()
				public := stogas.PublicBillingErrorFor(err)
				return errors.Join(err, catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message})
			}
			preparedCredential = candidate
			return nil
		},
		CredentialPolicy: func(provider schemas.ModelProvider, index int) (catalog.RequestPolicy, error) {
			selected, err := keyConfig.PolicyForCredential(string(provider), index, credential.EncryptionKeys, requestStartedAt, &candidateBudget)
			if err != nil {
				if errors.Is(err, policy.ErrSourceBudget) {
					return catalog.RequestPolicy{}, err
				}
				public := stogas.PublicBillingErrorFor(err)
				return catalog.RequestPolicy{}, errors.Join(err, catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message})
			}
			if selected.Config.DeniedAt(requestStartedAt.UTC()) {
				return catalog.RequestPolicy{}, catalog.APIError{Code: "schedule_denied", StatusCode: http.StatusForbidden, Type: "permission_denied", Message: "Request is not allowed at this time"}
			}
			return catalog.RequestPolicy{Config: selected.Config, LoadActivePlugins: func(config *policy.Config) (*policy.ActivePlugins, error) {
				compiled, err := keyConfig.ActivePlugins(config, credential.EncryptionKeys)
				if err != nil {
					public := stogas.PublicBillingErrorFor(err)
					return nil, errors.Join(err, catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message})
				}
				return compiled, nil
			}}, nil
		},
	})
	if err != nil {
		if errors.Is(err, errRequestMemoryCapacity) {
			s.writeRequestMemoryCapacity(ctx)
			return nil
		}
		s.writeCatalogError(ctx, err)
		return nil
	}
	if grown := keyConfig.MemoryBytes() - policyBytes; grown > 0 && !policyMemory.grow(int(grown)) {
		s.writeRequestMemoryCapacity(ctx)
		return nil
	}
	ctx.requestType = string(resolution.RequestType)
	prepared, failure := s.prepareCandidate(
		ctx,
		resolution,
		credential,
		nodeID,
		requestStartedAt,
		keyConfig,
		preparedCredential,
		finishPreprocessing,
	)
	keyConfig = nil
	policyMemory.release()
	if prepared == nil {
		if failure == nil {
			s.writeCatalogError(ctx, catalog.ErrModelUnavailable)
			return nil
		}
		switch failure.kind {
		case candidateFailureBilling:
			s.writeBillingError(ctx, failure.err)
		case candidateFailureRequest:
			s.writeError(ctx, http.StatusBadRequest, map[string]any{
				"error": map[string]any{"message": failure.err.Error(), "type": "invalid_request_error"},
			})
		default:
			s.writeCatalogError(ctx, failure.err)
		}
		return nil
	}
	return prepared
}

func (s *Server) keyConfigForCredential(credential apiCredential) (*billing.KeyConfigSnapshot, error) {
	if s == nil || s.runtime == nil || s.runtime.Billing() == nil {
		return nil, billing.ErrGatewayUnavailable
	}
	if credential.Dashboard != nil {
		return s.runtime.Billing().ConfigForDashboard(context.Background(), credential.Dashboard, credential.EncryptionKeys)
	}
	return s.runtime.Billing().ConfigForAPIKey(context.Background(), credential.Raw, credential.Claims, credential.EncryptionKeys)
}

func (s *Server) prepareCandidate(
	ctx *requestContext,
	resolution *catalog.ResolvedRequest,
	credential apiCredential,
	nodeID string,
	requestStartedAt time.Time,
	keyConfig *billing.KeyConfigSnapshot,
	preparedCredential *billing.PreparedCredential,
	finishPreprocessing func(),
) (*preparedCandidate, *candidateFailure) {
	adapter := stogas.AdapterFor(resolution.Provider)
	candidateCredential := credential
	bifrostCtx, state, cancel, err := newRequestContext(
		ctx,
		resolution,
		candidateCredential,
		adapter,
		nodeID,
	)
	if err != nil {
		return nil, &candidateFailure{err: err, kind: candidateFailureRequest}
	}
	state.StartedAt = requestStartedAt
	if keyConfig != nil && keyConfig.Claims != nil {
		state.Export = s.exports.Start(keyConfig.Claims.OrganizationID, state.RequestID, resolution.ExportConfig)
	}
	resolution.ExportConfig = nil
	failBeforeHold := func(err error, kind candidateFailureKind) (*preparedCandidate, *candidateFailure) {
		state.EncryptionKeys = nil
		public := catalog.PublicError(err)
		state.ProcessingError = &schemas.BifrostError{StatusCode: &public.StatusCode, Error: &schemas.ErrorField{Code: schemas.Ptr(public.Code)}}
		stogas.FinalizeExportState(state)
		cancel()
		return nil, &candidateFailure{err: err, kind: kind}
	}
	state.KeyConfig = keyConfig
	state.PreparedCredential = preparedCredential
	if keyConfig != nil {
		selected, err := keyConfig.PolicyForCredential(string(resolution.Provider), resolution.CredentialIndex, credential.EncryptionKeys, requestStartedAt, nil)
		if err != nil {
			return failBeforeHold(err, candidateFailureBilling)
		}
		state.PolicyVersions = selected.Versions
		ctx.policyVersions = selected.Versions
	}
	configureProviderStreamIdleTimeout(bifrostCtx, state)
	if err := adapter.ValidateRequest(state); err != nil {
		return failBeforeHold(err, candidateFailureCatalog)
	}
	if err := adapter.SanitizeRequest(state); err != nil {
		return failBeforeHold(err, candidateFailureCatalog)
	}
	if err := adapter.EstimateHold(state); err != nil {
		return failBeforeHold(err, candidateFailureCatalog)
	}
	bifrostReq, err := resolution.ToBifrost(bifrostCtx)
	if err != nil {
		return failBeforeHold(err, candidateFailureCatalog)
	}
	state.Export.Input(bifrostReq)
	if err := stogas.PrepareProviderRequest(bifrostCtx, state, bifrostReq); err != nil {
		return failBeforeHold(err, candidateFailureCatalog)
	}

	// Selection and the single input transformation are complete. Database and
	// provider waits are excluded from preprocessing; no failure can reroute.
	finishPreprocessing()
	err = stogas.AuthorizeState(bifrostCtx, s.runtime.Billing(), state)
	if state.Authorization != nil {
		s.recordAdmission(ctx)
	}
	if err != nil {
		finalizePreparedFailure(bifrostCtx, s.runtime.Billing(), state, err)
		state.EncryptionKeys = nil
		cancel()
		return nil, &candidateFailure{err: err, kind: candidateFailureBilling}
	}
	if err := s.runtime.ApplyUpstreamCredentials(bifrostCtx, state); err != nil {
		finalizePreparedFailure(bifrostCtx, s.runtime.Billing(), state, err)
		cancel()
		return nil, &candidateFailure{err: err, kind: candidateFailureBilling}
	}
	if resolution.Provider == schemas.Azure {
		bifrostReq, err = resolution.ToBifrost(bifrostCtx)
		if err == nil {
			err = stogas.PrepareProviderRequest(bifrostCtx, state, bifrostReq)
		}
		if err != nil {
			finalizePreparedFailure(bifrostCtx, s.runtime.Billing(), state, err)
			cancel()
			return nil, &candidateFailure{err: err, kind: candidateFailureCatalog}
		}
	}
	return &preparedCandidate{
		adapter:    adapter,
		bifrostCtx: bifrostCtx,
		bifrostReq: bifrostReq,
		cancel:     cancel,
		resolution: resolution,
		state:      state,
	}, nil
}

func finalizePreparedFailure(
	ctx *schemas.BifrostContext,
	billingService *billing.Service,
	state *stogas.State,
	err error,
) {
	apiErr := stogas.PublicBillingErrorFor(err)
	status := apiErr.StatusCode
	state.ProcessingError = &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &status,
		Error:          &schemas.ErrorField{Message: apiErr.Message, Code: schemas.Ptr(apiErr.Code)},
	}
	stogas.FinalizeState(context.WithoutCancel(ctx), billingService, state)
}
