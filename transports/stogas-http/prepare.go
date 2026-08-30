package stogashttp

import (
	"context"
	"errors"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/valyala/fasthttp"
)

type candidateFailureKind uint8

const (
	candidateFailureCatalog candidateFailureKind = iota
	candidateFailureBilling
	candidateFailureRequest
)

type candidateFailure struct {
	err           error
	kind          candidateFailureKind
	refreshConfig bool
	tryNext       bool
}

type preparedCandidate struct {
	adapter    stogas.Adapter
	bifrostCtx *schemas.BifrostContext
	bifrostReq *schemas.BifrostRequest
	cancel     context.CancelFunc
	resolution *catalog.ResolvedRequest
	state      *stogas.State
}

func (s *Server) keyConfigForCredential(credential apiCredential) (*billing.KeyConfigSnapshot, error) {
	if s == nil || s.runtime == nil || s.runtime.Billing() == nil {
		return nil, billing.ErrGatewayUnavailable
	}
	if credential.Dashboard != nil {
		return s.runtime.Billing().ConfigForDashboard(context.Background(), credential.Dashboard)
	}
	return s.runtime.Billing().ConfigForAPIKey(context.Background(), credential.Raw, credential.Claims)
}

func (s *Server) invalidateKeyConfig(credential apiCredential) {
	if s == nil || s.runtime == nil || s.runtime.Billing() == nil {
		return
	}
	if credential.Dashboard != nil {
		s.runtime.Billing().InvalidateDashboardConfig(credential.Dashboard)
		return
	}
	s.runtime.Billing().InvalidateAPIKeyConfig(credential.Raw)
}

func (s *Server) prepareCandidate(
	ctx *fasthttp.RequestCtx,
	resolution *catalog.ResolvedRequest,
	credential apiCredential,
	nodeID string,
	requestStartedAt time.Time,
	configGeneration int,
) (*preparedCandidate, *candidateFailure) {
	adapter := stogas.AdapterFor(resolution.Provider)
	candidateCredential := credential
	candidateCredential.Upstream = credential.Upstream.only(string(resolution.Provider))
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
	failBeforeHold := func(err error, kind candidateFailureKind, tryNext bool) (*preparedCandidate, *candidateFailure) {
		state.PassthroughByokSecret = ""
		cancel()
		return nil, &candidateFailure{err: err, kind: kind, tryNext: tryNext}
	}
	state.StartedAt = requestStartedAt
	state.ConfigGeneration = configGeneration
	configureProviderStreamIdleTimeout(bifrostCtx, state)
	if err := adapter.ValidateRequest(state); err != nil {
		return failBeforeHold(err, candidateFailureCatalog, true)
	}
	if err := adapter.SanitizeRequest(state); err != nil {
		return failBeforeHold(err, candidateFailureCatalog, true)
	}
	if err := adapter.EstimateHold(state); err != nil {
		return failBeforeHold(err, candidateFailureCatalog, true)
	}
	bifrostReq, err := resolution.ToBifrost(bifrostCtx)
	if err != nil {
		return failBeforeHold(err, candidateFailureCatalog, true)
	}
	if err := stogas.PrepareProviderRequest(bifrostCtx, state, bifrostReq); err != nil {
		return failBeforeHold(err, candidateFailureCatalog, true)
	}

	if err := stogas.AuthorizeState(bifrostCtx, s.runtime.Billing(), state); err != nil {
		if state.Authorization != nil {
			finalizePreparedFailure(bifrostCtx, s.runtime.Billing(), state, "BYOK key is unavailable")
		}
		state.PassthroughByokSecret = ""
		cancel()
		return nil, &candidateFailure{
			err:           err,
			kind:          candidateFailureBilling,
			refreshConfig: errors.Is(err, billing.ErrAPIKeyConfigStale),
			tryNext: state.Authorization == nil &&
				(errors.Is(err, billing.ErrByokRequired) || errors.Is(err, billing.ErrByokTarget)),
		}
	}
	if err := stogas.ApplyUpstreamCredentials(bifrostCtx, state); err != nil {
		finalizePreparedFailure(bifrostCtx, s.runtime.Billing(), state, "BYOK key is unavailable")
		cancel()
		return nil, &candidateFailure{err: err, kind: candidateFailureBilling}
	}
	if resolution.Provider == schemas.Azure {
		bifrostReq, err = resolution.ToBifrost(bifrostCtx)
		if err == nil {
			err = stogas.PrepareProviderRequest(bifrostCtx, state, bifrostReq)
		}
		if err != nil {
			finalizePreparedFailure(bifrostCtx, s.runtime.Billing(), state, "Invalid provider request")
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
	message string,
) {
	status := fasthttp.StatusServiceUnavailable
	state.BifrostError = &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &status,
		Error:          &schemas.ErrorField{Message: message},
	}
	stogas.FinalizeState(context.WithoutCancel(ctx), billingService, state)
}
