package stogashttp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/providerio"
)

type stogasContextKey string

const (
	stogasMetadataKey stogasContextKey = "stogas.metadata"

	stogasHeaderMetadata = "Stogas-Metadata"
)

func inferenceRequestID(ctx *requestContext) (string, error) {
	if ctx.requestID != "" {
		return ctx.requestID, nil
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	value := id.String()
	ctx.requestID = value
	ctx.writer.Header().Set("X-Request-ID", value)
	return value, nil
}

func newRequestContext(ctx *requestContext, startedAt time.Time, resolution *catalog.ResolvedRequest, credential apiCredential, nodeID string) (*schemas.BifrostContext, *stogas.State, context.CancelFunc, error) {
	// Every pair has the first pair's total: credential policies, and rules
	// whose condition reads the candidate, cannot set it.
	total := resolution.RequestTimeouts().Total()
	responseDeadline := startedAt.Add(total)
	if !time.Now().Before(responseDeadline) {
		return nil, nil, nil, context.DeadlineExceeded
	}
	bifrostCtx := schemas.NewBifrostContext(
		providerio.WithBudget(context.Background(), ctx.memory),
		startedAt.Add(billing.GatewayRequestLifetime),
	)
	cancel := bifrostCtx.Cancel
	ctx.deliveryDeadline = responseDeadline.Add(downstreamWriteIdleTimeout)
	requestID, err := inferenceRequestID(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("generate request ID: %w", err)
	}
	bifrostCtx.SetValue(schemas.BifrostContextKeyRequestID, requestID)
	bifrostCtx.SetValue(schemas.BifrostContextKeyIntegrationType, "openai")
	bifrostCtx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
	// Core's idle timer ends provider reads. The caller's idle limit ends only
	// delivery, so a silent provider stream may last the request lifetime.
	bifrostCtx.SetValue(schemas.BifrostContextKeyStreamIdleTimeout, billing.GatewayRequestLifetime)
	state := stogas.NewState(resolution, credential.Raw, credential.Claims, stogas.AdapterFor(resolution.Provider))
	state.SetDashboardCredential(credential.Dashboard)
	state.NodeID = strings.ToLower(strings.TrimSpace(nodeID))
	state.RequestID = requestID
	state.SessionID, err = stogas.RequestSessionID(resolution.RawBody(), ctx.request.Header)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	state.Transport = ctx.transport()
	state.StartedAt = startedAt
	state.RequestLifetime = billing.GatewayRequestLifetime
	stogas.SetState(bifrostCtx, state)

	metadata, err := metadataHeader(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	if metadata {
		bifrostCtx.SetValue(stogasMetadataKey, true)
	}

	wait := newResponseDeadline(startedAt, total)
	ctx.responseWait = wait
	client := ctx.request.Context()
	observed := make(chan struct{})
	stopObserver := context.AfterFunc(client, func() {
		state.MarkClientStopped()
		close(observed)
	})
	stopObservation := func() {
		if stopObserver() {
			// Stopping owns completion only if the callback cannot run. An
			// already observed disconnect still belongs in final accounting.
			if client.Err() != nil {
				state.MarkClientStopped()
			}
			close(observed)
		}
		// AfterFunc's stop alone does not wait for an in-progress callback.
		<-observed
	}
	ctx.stopClientObservation = stopObservation
	return bifrostCtx, state, func() {
		stopObservation()
		wait.stop()
		cancel()
	}, nil
}

func (ctx *requestContext) finishClientWait() {
	ctx.responseWait.stop()
	if ctx.stopClientObservation != nil {
		ctx.stopClientObservation()
	}
}

func (ctx *requestContext) inferenceWaitError() error {
	if ctx.responseWait.timedOut() {
		return context.DeadlineExceeded
	}
	return ctx.request.Context().Err()
}

func metadataHeader(ctx *requestContext) (bool, error) {
	values := ctx.request.Header.Values(stogasHeaderMetadata)
	if len(values) > 1 {
		return false, fmt.Errorf("%s must appear at most once", stogasHeaderMetadata)
	}
	raw := ""
	if len(values) == 1 {
		raw = strings.TrimSpace(string(values[0]))
	}
	if raw == "" {
		return false, nil
	}
	switch raw {
	case "v1":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be v1", stogasHeaderMetadata)
	}
}

func wantsMetadata(ctx *schemas.BifrostContext) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(stogasMetadataKey).(bool)
	return value
}
