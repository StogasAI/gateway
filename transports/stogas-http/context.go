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
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
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

func newRequestContext(ctx *requestContext, startedAt time.Time, resolution *catalog.ResolvedRequest, credential apiCredential, adapter stogas.Adapter, nodeID string) (*schemas.BifrostContext, *stogas.State, context.CancelFunc, error) {
	timeouts := resolution.RequestTimeouts()
	responseDeadline := startedAt.Add(timeouts.Total())
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
	state := stogas.NewState(resolution, credential.Raw, credential.Claims, adapter)
	state.RetainMemory = ctx.memory.retain
	state.SetDashboardCredential(credential.Dashboard)
	state.EncryptionKeys = credential.EncryptionKeys
	state.NodeID = strings.ToLower(strings.TrimSpace(nodeID))
	state.RequestID = requestID
	state.StartedAt = startedAt
	state.RequestLifetime = billing.GatewayRequestLifetime
	state.SingleUseRequestID = ctx.encrypted
	stogas.SetState(bifrostCtx, state)

	metadata, err := metadataHeader(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	if metadata {
		bifrostCtx.SetValue(stogasMetadataKey, true)
	}

	wait := newResponseDeadline(startedAt, timeouts.Total(), timeouts.OutputIdle())
	ctx.responseWait = wait
	client := ctx.request.Context()
	if resolution.Provider == catalog.ProviderChutes {
		chutese2ee.SetInvocationBudget(bifrostCtx, resolution.ProviderAttemptLimit(), func() bool {
			cancelled, _ := state.ClientStatus()
			return !cancelled && wait.waiting() && client.Err() == nil
		})
	}
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

func configureProviderStreamIdleTimeout(
	ctx *schemas.BifrostContext,
	state *stogas.State,
) {
	if ctx == nil || state == nil || state.RequestLifetime <= 0 {
		return
	}
	ctx.SetValue(schemas.BifrostContextKeyStreamIdleTimeout, state.RequestLifetime)
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
