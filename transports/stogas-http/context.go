package stogashttp

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/providerio"
)

type stogasContextKey string

const (
	stogasMetadataKey stogasContextKey = "stogas.receipt"

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

func newRequestContext(ctx *requestContext, resolution *catalog.ResolvedRequest, credential apiCredential, adapter stogas.Adapter, nodeID string) (*schemas.BifrostContext, *stogas.State, context.CancelFunc, error) {
	lifetime := billing.GatewayRequestLifetime
	bifrostCtx, cancel := schemas.NewBifrostContextWithTimeout(
		providerio.WithBudget(context.Background(), ctx.memory),
		lifetime,
	)
	if deadline, ok := bifrostCtx.Deadline(); ok {
		ctx.deliveryDeadline = deadline.Add(downstreamWriteIdleTimeout)
	}
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
	state.RequestLifetime = lifetime
	state.SingleUseRequestID = ctx.encrypted
	stogas.SetState(bifrostCtx, state)

	receipt, err := receiptHeader(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	if receipt {
		bifrostCtx.SetValue(stogasMetadataKey, true)
	}

	return bifrostCtx, state, cancel, nil
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

func receiptHeader(ctx *requestContext) (bool, error) {
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

func wantsReceipt(ctx *schemas.BifrostContext) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(stogasMetadataKey).(bool)
	return value
}
