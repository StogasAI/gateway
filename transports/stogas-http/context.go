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
	"github.com/valyala/fasthttp"
)

type stogasContextKey string

const (
	stogasReceiptKey stogasContextKey = "stogas.receipt"

	stogasHeaderReceipt = "Stogas-Receipt"
)

func newRequestContext(ctx *fasthttp.RequestCtx, resolution *catalog.ResolvedRequest, credential apiCredential, adapter stogas.Adapter, nodeID string) (*schemas.BifrostContext, *stogas.State, context.CancelFunc, error) {
	lifetime := billing.GatewayRequestLifetime
	bifrostCtx, cancel := schemas.NewBifrostContextWithTimeout(
		context.Background(),
		lifetime,
	)
	if deadline, ok := bifrostCtx.Deadline(); ok {
		setDownstreamWriteLimit(ctx.Conn(), deadline.Add(downstreamWriteIdleTimeout))
	}
	requestID := ""
	if session := encryptedSession(ctx); session != nil {
		requestID = session.RequestID
	} else {
		generated, err := uuid.NewV7()
		if err != nil {
			cancel()
			return nil, nil, nil, fmt.Errorf("generate request ID: %w", err)
		}
		requestID = generated.String()
	}
	bifrostCtx.SetValue(schemas.BifrostContextKeyRequestID, requestID)
	bifrostCtx.SetValue(schemas.BifrostContextKeyIntegrationType, "openai")
	bifrostCtx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
	state := stogas.NewState(resolution, credential.Raw, credential.Claims, adapter)
	state.SetDashboardCredential(credential.Dashboard)
	if upstreamSecret := credential.Upstream.get(string(resolution.Provider)); upstreamSecret != "" {
		plaintext, credentialErr := stogas.CanonicalPassthroughCredential(
			resolution.Provider,
			upstreamSecret,
		)
		if credentialErr != nil {
			cancel()
			return nil, nil, nil, credentialErr
		}
		state.PassthroughByokSecret = plaintext
	}
	state.NodeID = strings.ToLower(strings.TrimSpace(nodeID))
	state.RequestID = requestID
	state.RequestLifetime = lifetime
	state.SingleUseRequestID = encryptedSession(ctx) != nil
	stogas.SetState(bifrostCtx, state)

	receipt, err := receiptHeader(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	if receipt {
		bifrostCtx.SetValue(stogasReceiptKey, true)
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

func receiptHeader(ctx *fasthttp.RequestCtx) (bool, error) {
	values := ctx.Request.Header.PeekAll(stogasHeaderReceipt)
	if len(values) > 1 {
		return false, fmt.Errorf("%s must appear at most once", stogasHeaderReceipt)
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
		return false, fmt.Errorf("%s must be v1", stogasHeaderReceipt)
	}
}

func wantsReceipt(ctx *schemas.BifrostContext) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(stogasReceiptKey).(bool)
	return value
}
