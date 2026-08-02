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
	"github.com/valyala/fasthttp"
)

type stogasContextKey string

const (
	stogasExtraFieldsKey stogasContextKey = "stogas.extra_fields"

	stogasHeaderExtraFields = "X-Stogas-Extra-Fields"

	chatRequestLifetime = 10 * time.Minute
)

var chatStreamIdleTimeout = 2 * time.Minute

func newRequestContext(ctx *fasthttp.RequestCtx, resolution *catalog.ResolvedRequest, credential apiCredential, adapter stogas.Adapter, nodeID string) (*schemas.BifrostContext, *stogas.State, context.CancelFunc, error) {
	lifetime := requestLifetime(resolution)
	bifrostCtx, cancel := schemas.NewBifrostContextWithTimeout(
		context.Background(),
		lifetime,
	)
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
	state.NodeID = strings.ToLower(strings.TrimSpace(nodeID))
	state.RequestID = requestID
	state.RequestLifetime = lifetime
	state.SingleUseRequestID = encryptedSession(ctx) != nil
	stogas.SetState(bifrostCtx, state)

	extraFields, err := extraFieldsHeader(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	if extraFields {
		bifrostCtx.SetValue(stogasExtraFieldsKey, true)
	}

	return bifrostCtx, state, cancel, nil
}

func requestLifetime(resolution *catalog.ResolvedRequest) time.Duration {
	if resolution == nil {
		return billing.GatewayRequestLifetime
	}
	switch resolution.Route {
	case catalog.RouteChat:
		return chatRequestLifetime
	case catalog.RouteResponses:
		return billing.GatewayRequestLifetime
	default:
		return billing.GatewayRequestLifetime
	}
}

func streamIdleTimeout(state *stogas.State) time.Duration {
	if state == nil || state.Resolution == nil {
		return 0
	}
	switch state.Resolution.Route {
	case catalog.RouteChat:
		return chatStreamIdleTimeout
	default:
		return 0
	}
}

func extraFieldsHeader(ctx *fasthttp.RequestCtx) (bool, error) {
	raw := strings.ToLower(strings.TrimSpace(string(ctx.Request.Header.Peek(stogasHeaderExtraFields))))
	if raw == "" {
		return false, nil
	}
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", stogasHeaderExtraFields)
	}
}

func wantsExtraFields(ctx *schemas.BifrostContext) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(stogasExtraFieldsKey).(bool)
	return value
}
