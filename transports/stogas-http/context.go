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
	stogasReturnExtraFieldsKey stogasContextKey = "stogas.return_extra_fields"

	stogasHeaderReturnExtraFields = "X-Stogas-Return-Extra-Fields"

	chatRequestLifetime = 10 * time.Minute
)

func newRequestContext(ctx *fasthttp.RequestCtx, resolution *catalog.ResolvedRequest, credential apiCredential, adapter stogas.Adapter) (*schemas.BifrostContext, *stogas.State, context.CancelFunc, error) {
	lifetime := requestLifetime(resolution)
	bifrostCtx, cancel := schemas.NewBifrostContextWithTimeout(
		context.Background(),
		lifetime,
	)
	requestID, err := uuid.NewV7()
	if err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("generate request ID: %w", err)
	}
	bifrostCtx.SetValue(schemas.BifrostContextKeyRequestID, requestID.String())
	bifrostCtx.SetValue(schemas.BifrostContextKeyIntegrationType, "openai")
	bifrostCtx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
	bifrostCtx.SetValue(schemas.BifrostContextKeyRequestHeaders, requestHeaders(ctx))
	state := stogas.NewState(resolution, credential.Raw, credential.Claims, adapter)
	state.RequestLifetime = lifetime
	state.ClientRequestHeaders = requestHeaderValues(ctx)
	stogas.SetState(bifrostCtx, state)

	extraFields, err := extraFieldsHeader(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	if len(extraFields) > 0 {
		bifrostCtx.SetValue(stogasReturnExtraFieldsKey, extraFields)
		if extraFields["raw_request"] {
			bifrostCtx.SetValue(schemas.BifrostContextKeySendBackRawRequest, true)
		}
		if extraFields["raw_response"] {
			bifrostCtx.SetValue(schemas.BifrostContextKeySendBackRawResponse, true)
		}
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

func requestHeaders(ctx *fasthttp.RequestCtx) map[string]string {
	headers := make(map[string]string)
	ctx.Request.Header.VisitAll(func(key []byte, value []byte) {
		name := strings.ToLower(string(key))
		if existing := headers[name]; existing != "" {
			headers[name] = existing + ", " + string(value)
			return
		}
		headers[name] = string(value)
	})
	return headers
}

func requestHeaderValues(ctx *fasthttp.RequestCtx) map[string][]string {
	headers := make(map[string][]string)
	ctx.Request.Header.VisitAll(func(key []byte, value []byte) {
		name := string(key)
		headers[name] = append(headers[name], string(value))
	})
	return headers
}

func extraFieldsHeader(ctx *fasthttp.RequestCtx) (map[string]bool, error) {
	fields := make(map[string]bool)
	raw := strings.TrimSpace(string(ctx.Request.Header.Peek(stogasHeaderReturnExtraFields)))
	if raw == "" {
		return fields, nil
	}
	for _, field := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(field))
		if name == "" {
			continue
		}
		if !allowsStogasResponseField(name) {
			return nil, fmt.Errorf("unsupported Stogas extra field: %s", name)
		}
		fields[name] = true
	}
	return fields, nil
}

func allowsStogasResponseField(name string) bool {
	return catalog.AllowsResponseMetadataField(name)
}
