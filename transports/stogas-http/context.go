package stogashttp

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/valyala/fasthttp"
)

type stogasContextKey string

const (
	stogasReturnExtraFieldsKey stogasContextKey = "stogas.return_extra_fields"

	stogasHeaderReturnExtraFields = "X-Stogas-Return-Extra-Fields"
)

func newRequestContext(ctx *fasthttp.RequestCtx, resolution *catalog.ResolvedRequest) (*schemas.BifrostContext, context.CancelFunc, error) {
	bifrostCtx, cancel := schemas.NewBifrostContextWithTimeout(
		context.Background(),
		stogas.GatewayRequestLifetime,
	)
	requestID, err := uuid.NewV7()
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("generate request ID: %w", err)
	}
	bifrostCtx.SetValue(schemas.BifrostContextKeyRequestID, requestID.String())
	bifrostCtx.SetValue(schemas.BifrostContextKeyIntegrationType, "openai")
	bifrostCtx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
	bifrostCtx.SetValue(schemas.BifrostContextKeyRequestHeaders, requestHeaders(ctx))
	stogas.SetCatalogResolution(bifrostCtx, resolution)

	extraFields, err := extraFieldsHeader(ctx)
	if err != nil {
		cancel()
		return nil, nil, err
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

	if extraHeaders := allowedUpstreamRequestHeaders(ctx, resolution.Provider, resolution.Model, resolution.Route); len(extraHeaders) > 0 {
		bifrostCtx.SetValue(schemas.BifrostContextKeyExtraHeaders, extraHeaders)
	}

	return bifrostCtx, cancel, nil
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

func allowedUpstreamRequestHeaders(ctx *fasthttp.RequestCtx, provider schemas.ModelProvider, model string, route catalog.Route) map[string][]string {
	allowed := make(map[string][]string)
	ctx.Request.Header.VisitAll(func(key []byte, value []byte) {
		name := string(key)
		if !catalog.AllowsUpstreamRequestHeader(provider, model, route, name) {
			return
		}
		allowed[name] = append(allowed[name], string(value))
	})
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}
