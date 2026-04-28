package stogashttp

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

type stogasContextKey string

const (
	stogasRawResponsePassthroughKey stogasContextKey = "stogas.raw_response_passthrough"
	stogasReturnExtraFieldsKey      stogasContextKey = "stogas.return_extra_fields"

	stogasHeaderReturnExtraFields = "X-Stogas-Return-Extra-Fields"
	stogasHeaderReturnRawRequest  = "X-Stogas-Return-Raw-Request"
	stogasHeaderReturnRawResponse = "X-Stogas-Return-Raw-Response"
)

func newRequestContext(ctx *fasthttp.RequestCtx, requestType schemas.RequestType) (*schemas.BifrostContext, context.CancelFunc, error) {
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(context.Background())
	bifrostCtx.SetValue(schemas.BifrostContextKeyRequestID, uuid.NewString())
	bifrostCtx.SetValue(schemas.BifrostContextKeyIntegrationType, "openai")
	bifrostCtx.SetValue(schemas.BifrostContextKeyHTTPRequestType, requestType)
	bifrostCtx.SetValue(schemas.BifrostContextKeyRequestHeaders, requestHeaders(ctx))

	returnRawRequest, err := boolHeader(ctx, stogasHeaderReturnRawRequest)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	if returnRawRequest {
		bifrostCtx.SetValue(schemas.BifrostContextKeySendBackRawRequest, true)
	}

	returnRawResponse, err := boolHeader(ctx, stogasHeaderReturnRawResponse)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	if returnRawResponse {
		bifrostCtx.SetValue(stogasRawResponsePassthroughKey, true)
		bifrostCtx.SetValue(schemas.BifrostContextKeySendBackRawResponse, true)
	}

	extraFields := extraFieldsHeader(ctx)
	if returnRawRequest {
		extraFields["raw_request"] = true
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

	if extraHeaders := catalogExtraHeaders(ctx); len(extraHeaders) > 0 {
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

func boolHeader(ctx *fasthttp.RequestCtx, name string) (bool, error) {
	raw := strings.TrimSpace(string(ctx.Request.Header.Peek(name)))
	if raw == "" {
		return false, nil
	}
	switch strings.ToLower(raw) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", name)
	}
}

func extraFieldsHeader(ctx *fasthttp.RequestCtx) map[string]bool {
	fields := make(map[string]bool)
	raw := strings.TrimSpace(string(ctx.Request.Header.Peek(stogasHeaderReturnExtraFields)))
	if raw == "" {
		return fields
	}
	for _, field := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(field))
		if name == "" {
			continue
		}
		fields[name] = true
	}
	return fields
}

func catalogExtraHeaders(ctx *fasthttp.RequestCtx) map[string][]string {
	provider, model := schemas.OpenAI, ""
	allowed := make(map[string][]string)
	ctx.Request.Header.VisitAll(func(key []byte, value []byte) {
		name := string(key)
		if !catalogAllowsUpstreamRequestHeader(provider, model, name) {
			return
		}
		allowed[name] = append(allowed[name], string(value))
	})
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func rawResponsePassthrough(ctx *schemas.BifrostContext) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(stogasRawResponsePassthroughKey).(bool)
	return value
}
