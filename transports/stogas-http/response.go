package stogashttp

import (
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
)

func publicResponsePayload(ctx *schemas.BifrostContext, value any, extra schemas.BifrostResponseExtraFields) any {
	metadata := stogasMetadata(ctx, extra)
	return publicPayload(value, metadata)
}

func publicPayload(value any, metadata map[string]any) any {
	switch typed := value.(type) {
	case *schemas.BifrostChatResponse:
		return publicChatResponse{BifrostChatResponse: typed, Stogas: metadata}
	case *schemas.BifrostResponsesResponse:
		return publicResponsesResponse{BifrostResponsesResponse: typed, Stogas: metadata}
	case *schemas.BifrostResponsesStreamResponse:
		return publicResponsesStreamResponse{
			BifrostResponsesStreamResponse: typed,
			Response:                       publicPayload(typed.Response, nil),
			Stogas:                         metadata,
		}
	case map[string]any:
		if len(metadata) == 0 {
			return typed
		}
		object := make(map[string]any, len(typed)+1)
		for key, value := range typed {
			object[key] = value
		}
		object["stogas"] = metadata
		return object
	case nil:
		return nil
	default:
		if len(metadata) == 0 {
			return typed
		}
		return map[string]any{"data": typed, "stogas": metadata}
	}
}

type publicChatResponse struct {
	*schemas.BifrostChatResponse
	ExtraFields *struct{}      `json:"extra_fields,omitempty"`
	Stogas      map[string]any `json:"stogas,omitempty"`
}

type publicResponsesResponse struct {
	*schemas.BifrostResponsesResponse
	ExtraFields *struct{}      `json:"extra_fields,omitempty"`
	Stogas      map[string]any `json:"stogas,omitempty"`
}

type publicResponsesStreamResponse struct {
	*schemas.BifrostResponsesStreamResponse
	Response    any            `json:"response,omitempty"`
	ExtraFields *struct{}      `json:"extra_fields,omitempty"`
	Stogas      map[string]any `json:"stogas,omitempty"`
}

func stogasMetadata(ctx *schemas.BifrostContext, extra schemas.BifrostResponseExtraFields) map[string]any {
	if ctx == nil {
		return nil
	}
	fields, _ := ctx.Value(stogasReturnExtraFieldsKey).(map[string]bool)
	if len(fields) == 0 {
		return nil
	}

	metadata := make(map[string]any)
	if fields["provider"] && extra.Provider != "" {
		metadata["provider"] = extra.Provider
	}
	if fields["model_requested"] && extra.OriginalModelRequested != "" {
		metadata["model_requested"] = extra.OriginalModelRequested
	}
	if fields["model_deployment"] && extra.ResolvedModelUsed != "" {
		metadata["model_deployment"] = extra.ResolvedModelUsed
	}
	if fields["latency"] {
		metadata["latency"] = extra.Latency
	}
	if fields["raw_request"] && extra.RawRequest != nil {
		metadata["raw_request"] = redactRawRequest(extra.RawRequest)
	}
	if fields["raw_response"] && extra.RawResponse != nil {
		metadata["raw_response"] = extra.RawResponse
	}
	if headers := filterProviderResponseHeaders(ctx, extra); fields["provider_response_headers"] && len(headers) > 0 {
		metadata["provider_response_headers"] = headers
	}

	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

func redactRawRequest(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if rawRequestRedactedKey(key) {
				out[key] = "<redacted>"
				continue
			}
			out[key] = redactRawRequest(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = redactRawRequest(item)
		}
		return out
	default:
		return value
	}
}

func rawRequestRedactedKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	switch normalized {
	case "authorization",
		"authorization_token",
		"api-key",
		"api_key",
		"access_token",
		"refresh_token",
		"password",
		"proxy-authorization",
		"secret",
		"token",
		"x-api-key",
		"x-goog-api-key":
		return true
	default:
		return rawRequestCanonicalSecretKey(normalized)
	}
}

func rawRequestCanonicalSecretKey(key string) bool {
	canonical := strings.NewReplacer("_", "", "-", "", " ", "").Replace(key)
	switch canonical {
	case "authorizationtoken",
		"apikey",
		"xapikey",
		"xgoogapikey",
		"accesstoken",
		"refreshtoken",
		"password",
		"proxyauthorization",
		"secret",
		"secretkey",
		"clientsecret",
		"token",
		"bearertoken":
		return true
	default:
		return false
	}
}

func filterProviderResponseHeaders(ctx *schemas.BifrostContext, extra schemas.BifrostResponseExtraFields) map[string]string {
	headers := extra.ProviderResponseHeaders
	if state, ok := stogas.StateFrom(ctx); ok && state.ProviderResponseHeaders != nil {
		headers = state.ProviderResponseHeaders
	}
	return safeProviderResponseHeaders(headers)
}

type streamMetadataAccumulator struct {
	extra             schemas.BifrostResponseExtraFields
	rawResponseChunks []any
	wantsRawResponses bool
}

func newStreamMetadataAccumulator(ctx *schemas.BifrostContext) *streamMetadataAccumulator {
	value, _ := ctx.Value(schemas.BifrostContextKeySendBackRawResponse).(bool)
	return &streamMetadataAccumulator{wantsRawResponses: value}
}

func (a *streamMetadataAccumulator) add(extra schemas.BifrostResponseExtraFields) {
	if extra.Provider != "" {
		a.extra.Provider = extra.Provider
	}
	if extra.OriginalModelRequested != "" {
		a.extra.OriginalModelRequested = extra.OriginalModelRequested
	}
	if extra.ResolvedModelUsed != "" {
		a.extra.ResolvedModelUsed = extra.ResolvedModelUsed
	}
	if extra.Latency != 0 {
		a.extra.Latency = extra.Latency
	}
	if extra.RawRequest != nil {
		a.extra.RawRequest = extra.RawRequest
	}
	if len(extra.ProviderResponseHeaders) > 0 {
		a.extra.ProviderResponseHeaders = extra.ProviderResponseHeaders
	}
	if a.wantsRawResponses && extra.RawResponse != nil {
		a.rawResponseChunks = append(a.rawResponseChunks, extra.RawResponse)
	}
}

func (a *streamMetadataAccumulator) metadata(ctx *schemas.BifrostContext) map[string]any {
	if len(a.rawResponseChunks) == 1 {
		a.extra.RawResponse = a.rawResponseChunks[0]
	} else if len(a.rawResponseChunks) > 1 {
		a.extra.RawResponse = a.rawResponseChunks
	}
	return stogasMetadata(ctx, a.extra)
}
