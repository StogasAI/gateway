package stogashttp

import (
	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
)

func publicResponsePayload(ctx *schemas.BifrostContext, raw any, value any, extra schemas.BifrostResponseExtraFields) any {
	if rawResponsePassthrough(ctx) && raw != nil {
		return raw
	}

	payload := sanitizeBifrostPayload(value)
	metadata := stogasMetadata(ctx, extra)
	if len(metadata) == 0 {
		return payload
	}

	if object, ok := payload.(map[string]any); ok {
		object["stogas"] = metadata
		return object
	}

	return map[string]any{
		"data":   payload,
		"stogas": metadata,
	}
}

func sanitizeBifrostPayload(value any) any {
	data, err := sonic.Marshal(value)
	if err != nil {
		return value
	}

	var decoded any
	if err := sonic.Unmarshal(data, &decoded); err != nil {
		return value
	}
	removeBifrostExtraFields(decoded)
	return decoded
}

func removeBifrostExtraFields(value any) {
	switch typed := value.(type) {
	case map[string]any:
		delete(typed, "extra_fields")
		for _, nested := range typed {
			removeBifrostExtraFields(nested)
		}
	case []any:
		for _, nested := range typed {
			removeBifrostExtraFields(nested)
		}
	}
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
	if fields["model_requested"] && extra.ModelRequested != "" {
		metadata["model_requested"] = extra.ModelRequested
	}
	if fields["model_deployment"] && extra.ModelDeployment != "" {
		metadata["model_deployment"] = extra.ModelDeployment
	}
	if fields["latency"] && extra.Latency != 0 {
		metadata["latency"] = extra.Latency
	}
	if fields["raw_request"] && extra.RawRequest != nil {
		metadata["raw_request"] = extra.RawRequest
	}
	if fields["raw_response"] && extra.RawResponse != nil {
		metadata["raw_response"] = extra.RawResponse
	}
	if headers := filterCatalogProviderResponseHeaders(extra.Provider, extra.ModelRequested, extra.ProviderResponseHeaders); fields["provider_response_headers"] && len(headers) > 0 {
		metadata["provider_response_headers"] = headers
	}

	if len(metadata) == 0 {
		return nil
	}
	return metadata
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
	if extra.ModelRequested != "" {
		a.extra.ModelRequested = extra.ModelRequested
	}
	if extra.ModelDeployment != "" {
		a.extra.ModelDeployment = extra.ModelDeployment
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
