package utils

import (
	"context"

	"github.com/maximhq/bifrost/core/schemas"
)

type preparedRequestBody struct {
	requestType schemas.RequestType
	provider    schemas.ModelProvider
	model       string
	body        []byte
}

// SetPreparedRequestBody installs final provider bytes together with the
// request identity for which they were built. It does not copy body; callers
// must not modify the byte slice after this call.
func SetPreparedRequestBody(
	ctx *schemas.BifrostContext,
	requestType schemas.RequestType,
	provider schemas.ModelProvider,
	model string,
	body []byte,
) bool {
	if ctx == nil || len(body) == 0 || provider == "" || model == "" ||
		(!isPreparedChatRequestType(requestType) && !isPreparedResponsesRequestType(requestType)) {
		if ctx != nil {
			ctx.ClearValue(schemas.BifrostContextKeyPreparedRequestBody)
		}
		return false
	}
	ctx.SetValue(schemas.BifrostContextKeyPreparedRequestBody, preparedRequestBody{
		requestType: requestType,
		provider:    provider,
		model:       model,
		body:        body,
	})
	return true
}

// CheckAndGetPreparedRequestBody returns final provider bytes only when their
// request type, provider, and model still match the request being dispatched.
// Unlike raw input passthrough, provider builders must send these bytes unchanged.
func CheckAndGetPreparedRequestBody(ctx context.Context, request RequestBodyGetter) ([]byte, bool) {
	if ctx == nil || request == nil {
		return nil, false
	}
	prepared, ok := ctx.Value(schemas.BifrostContextKeyPreparedRequestBody).(preparedRequestBody)
	if !ok || len(prepared.body) == 0 {
		return nil, false
	}
	requestType, ok := ctx.Value(schemas.BifrostContextKeyHTTPRequestType).(schemas.RequestType)
	if !ok || requestType != prepared.requestType {
		return nil, false
	}
	switch typed := request.(type) {
	case *schemas.BifrostChatRequest:
		if !isPreparedChatRequestType(prepared.requestType) || typed.Provider != prepared.provider || typed.Model != prepared.model {
			return nil, false
		}
	case *schemas.BifrostResponsesRequest:
		if !isPreparedResponsesRequestType(prepared.requestType) || typed.Provider != prepared.provider || typed.Model != prepared.model {
			return nil, false
		}
	default:
		return nil, false
	}
	return prepared.body, true
}

func isPreparedChatRequestType(requestType schemas.RequestType) bool {
	return requestType == schemas.ChatCompletionRequest || requestType == schemas.ChatCompletionStreamRequest
}

func isPreparedResponsesRequestType(requestType schemas.RequestType) bool {
	return requestType == schemas.ResponsesRequest || requestType == schemas.ResponsesStreamRequest
}
