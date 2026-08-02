package stogashttp

import "github.com/maximhq/bifrost/core/schemas"

// publicResponsePayload removes Bifrost-only response fields. Stogas request
// metadata is returned only in the bounded signed proof.
func publicResponsePayload(_ *schemas.BifrostContext, value any, _ schemas.BifrostResponseExtraFields) any {
	return publicPayload(value)
}

func publicPayload(value any) any {
	switch typed := value.(type) {
	case *schemas.BifrostChatResponse:
		return publicChatResponse{BifrostChatResponse: typed}
	case *schemas.BifrostResponsesResponse:
		return publicResponsesResponse{BifrostResponsesResponse: typed}
	case *schemas.BifrostResponsesStreamResponse:
		return publicResponsesStreamResponse{
			BifrostResponsesStreamResponse: typed,
			Response:                       publicPayload(typed.Response),
		}
	default:
		return typed
	}
}

type publicChatResponse struct {
	*schemas.BifrostChatResponse
	ExtraFields *struct{} `json:"extra_fields,omitempty"`
}

type publicResponsesResponse struct {
	*schemas.BifrostResponsesResponse
	ExtraFields *struct{} `json:"extra_fields,omitempty"`
}

type publicResponsesStreamResponse struct {
	*schemas.BifrostResponsesStreamResponse
	Response    any       `json:"response,omitempty"`
	ExtraFields *struct{} `json:"extra_fields,omitempty"`
}
