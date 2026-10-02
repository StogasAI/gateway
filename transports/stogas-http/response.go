package stogashttp

import (
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/tidwall/sjson"
)

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
		return publicResponsesStreamResponse{response: typed}
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
	response *schemas.BifrostResponsesStreamResponse
}

func (payload publicResponsesStreamResponse) MarshalJSON() ([]byte, error) {
	if payload.response == nil {
		return []byte("null"), nil
	}
	// Core's custom event marshaler controls omitted versus empty fields.
	// Embedding it would promote MarshalJSON and bypass our field projection.
	data, err := payload.response.MarshalJSON()
	if err != nil {
		return nil, err
	}
	data, err = sjson.DeleteBytes(data, "extra_fields")
	if err != nil {
		return nil, err
	}
	return sjson.DeleteBytes(data, "response.extra_fields")
}
