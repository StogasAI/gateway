package stogashttp

import (
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/tidwall/sjson"
)

// publicResponsePayload removes Bifrost-only response fields. Stogas request
// metadata is returned only in the bounded signed proof.
//
// model is the catalog model that served, which the reply names in place of the
// provider's own name for it: a dated snapshot, a cloud's model ID, or the name
// of a customer's Azure deployment. Clients then read the ID that they can send,
// whichever provider served. Empty keeps the provider's name.
func publicResponsePayload(value any, model string) any {
	switch typed := value.(type) {
	case *schemas.BifrostChatResponse:
		if typed != nil && model != "" {
			named := *typed
			named.Model = model
			typed = &named
		}
		return publicChatResponse{BifrostChatResponse: typed}
	case *schemas.BifrostResponsesResponse:
		if typed != nil && model != "" {
			named := *typed
			named.Model = model
			typed = &named
		}
		return publicResponsesResponse{response: typed}
	case *schemas.BifrostResponsesStreamResponse:
		if typed != nil && typed.Response != nil && model != "" {
			event, response := *typed, *typed.Response
			response.Model = model
			event.Response = &response
			typed = &event
		}
		return publicResponsesStreamResponse{response: typed}
	default:
		return typed
	}
}

// servedModel is the catalog model of the pair that is serving the request.
func servedModel(state *stogas.State) string {
	if state == nil || state.Resolution == nil {
		return ""
	}
	return state.Resolution.Deployment.ModelID
}

type publicChatResponse struct {
	*schemas.BifrostChatResponse
	ExtraFields *struct{} `json:"extra_fields,omitempty"`
}

type publicResponsesResponse struct {
	response *schemas.BifrostResponsesResponse
}

func (payload publicResponsesResponse) MarshalJSON() ([]byte, error) {
	if payload.response == nil {
		return []byte("null"), nil
	}
	// Core's marshaler sends tool_usage at the top level and output as an array.
	// Embedding it would promote MarshalJSON and bypass our field projection.
	data, err := payload.response.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return sjson.DeleteBytes(data, "extra_fields")
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
