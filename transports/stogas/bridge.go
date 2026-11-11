package stogas

import (
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// A bridged request reaches its deployment on the other one of Chat Completions and Responses,
// whose provider replies on that interface. Its client gets the reply on the interface that it
// called, which Bifrost converts. The converted reply must then pass the checks of a provider's
// reply on the client's interface, which read the request as the client sent it. Those checks run
// on a state of their own: the request's state keeps the provider's reply, from which the gateway
// bills and logs.
//
// Bifrost names why a reply converted to Responses ended in its stop reason too, which a Responses
// reply carries only from Anthropic's interface. Its status and incomplete details say the same.
//
// The translation to Chat Completions flattens namespace tools into function tools, so a converted
// call to one gets its namespace and name back before the checks.

// convertedChecks is the state on which the checks of the client's interface check a bridged
// request's converted reply.
func convertedChecks(state *State) *State {
	return &State{Pair: Pair{Resolution: state.Resolution.ClientView(), Adapter: state.Adapter}}
}

// BridgedResponse returns the reply that the client of a unary request gets: for a bridged
// request, the provider's reply on the client's interface, and otherwise the reply itself.
func BridgedResponse(state *State, response *schemas.BifrostResponse) (*schemas.BifrostResponse, error) {
	if state == nil || !state.Resolution.Bridged() || response == nil {
		return response, nil
	}
	if state.Resolution.Route == catalog.RouteChat {
		if response.ResponsesResponse == nil {
			return nil, ErrProviderResponseMalformed
		}
		converted := response.ResponsesResponse.ToBifrostChatResponse()
		if err := validateProviderChatResponse(convertedChecks(state), converted, false); err != nil {
			return nil, err
		}
		return &schemas.BifrostResponse{ChatResponse: converted}, nil
	}
	chat := response.ChatResponse
	if chat == nil || len(chat.Choices) != 1 || chat.Choices[0].ChatNonStreamResponseChoice == nil ||
		chat.Choices[0].ChatNonStreamResponseChoice.Message == nil {
		return nil, ErrProviderResponseMalformed
	}
	converted := chat.ToBifrostResponsesResponse()
	// A finish reason that Responses has no status for leaves the status unset.
	if converted.Status == nil {
		return nil, ErrProviderResponseMalformed
	}
	converted.StopReason = nil
	providerutils.RestoreResponsesNamespaceToolCalls(state.Resolution.NamespaceToolAliases(), &schemas.BifrostResponse{ResponsesResponse: converted})
	if err := validateProviderResponsesResponse(convertedChecks(state), converted); err != nil {
		return nil, err
	}
	return &schemas.BifrostResponse{ResponsesResponse: converted}, nil
}

// BridgedStream converts the stream of a bridged request's provider into the stream of the
// interface that its client called.
type BridgedStream struct {
	state  *State
	checks *State
	// toResponses converts a Chat Completions stream for a Responses client. Bifrost gives the
	// event that ends the response at the finish reason, and the stream holds it until the provider
	// has given the usage, which it then carries.
	toResponses schemas.ChatToResponsesStreamState
	usage       *schemas.BifrostLLMUsage
	terminal    *schemas.BifrostResponsesStreamResponse
	// toChat converts a Responses stream for a Chat Completions client.
	toChat schemas.ResponsesToChatStreamState
	ended  bool
}

// NewBridgedStream returns the converter of a bridged request's stream, or nil for any other
// request.
func NewBridgedStream(state *State) *BridgedStream {
	if state == nil || !state.Resolution.Bridged() {
		return nil
	}
	return &BridgedStream{state: state, checks: convertedChecks(state)}
}

// Convert returns the chunks of the client's stream that a chunk of the provider's stream, which
// the request's state took, gives.
func (s *BridgedStream) Convert(chunk *schemas.BifrostStreamChunk) ([]*schemas.BifrostStreamChunk, error) {
	if s == nil || chunk == nil {
		return nil, nil
	}
	if s.ended {
		return nil, ErrProviderResponseMalformed
	}
	if s.state.Resolution.Route == catalog.RouteChat {
		return s.chatChunks(chunk.BifrostResponsesStreamResponse)
	}
	return s.responsesEvents(chunk.BifrostChatResponse)
}

// chatChunks returns the Chat Completions chunks of a Responses event. A chunk that carries nothing
// stays out, and the usage of the chunk that ends the reply follows it in a chunk of its own, as
// OpenAI sends them.
func (s *BridgedStream) chatChunks(event *schemas.BifrostResponsesStreamResponse) ([]*schemas.BifrostStreamChunk, error) {
	if event == nil {
		return nil, ErrProviderResponseMalformed
	}
	chunk := event.ToBifrostChatResponse(&s.toChat)
	chunks := []*schemas.BifrostChatResponse{chunk}
	switch choice := chunk.Choices[0]; {
	case choice.FinishReason != nil:
		s.ended = true
		if chunk.Usage != nil {
			usage := *chunk
			usage.Choices = []schemas.BifrostResponseChoice{}
			chunk.Usage = nil
			chunks = append(chunks, &usage)
		}
	case emptyProviderChatUsageChoice(choice):
		return nil, nil
	}
	converted := make([]*schemas.BifrostStreamChunk, len(chunks))
	for i, chunk := range chunks {
		if err := validateProviderChatResponse(s.checks, chunk, true); err != nil {
			return nil, err
		}
		converted[i] = &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}
	}
	return converted, nil
}

// responsesEvents returns the Responses events of a Chat Completions chunk. The chunk that
// completes the provider's stream with its usage ends the events with response.completed or
// response.incomplete.
func (s *BridgedStream) responsesEvents(chunk *schemas.BifrostChatResponse) ([]*schemas.BifrostStreamChunk, error) {
	if chunk == nil {
		return nil, ErrProviderResponseMalformed
	}
	if chunk.Usage != nil {
		s.usage = chunk.Usage
	}
	events := chunk.ToBifrostResponsesStreamResponse(&s.toResponses)
	for index, event := range events {
		switch event.Type {
		case schemas.ResponsesStreamResponseTypeError:
			return nil, ErrProviderResponseMalformed
		case schemas.ResponsesStreamResponseTypeCompleted, schemas.ResponsesStreamResponseTypeIncomplete:
			if index != len(events)-1 || event.Response == nil {
				return nil, ErrProviderResponseMalformed
			}
			s.terminal, events = event, events[:index]
		}
	}
	if s.terminal != nil && s.state.chatStreamFinished && s.state.chatStreamUsageEnded {
		s.ended = true
		s.terminal.Response.StopReason = nil
		if s.usage != nil {
			s.terminal.Response.Usage = s.usage.ToResponsesResponseUsage()
		}
		events = append(events, s.terminal)
	}
	converted := make([]*schemas.BifrostStreamChunk, len(events))
	for i, event := range events {
		providerutils.RestoreResponsesNamespaceToolCalls(s.state.Resolution.NamespaceToolAliases(), &schemas.BifrostResponse{ResponsesStreamResponse: event})
		if err := validateProviderResponsesStream(s.checks, event); err != nil {
			return nil, err
		}
		converted[i] = &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}
	}
	return converted, nil
}
