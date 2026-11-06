package stogas

import (
	"github.com/maximhq/bifrost/core/schemas"
)

// A bridged request reaches a deployment that takes only Chat Completions, whose provider replies
// with Chat Completions. Its client, which called Responses, gets the reply as Responses, which
// Bifrost converts. The converted reply must then pass the checks of a provider's Responses reply,
// which also give it the echo of the request. Those checks run on a state of their own: the
// request's state keeps the provider's reply, from which the gateway bills and logs.
//
// Bifrost names why a converted reply ended in its stop reason too, which a Responses reply carries
// only from Anthropic's interface. Its status and incomplete details say the same.

// bridgedChecks is the state on which the Responses checks check a bridged request's reply.
func bridgedChecks(state *State) *State {
	return &State{Pair: Pair{Resolution: state.Resolution, Adapter: state.Adapter}}
}

// BridgedResponse returns the reply that the client of a unary request gets: for a bridged
// request, the provider's Chat Completions reply as Responses, and otherwise the reply itself.
func BridgedResponse(state *State, response *schemas.BifrostResponse) (*schemas.BifrostResponse, error) {
	if state == nil || !state.Resolution.Bridged() || response == nil {
		return response, nil
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
	if err := validateProviderResponsesResponse(bridgedChecks(state), converted); err != nil {
		return nil, err
	}
	return &schemas.BifrostResponse{ResponsesResponse: converted}, nil
}

// BridgedStream converts the Chat Completions stream of a bridged request into the Responses
// events that its client gets. Bifrost gives the event that ends the response at the finish
// reason, and the stream holds it until the provider has given the usage, which it then carries.
type BridgedStream struct {
	state     *State
	checks    *State
	converter schemas.ChatToResponsesStreamState
	usage     *schemas.BifrostLLMUsage
	terminal  *schemas.BifrostResponsesStreamResponse
	ended     bool
}

// NewBridgedStream returns the converter of a bridged request's stream, or nil for any other
// request.
func NewBridgedStream(state *State) *BridgedStream {
	if state == nil || !state.Resolution.Bridged() {
		return nil
	}
	return &BridgedStream{state: state, checks: bridgedChecks(state)}
}

// Convert returns the events of a chunk that the request's state took. The chunk that completes
// the provider's stream with its usage ends the events with response.completed or
// response.incomplete.
func (s *BridgedStream) Convert(chunk *schemas.BifrostChatResponse) ([]*schemas.BifrostResponsesStreamResponse, error) {
	if s == nil || chunk == nil {
		return nil, nil
	}
	if s.ended {
		return nil, ErrProviderResponseMalformed
	}
	if chunk.Usage != nil {
		s.usage = chunk.Usage
	}
	events := chunk.ToBifrostResponsesStreamResponse(&s.converter)
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
	for _, event := range events {
		if err := validateProviderResponsesStream(s.checks, event); err != nil {
			return nil, err
		}
	}
	return events, nil
}
