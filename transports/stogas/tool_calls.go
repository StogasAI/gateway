package stogas

import (
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// The request log times each tool call of the response on the gateway's clock and links a call
// that the client runs to the later request that sends its result: both log a hash of the call's
// ID, so the time between them is the client's. Calls run by the provider take the time between
// their stream events. A response that arrives whole has no times.

// observedToolCall is a tool call of the response. callID is the ID that the client's result
// names, which is empty for a call that the provider runs.
type observedToolCall struct {
	itemType  string
	callID    string
	startedAt time.Time
	doneAt    time.Time
}

// responsesLoggedToolCall reports whether the request log records an output item as a tool call,
// and the ID that answers it. The client answers its own calls and the provider's approval
// requests; the provider runs the rest.
func responsesLoggedToolCall(item providerResponsesItem) (string, bool) {
	switch item.itemType {
	case schemas.ResponsesMessageTypeFunctionCall, schemas.ResponsesMessageTypeCustomToolCall:
		return item.callID, true
	case schemas.ResponsesMessageTypeMCPApprovalRequest:
		return item.id, true
	case schemas.ResponsesMessageTypeWebSearchCall, schemas.ResponsesMessageTypeWebFetchCall,
		schemas.ResponsesMessageTypeMCPCall, schemas.ResponsesMessageTypeMCPListTools:
		return "", true
	default:
		return "", false
	}
}

// observeResponsesToolCall records a tool call the first time the response shows it: when a
// stream adds it, or untimed in a whole response. Calls past the log's limit are left out.
func (s *State) observeResponsesToolCall(item providerResponsesItem, at time.Time) {
	callID, ok := responsesLoggedToolCall(item)
	if s == nil || !ok || len(s.toolCalls) >= billing.MaxLoggedToolCalls {
		return
	}
	if _, seen := s.toolCallPositions[item.id]; seen {
		return
	}
	if s.toolCallPositions == nil {
		s.toolCallPositions = make(map[string]int)
	}
	s.toolCallPositions[item.id] = len(s.toolCalls)
	s.toolCalls = append(s.toolCalls, observedToolCall{itemType: string(item.itemType), callID: callID, startedAt: at})
}

// finishResponsesToolCall ends a streamed call when the stream marks its item done.
func (s *State) finishResponsesToolCall(item providerResponsesItem, at time.Time) {
	if s == nil {
		return
	}
	if position, ok := s.toolCallPositions[item.id]; ok && !s.toolCalls[position].startedAt.IsZero() {
		s.toolCalls[position].doneAt = at
	}
}

// loggedToolCalls are the calls of a Chat or a Responses response, in output order.
func (s *State) loggedToolCalls() []billing.ToolCallInput {
	if s == nil {
		return nil
	}
	var calls []billing.ToolCallInput
	for index := range min(len(s.chatToolCalls), billing.MaxLoggedToolCalls) {
		call, ok := s.chatToolCalls[uint16(index)]
		if !ok {
			break
		}
		calls = append(calls, billing.ToolCallInput{
			Type: string(schemas.ResponsesMessageTypeFunctionCall), CallID: call.id, StartedAt: call.startedAt, DoneAt: call.doneAt,
		})
	}
	for _, call := range s.toolCalls {
		calls = append(calls, billing.ToolCallInput{Type: call.itemType, CallID: call.callID, StartedAt: call.startedAt, DoneAt: call.doneAt})
	}
	return calls
}

// inputTurn finds the results that answer the latest model turn of an input. Results follow the
// calls they answer, so a later model output starts a new turn, and messages after results end
// theirs: a call or result after such a message starts a new turn too. Results that a client
// interleaves with the calls of one turn stay together.
type inputTurn struct {
	answered []string
	closed   bool
}

// output is a model output other than a call, such as an assistant message or reasoning.
func (t *inputTurn) output() {
	t.answered, t.closed = t.answered[:0], false
}

// message is a message that the client added, such as a user message.
func (t *inputTurn) message() {
	t.closed = len(t.answered) > 0
}

// call is a call of the model or the provider.
func (t *inputTurn) call() {
	if t.closed {
		t.output()
	}
}

// result is the client's result for the call with this ID.
func (t *inputTurn) result(callID string) {
	t.call()
	t.answered = append(t.answered, callID)
}
