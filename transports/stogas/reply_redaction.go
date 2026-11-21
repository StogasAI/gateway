package stogas

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

// ReplyRedaction changes the response of one request as the redactions of its policies say. It
// puts back the values that the request's restoring redactions replaced, and it replaces or
// refuses what the redactions that read responses match. Reasoning keeps its placeholders.
//
// A redaction that replaces or refuses in responses changes a response whole. The client of a
// stream therefore gets nothing until the provider's stream ends: a match can span two chunks,
// and text that the client has can not be taken back. A reply that only gets values back, or
// whose matches are only recorded, streams as it arrives and waits only where Holds says.
type ReplyRedaction struct {
	state    *State
	redactor *redaction.Redactor
	reserve  func(int) error
	// jsonOutput marks a reply whose text is a JSON document, as the request asked.
	jsonOutput bool
	// request is what the request's own redaction recorded.
	request *plugins.RedactionMetrics
	// views count what each view of the reply found.
	views [replyViews]replyCount
	// sealed are the outputs of a Responses stream that hold signed or encrypted reasoning, and
	// sealedChoices and sealedDetails the reasoning of a Chat Completions stream that does.
	sealed        map[int]bool
	sealedChoices map[int]bool
	sealedDetails map[chatReplyText]bool
	// passed holds each text of a Chat Completions stream that has passed to the client and that
	// a redaction records, until the stream ends. A Responses stream repeats its texts whole.
	passed      map[chatReplyText]*bytes.Buffer
	passedOrder []chatReplyText
	// tails are the ends of the streamed texts that may become placeholders.
	tails map[any]string
}

// A Responses stream repeats one text in its deltas, in the item that ends it and in the
// response that ends the stream. Each is one view of the reply and holds a text once, so the
// record takes the view that found the most. The events that repeat a part are not counted.
const (
	replyViewWhole = iota
	replyViewDeltas
	replyViewItems
	replyViews
	replyViewRepeat = -1
)

type replyCount struct{ redacted, restored, recorded uint32 }

// NewReplyRedaction returns the redaction of the reply of the pair that serves the request, or
// nil when no policy changes the reply. reserve admits the bytes that the reply has grown by.
func NewReplyRedaction(state *State, reserve func(int) error) *ReplyRedaction {
	if state == nil {
		return nil
	}
	redactor := state.Resolution.ReplyRedactor()
	if redactor == nil {
		return nil
	}
	reply := &ReplyRedaction{state: state, redactor: redactor, reserve: reserve, request: state.PluginMetrics.Redaction}
	if state.structuredOutput().json {
		reply.jsonOutput = true
		redactor.JSONOutput()
	}
	return reply
}

// Response returns an encoded response that is no stream, changed.
func (r *ReplyRedaction) Response(encoded []byte) ([]byte, error) {
	if r == nil {
		return encoded, nil
	}
	shape := redaction.ReplyChat
	if r.state.Resolution.Route == catalog.RouteResponses {
		shape = redaction.ReplyResponses
	}
	defer r.count(replyViewWhole)()
	return r.redactor.RedactReply(encoded, shape, r.reserve)
}

// Event returns an encoded event of a held Responses stream, changed. Stream has already
// changed the event's delta, and the events of signed or encrypted reasoning stay as they are.
func (r *ReplyRedaction) Event(event *schemas.BifrostResponsesStreamResponse, encoded []byte) ([]byte, error) {
	if r == nil || event == nil || event.Delta != nil || event.OutputIndex != nil && r.sealed[*event.OutputIndex] {
		return encoded, nil
	}
	view := replyViewRepeat
	switch event.Type {
	case schemas.ResponsesStreamResponseTypeOutputItemDone:
		view = replyViewItems
	case schemas.ResponsesStreamResponseTypeCompleted, schemas.ResponsesStreamResponseTypeIncomplete, schemas.ResponsesStreamResponseTypeFailed:
		view = replyViewWhole
	}
	shape := redaction.ReplyResponsesEvent
	switch {
	case strings.HasPrefix(string(event.Type), "response.reasoning"):
		shape = redaction.ReplyResponsesReasoningEvent
	case event.Type == schemas.ResponsesStreamResponseTypeOutputTextDone || event.Type == schemas.ResponsesStreamResponseTypeContentPartDone:
		shape = redaction.ReplyResponsesTextEvent
	}
	defer r.count(view)()
	return r.redactor.RedactReply(encoded, shape, r.reserve)
}

// replyText is one text of a streamed reply: the deltas that continue it, in order.
type replyText struct {
	deltas    []*string
	arguments bool
}

// chatReplyText names one text of a streamed Chat Completions reply.
type chatReplyText struct {
	choice, index int
	kind          uint8
}

const (
	chatTextContent = iota
	chatTextRefusal
	chatTextReasoning
	chatTextArguments
	chatTextDetail
	chatTextDetailSummary
	chatTextTranscript
)

// responsesReplyText names one text of a streamed Responses reply.
type responsesReplyText struct {
	event                           schemas.ResponsesStreamResponseType
	output, content, summary, shell int
}

// Holds takes the next chunks of a stream and reports whether the client waits for more
// before it gets the chunks held so far. A redaction that changes the response holds every
// chunk. Any other reply is held only while a text ends in what may become a placeholder.
func (r *ReplyRedaction) Holds(chunks []*schemas.BifrostStreamChunk) bool {
	if r == nil {
		return false
	}
	if r.redactor.ChangesResponse() {
		return true
	}
	if r.tails == nil {
		r.tails = map[any]string{}
	}
	ended := func(owns func(key any) bool) {
		for key := range r.tails {
			if owns(key) {
				delete(r.tails, key)
			}
		}
	}
	for _, chunk := range chunks {
		replyDeltas(chunk, func(key any, delta *string, _ bool) {
			if reasoningText(key) {
				return
			}
			if tail := redaction.UnfinishedPlaceholder(r.tails[key] + *delta); tail != "" {
				r.tails[key] = tail
			} else {
				delete(r.tails, key)
			}
		})
		// No text of an ended choice or item continues.
		if chat := chunk.BifrostChatResponse; chat != nil {
			for i := range chat.Choices {
				if choice := &chat.Choices[i]; choice.FinishReason != nil {
					ended(func(key any) bool { text, ok := key.(chatReplyText); return ok && text.choice == choice.Index })
				}
			}
		}
		if event := chunk.BifrostResponsesStreamResponse; event != nil && event.OutputIndex != nil && event.Type == schemas.ResponsesStreamResponseTypeOutputItemDone {
			ended(func(key any) bool {
				text, ok := key.(responsesReplyText)
				return ok && text.output == *event.OutputIndex
			})
		}
	}
	return len(r.tails) > 0
}

// reasoningText reports whether a streamed text is the model's reasoning, which keeps its
// placeholders: a provider signs reasoning, and the signature can arrive after the text.
func reasoningText(key any) bool {
	switch key := key.(type) {
	case chatReplyText:
		return key.kind == chatTextReasoning || key.kind == chatTextDetail || key.kind == chatTextDetailSummary
	case responsesReplyText:
		return strings.HasPrefix(string(key.event), "response.reasoning")
	}
	return false
}

// outputText reports whether a streamed text is the reply's own text, which is a JSON document
// when the request asked for JSON output.
func outputText(key any) bool {
	switch key := key.(type) {
	case chatReplyText:
		return key.kind == chatTextContent
	case responsesReplyText:
		return key.event == schemas.ResponsesStreamResponseTypeOutputTextDelta
	}
	return false
}

// replyDeltas visits the texts that a chunk of a stream continues, each with the name of its
// text. arguments marks the JSON document of a tool call's arguments.
func replyDeltas(chunk *schemas.BifrostStreamChunk, visit func(key any, delta *string, arguments bool)) {
	add := func(key any, delta *string, arguments bool) {
		if delta != nil && *delta != "" {
			visit(key, delta, arguments)
		}
	}
	if chat := chunk.BifrostChatResponse; chat != nil {
		for i := range chat.Choices {
			choice := &chat.Choices[i]
			if choice.ChatStreamResponseChoice == nil || choice.Delta == nil {
				continue
			}
			delta := choice.Delta
			add(chatReplyText{choice: choice.Index, kind: chatTextContent}, delta.Content, false)
			add(chatReplyText{choice: choice.Index, kind: chatTextRefusal}, delta.Refusal, false)
			add(chatReplyText{choice: choice.Index, kind: chatTextReasoning}, delta.Reasoning, false)
			if delta.Audio != nil {
				add(chatReplyText{choice: choice.Index, kind: chatTextTranscript}, &delta.Audio.Transcript, false)
			}
			for j := range delta.ToolCalls {
				call := &delta.ToolCalls[j]
				add(chatReplyText{choice: choice.Index, index: int(call.Index), kind: chatTextArguments}, &call.Function.Arguments, true)
			}
			for j := range delta.ReasoningDetails {
				detail := &delta.ReasoningDetails[j]
				add(chatReplyText{choice: choice.Index, index: detail.Index, kind: chatTextDetail}, detail.Text, false)
				add(chatReplyText{choice: choice.Index, index: detail.Index, kind: chatTextDetailSummary}, detail.Summary, false)
			}
		}
	}
	if event := chunk.BifrostResponsesStreamResponse; event != nil {
		index := func(value *int) int {
			if value == nil {
				return -1
			}
			return *value
		}
		arguments := event.Type == schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta || event.Type == schemas.ResponsesStreamResponseTypeMCPCallArgumentsDelta
		add(responsesReplyText{event: event.Type, output: index(event.OutputIndex), content: index(event.ContentIndex), summary: index(event.SummaryIndex), shell: index(event.CommandIndex)}, event.Delta, arguments)
	}
}

// Stream changes the texts of held chunks in place and notes the outputs of a Responses
// stream that hold signed or encrypted reasoning. The first delta of a changed text gets the
// whole text and the later ones get none, so the other fields of every chunk stay where the
// provider put them. A text that does not change keeps its deltas. ended says that the chunks
// end the stream, so the texts that passed to the client are whole and their matches recorded.
func (r *ReplyRedaction) Stream(chunks []*schemas.BifrostStreamChunk, ended bool) error {
	if r == nil {
		return nil
	}
	defer r.count(replyViewDeltas)()
	var order []any
	texts := map[any]*replyText{}
	// A signed or encrypted reasoning detail keeps its text, and so does the reasoning text of
	// the message that holds one, as in a request (redaction.RedactRequestFields).
	if r.sealed == nil {
		r.sealed, r.sealedChoices, r.sealedDetails = map[int]bool{}, map[int]bool{}, map[chatReplyText]bool{}
	}
	sealedChoices, sealedDetails := r.sealedChoices, r.sealedDetails
	// The held chunks of a reply that a redaction changes hold every text whole.
	pieces := !r.redactor.ChangesResponse()
	for _, chunk := range chunks {
		replyDeltas(chunk, func(key any, delta *string, arguments bool) {
			text := texts[key]
			if text == nil {
				text = &replyText{arguments: arguments}
				texts[key] = text
				order = append(order, key)
			}
			text.deltas = append(text.deltas, delta)
		})
		if chat := chunk.BifrostChatResponse; chat != nil {
			for i := range chat.Choices {
				choice := &chat.Choices[i]
				if choice.ChatStreamResponseChoice == nil || choice.Delta == nil {
					continue
				}
				for j := range choice.Delta.ReasoningDetails {
					detail := &choice.Delta.ReasoningDetails[j]
					if stringValue(detail.Signature) != "" || stringValue(detail.Data) != "" {
						sealedChoices[choice.Index] = true
						sealedDetails[chatReplyText{choice: choice.Index, index: detail.Index}] = true
					}
				}
			}
		}
		if event := chunk.BifrostResponsesStreamResponse; event != nil && event.OutputIndex != nil {
			if item := event.Item; item != nil && item.Type != nil && *item.Type == schemas.ResponsesMessageTypeReasoning {
				if reasoning := item.ResponsesReasoning; reasoning != nil && stringValue(reasoning.EncryptedContent) != "" {
					r.sealed[*event.OutputIndex] = true
				}
			}
			if stringValue(event.Signature) != "" {
				r.sealed[*event.OutputIndex] = true
			}
		}
	}
	for _, key := range order {
		switch key := key.(type) {
		case chatReplyText:
			if key.kind == chatTextReasoning && sealedChoices[key.choice] ||
				(key.kind == chatTextDetail || key.kind == chatTextDetailSummary) && sealedDetails[chatReplyText{choice: key.choice, index: key.index}] {
				continue
			}
		case responsesReplyText:
			if r.sealed[key.output] {
				continue
			}
		}
		text := texts[key]
		size := 0
		for _, delta := range text.deltas {
			size += len(*delta)
		}
		joined := make([]byte, 0, size)
		for _, delta := range text.deltas {
			joined = append(joined, *delta...)
		}
		changed, err := r.redactor.RedactReplyText(string(joined), text.arguments || r.jsonOutput && outputText(key), !reasoningText(key), pieces, r.reserve)
		if err != nil {
			return err
		}
		if chat, ok := key.(chatReplyText); ok && pieces && r.redactor.RecordsResponse() {
			if err := r.pass(chat, changed); err != nil {
				return err
			}
		}
		if changed == string(joined) {
			continue
		}
		*text.deltas[0] = changed
		for _, delta := range text.deltas[1:] {
			*delta = ""
		}
	}
	if !ended {
		return nil
	}
	for _, key := range r.passedOrder {
		// The signature of a reasoning text can arrive after the text.
		if key.kind == chatTextReasoning && sealedChoices[key.choice] ||
			(key.kind == chatTextDetail || key.kind == chatTextDetailSummary) && sealedDetails[chatReplyText{choice: key.choice, index: key.index}] {
			continue
		}
		if err := r.redactor.RecordReplyText(r.passed[key].Bytes()); err != nil {
			return err
		}
	}
	r.passed, r.passedOrder = nil, nil
	return nil
}

// pass keeps a piece of a text that has passed to the client, within the reply's memory.
func (r *ReplyRedaction) pass(key chatReplyText, piece string) error {
	if err := r.redactor.ReserveGrowth(len(piece), r.reserve); err != nil {
		return err
	}
	if r.passed == nil {
		r.passed = map[chatReplyText]*bytes.Buffer{}
	}
	text := r.passed[key]
	if text == nil {
		text = &bytes.Buffer{}
		r.passed[key], r.passedOrder = text, append(r.passedOrder, key)
	}
	text.WriteString(piece)
	return nil
}

// count adds what one call found to its view, and puts the reply's counts beside what the
// request's redaction recorded.
func (r *ReplyRedaction) count(view int) func() {
	before := r.redactor.Summary()
	return func() {
		after := r.redactor.Summary()
		if before == nil || after == nil {
			return
		}
		if view != replyViewRepeat {
			r.views[view].redacted += after.ItemsRedacted - before.ItemsRedacted
			r.views[view].restored += after.ItemsRestored - before.ItemsRestored
			r.views[view].recorded += after.ItemsRecorded - before.ItemsRecorded
		}
		metrics := plugins.RedactionMetrics{}
		if r.request != nil {
			metrics = *r.request
		}
		for _, found := range r.views {
			metrics.ResponseItemsRedacted = max(metrics.ResponseItemsRedacted, found.redacted)
			metrics.ItemsRestored = max(metrics.ItemsRestored, found.restored)
			metrics.ResponseItemsRecorded = max(metrics.ResponseItemsRecorded, found.recorded)
		}
		r.state.PluginMetrics.Redaction = &metrics
		if event := r.state.FinalEvent; event != nil {
			event.Plugins.Redaction = &metrics
		}
	}
}

// ReplyRedactionError is the failure of a request whose reply its redaction could not change
// or refused. The provider served the request, so its usage is billed.
func ReplyRedactionError(err error) *schemas.BifrostError {
	status, errorType, code, message := http.StatusInternalServerError, "internal_error", "response_encoding_failed", "Failed to encode response"
	var refused *redaction.RefusedError
	switch {
	case errors.As(err, &refused):
		status, errorType, code, message = http.StatusBadRequest, "invalid_request_error", "redaction_refused", "Policy refuses a response that matches "+refused.Placeholder()
	case errors.Is(err, ErrProviderResponseTooLarge):
		return UpstreamProtocolError(err)
	case errors.Is(err, redaction.ErrWorkLimit), errors.Is(err, redaction.ErrMatchLimit), errors.Is(err, redaction.ErrNestingLimit):
		status, errorType, code, message = http.StatusBadGateway, "upstream_protocol_error", "upstream_response_too_large", "The response has too much text for the policy's redactions to scan"
	}
	allowFallbacks := false
	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &status,
		Type:           &errorType,
		AllowFallbacks: &allowFallbacks,
		Error:          &schemas.ErrorField{Type: &errorType, Code: &code, Message: message},
	}
}
