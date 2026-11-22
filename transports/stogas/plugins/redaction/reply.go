package redaction

import (
	"time"
)

// ReplyShape says what a response's JSON is, so that the walk reads the reply's content and
// leaves the protocol fields around it.
type ReplyShape uint8

const (
	// ReplyChat is a Chat Completions response.
	ReplyChat ReplyShape = iota + 1
	// ReplyResponses is a Responses response.
	ReplyResponses
	// ReplyResponsesEvent is an event of a Responses stream that holds whole values, such as
	// an item or the text of a finished part.
	ReplyResponsesEvent
	// ReplyResponsesReasoningEvent is such an event of a reasoning text or summary.
	ReplyResponsesReasoningEvent
	// ReplyResponsesTextEvent is such an event of an output text or its part, whose text is not
	// inside an item's content.
	ReplyResponsesTextEvent
	// ReplyMessages is Claude's reply to a Messages request.
	ReplyMessages
	// ReplyMessagesEvent is an event of a Messages stream that holds whole values: the message
	// that starts it, a content block that starts, or the end of the message.
	ReplyMessagesEvent
)

// RedactReply returns a response with the values of the request's restoring redactions back
// and with the matches of the response's own redactions replaced. It reads the content as a
// request reads the same content in a later turn, so signed and encrypted reasoning stays as
// the provider wrote it. Media, citations and provider metadata stay too. Reasoning gets no
// value back: a provider signs it, a stream can deliver the text before its signature, and a
// later turn must send signed reasoning as the provider wrote it. A match of a
// refusing redaction returns a RefusedError. reserve, when given, admits the bytes that the
// response has grown by. The source is unchanged, and the result is the source itself when
// nothing changed.
func (r *Redactor) RedactReply(source []byte, shape ReplyShape, reserve func(int) error) ([]byte, error) {
	if r == nil {
		return source, nil
	}
	context := jsonContextReplyEvent
	switch shape {
	case ReplyChat:
		context = jsonContextReplyChat
	case ReplyResponses:
		context = jsonContextReplyResponses
	case ReplyResponsesEvent, ReplyResponsesReasoningEvent, ReplyResponsesTextEvent:
	case ReplyMessages:
		context = jsonContextReplyMessages
	case ReplyMessagesEvent:
		context = jsonContextReplyMessagesEvent
	default:
		return nil, errInvalidJSON
	}
	defer r.time(reserve)()
	baseRestored := r.restored
	r.keepPlaceholders = shape == ReplyResponsesReasoningEvent
	r.argumentsJSON = r.jsonOutput && shape == ReplyResponsesTextEvent
	r.messages = shape == ReplyMessages || shape == ReplyMessagesEvent
	redacted, _, err := r.redactJSONContext(source, context)
	r.keepPlaceholders, r.argumentsJSON, r.messages = false, false, false
	if err != nil {
		r.restored = baseRestored
		return nil, err
	}
	return redacted, nil
}

// RedactReplyText changes one text of a response as RedactReply changes the text of a field. A
// stream gives it the joined deltas of one text. arguments marks a JSON document, a tool call's
// arguments or the text of a reply in JSON, where a restored value is written as the inside of
// a JSON string. restore is false for reasoning. piece marks a text that goes on, whose matches
// RecordReplyText records once the text has ended.
func (r *Redactor) RedactReplyText(text string, arguments, restore, piece bool, reserve func(int) error) (string, error) {
	if r == nil || text == "" {
		return text, nil
	}
	defer r.time(reserve)()
	r.piece = piece
	defer func() { r.piece = false }()
	source, restored := []byte(text), uint32(0)
	if restore {
		source, restored = r.values.restore(source, arguments)
	}
	if err := r.reserveGrowth(len(source) - len(text)); err != nil {
		return "", err
	}
	redacted, changed, err := r.redactBytes(source)
	if err != nil {
		return "", err
	}
	r.restored += restored
	if !changed && restored == 0 {
		return text, nil
	}
	return string(redacted), nil
}

// RecordReplyText counts the matches of the recording redactions in one whole text of a stream
// whose pieces RedactReplyText has passed.
func (r *Redactor) RecordReplyText(text []byte) error {
	if r == nil || len(text) == 0 {
		return nil
	}
	defer r.time(nil)()
	recorded, err := r.scan(r.policy.at(PartResponse, ActionRecord), text)
	if err != nil {
		return err
	}
	r.recorded = saturatingAdd(r.recorded, uint32(min(len(recorded), int(^uint32(0)))))
	return nil
}

// ReserveGrowth admits bytes of the reply's text that the gateway keeps beside the reply.
func (r *Redactor) ReserveGrowth(bytes int, reserve func(int) error) error {
	if r == nil {
		return nil
	}
	defer r.time(reserve)()
	return r.reserveGrowth(bytes)
}

// time counts the duration of one call and gives its text the growth bound.
func (r *Redactor) time(reserve func(int) error) func() {
	startedAt := time.Now()
	r.reserveExpansion = reserve
	return func() {
		r.duration += time.Since(startedAt)
		r.reserveExpansion = nil
	}
}
