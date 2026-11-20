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
	case ReplyResponsesEvent, ReplyResponsesReasoningEvent:
	default:
		return nil, errInvalidJSON
	}
	defer r.time(reserve)()
	baseRestored := r.restored
	r.keepPlaceholders = shape == ReplyResponsesReasoningEvent
	redacted, _, err := r.redactJSONContext(source, context)
	r.keepPlaceholders = false
	if err != nil {
		r.restored = baseRestored
		return nil, err
	}
	return redacted, nil
}

// RedactReplyText changes one text of a response as RedactReply changes the text of a field. A
// stream gives it the joined deltas of one text. arguments marks the JSON document of a tool
// call's arguments, where a restored value is written as the inside of a JSON string. restore
// is false for reasoning.
func (r *Redactor) RedactReplyText(text string, arguments, restore bool, reserve func(int) error) (string, error) {
	if r == nil || text == "" {
		return text, nil
	}
	defer r.time(reserve)()
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

// time counts the duration of one call and gives its text the growth bound.
func (r *Redactor) time(reserve func(int) error) func() {
	startedAt := time.Now()
	r.reserveExpansion = reserve
	return func() {
		r.duration += time.Since(startedAt)
		r.reserveExpansion = nil
	}
}
