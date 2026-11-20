package stogashttp

import (
	"errors"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
)

var errReplyMemory = errors.New("gateway memory cannot hold the changed reply")

// replyGrowth bounds the bytes that a redaction adds to a reply when it puts values back: the
// response limit, and the request's memory.
func replyGrowth(memory *requestMemoryLease) func(int) error {
	charged := 0
	return func(total int) error {
		if total > maxInferenceStreamResponseBytes {
			return stogas.ErrProviderResponseTooLarge
		}
		if !memory.grow(total - charged) {
			return errReplyMemory
		}
		charged = total
		return nil
	}
}

func replyRedactionFailure(err error) *schemas.BifrostError {
	if errors.Is(err, errReplyMemory) {
		return streamMemoryCapacityError()
	}
	return stogas.ReplyRedactionError(err)
}

// unaryReplyPayload is the response of a request that is no stream, as the caller gets it: the
// provider's reply, changed when a redaction of the request's policies changes replies. A
// failure is the request's, and its state keeps it.
func unaryReplyPayload(state *stogas.State, memory *requestMemoryLease, reply *schemas.BifrostResponse) (any, *schemas.BifrostError) {
	payload := unaryResponsePayload(reply, servedModel(state))
	redaction := stogas.NewReplyRedaction(state, replyGrowth(memory))
	if redaction == nil {
		return payload, nil
	}
	encoded, err := marshalPayload(payload)
	if err != nil {
		failure := responseEncodingFailure()
		retainResponseFailure(state, failure)
		return nil, failure
	}
	changed, err := redaction.Response(encoded)
	if err != nil {
		clear(encoded)
		failure := replyRedactionFailure(err)
		retainResponseFailure(state, failure)
		return nil, failure
	}
	if len(changed) == 0 || &changed[0] != &encoded[0] {
		clear(encoded)
	}
	return changed, nil
}
