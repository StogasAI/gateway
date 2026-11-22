package stogashttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/tidwall/sjson"
)

// A Messages request gets Claude's own reply: the provider's JSON or events, with the served
// model in place of the provider's name for it, and errors in Anthropic's shape. The reply checks,
// settlement and records read core's Responses form of the same reply.

var errMissingClaudeReply = errors.New("the provider call returned no reply in Claude's format")

// isMessagesRequest reports whether the request calls Anthropic's Messages API.
func isMessagesRequest(request *http.Request) bool {
	route, ok := catalog.RouteForPath(request.URL.Path)
	return ok && route == catalog.RouteMessages
}

// acceptedInferenceQuery reports whether the gateway takes the request's query string: none, or
// the beta=true that Anthropic's SDKs add to a Messages request from their beta methods.
func acceptedInferenceQuery(request *http.Request) bool {
	return request.URL.RawQuery == "" || request.URL.RawQuery == "beta=true" && isMessagesRequest(request)
}

// usesMessages reports whether the state's request calls Anthropic's Messages API.
func usesMessages(state *stogas.State) bool {
	return state != nil && state.Resolution != nil && state.Resolution.Messages
}

// anthropicErrorType is the type that Anthropic's API gives an error of the status
// (https://platform.claude.com/docs/en/api/errors): invalid_request_error for any other 4xx
// status, and api_error for any other 5xx.
func anthropicErrorType(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusPaymentRequired:
		return "billing_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusConflict:
		return "conflict_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusGatewayTimeout:
		return "timeout_error"
	case 529:
		return "overloaded_error"
	}
	if status >= http.StatusInternalServerError {
		return "api_error"
	}
	return "invalid_request_error"
}

// anthropicError is an error in Anthropic's shape. The error keeps the gateway's own fields, such
// as its code and the provider that failed, and takes the type that Anthropic gives the status.
func anthropicError(status int, payload map[string]any, requestID string) map[string]any {
	detail := map[string]any{"type": anthropicErrorType(status)}
	if source, ok := payload["error"].(map[string]any); ok {
		for name, value := range source {
			if name != "type" && value != nil {
				detail[name] = value
			}
		}
	}
	converted := map[string]any{"type": "error", "error": detail}
	if requestID != "" {
		converted["request_id"] = requestID
	}
	return converted
}

// clientErrorPayload is an error as the state's client gets it.
func clientErrorPayload(state *stogas.State, status int, payload map[string]any) map[string]any {
	if !usesMessages(state) {
		return payload
	}
	return anthropicError(status, payload, state.RequestID)
}

// streamErrorEvent names the event of a stream's error: Anthropic's error event on a Messages
// stream, and none on the others.
func streamErrorEvent(state *stogas.State) string {
	if usesMessages(state) {
		return "error"
	}
	return ""
}

// rawProviderJSON reads the provider's own JSON that core keeps with a reply.
func rawProviderJSON(raw any) ([]byte, bool) {
	var data []byte
	switch typed := raw.(type) {
	case json.RawMessage:
		data = typed
	case []byte:
		data = typed
	case string:
		data = []byte(typed)
	}
	return data, len(data) > 0
}

// messagesReply is Claude's reply to a Messages request that is no stream.
func messagesReply(reply *schemas.BifrostResponsesResponse, model string) ([]byte, error) {
	if reply == nil {
		return nil, errMissingClaudeReply
	}
	raw, ok := rawProviderJSON(reply.ExtraFields.RawResponse)
	if !ok {
		return nil, errMissingClaudeReply
	}
	if model == "" {
		return bytes.Clone(raw), nil
	}
	return sjson.SetBytes(raw, "model", model)
}

// messagesStreamEvent is the Claude event that a chunk of a Messages stream carries. Core puts
// each of Claude's events on one chunk, so a chunk without one gives the client nothing.
func messagesStreamEvent(chunk *schemas.BifrostResponsesStreamResponse, model string) (streamEvent, bool) {
	raw, ok := chunk.ExtraFields.RawResponse.(string)
	if !ok || raw == "" {
		return streamEvent{}, false
	}
	node, err := sonic.GetFromString(raw, "type")
	if err != nil {
		return streamEvent{}, false
	}
	name, err := node.String()
	if err != nil || !messagesEventName(name) {
		return streamEvent{}, false
	}
	if name == "message_start" && model != "" {
		if raw, err = sjson.Set(raw, "message.model", model); err != nil {
			return streamEvent{}, false
		}
	}
	// An event goes on one data line.
	if strings.ContainsAny(raw, "\r\n") {
		var compact bytes.Buffer
		if json.Compact(&compact, []byte(raw)) != nil {
			return streamEvent{}, false
		}
		raw = compact.String()
	}
	return streamEvent{name: name, payload: raw, responses: chunk}, true
}

// messagesEventName reports whether name can name an event: lower-case letters and underscores.
func messagesEventName(name string) bool {
	if name == "" {
		return false
	}
	for index := range len(name) {
		if (name[index] < 'a' || name[index] > 'z') && name[index] != '_' {
			return false
		}
	}
	return true
}
