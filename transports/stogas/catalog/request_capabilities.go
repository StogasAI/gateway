package catalog

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/maximhq/bifrost/core/schemas"
)

// Read only feature selectors. Large prompt strings and tool schemas are skipped
// by the JSON decoder, rather than decoded into provider request types here.
func requestCapabilities(raw map[string]json.RawMessage, route Route, shared Capabilities) (Capabilities, error) {
	// Neither a prompt cache setting nor parallel_tool_calls needs a capability. A cache setting
	// only tunes how a provider caches the prompt, and a deployment that does not take one never
	// receives it (ResolvedRequest.KeepCarriedPreferences, ResolvedRequest.ToBifrost).
	// parallel_tool_calls either allows parallel calls, the default that
	// dropNoOpCompatibilityFields drops, or asks the provider for one call per turn.
	var required Capabilities
	if value, ok := raw["stream"]; ok && !shared.Streaming {
		if err := json.Unmarshal(value, &required.Streaming); err != nil {
			return required, ErrInvalidJSON
		}
	}
	var tools []struct{ Type string }
	if value, ok := raw["tools"]; ok && !shared.FunctionCalling {
		if err := json.Unmarshal(value, &tools); err != nil {
			return required, ErrInvalidJSON
		}
		for _, tool := range tools {
			// A namespace holds function and custom tools, and the model calls shell and
			// apply_patch as it calls a function.
			switch CanonicalResponsesToolType(tool.Type) {
			case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom, schemas.ResponsesToolTypeNamespace,
				schemas.ResponsesToolTypeShell, schemas.ResponsesToolTypeApplyPatch:
				required.FunctionCalling = true
			}
		}
	}
	if value, ok := raw["functions"]; ok && route == RouteChat && !shared.FunctionCalling {
		var functions []struct{}
		if err := json.Unmarshal(value, &functions); err != nil {
			return required, ErrInvalidJSON
		}
		required.FunctionCalling = required.FunctionCalling || len(functions) != 0
	}
	// auto works wherever function calling does. Many providers parse no call under none but leave
	// the model free to write one, and many models do after an earlier call, so none with tools
	// needs a deployment that holds its model to it.
	listed := func(name string) bool {
		value := bytes.TrimSpace(raw[name])
		return len(value) > 0 && !rawJSONNullOrEmptyArray(value)
	}
	for _, name := range []string{"tool_choice", "function_call"} {
		value := bytes.TrimSpace(raw[name])
		if len(value) == 0 || bytes.Equal(value, []byte("null")) {
			continue
		}
		switch choice := rawStringValue(value); {
		case value[0] == '"' && choice == "auto":
		case value[0] == '"' && choice == "none":
			required.ToolChoiceNone = !shared.ToolChoiceNone && (listed("tools") || listed("functions"))
		default:
			required.ToolChoice = !shared.ToolChoice
		}
	}
	var format struct{ Type string }
	if value, ok := raw["response_format"]; ok && route == RouteChat && !shared.StructuredOutputs {
		if err := json.Unmarshal(value, &format); err != nil {
			return required, ErrInvalidJSON
		}
	}
	if value, ok := raw["text"]; ok && route == RouteResponses && !shared.StructuredOutputs {
		var text struct{ Format struct{ Type string } }
		if err := json.Unmarshal(value, &text); err != nil {
			return required, ErrInvalidJSON
		}
		format = text.Format
	}
	required.StructuredOutputs = format.Type == "json_schema"
	if shared.SystemMessages {
		return required, nil
	}
	var err error
	required.SystemMessages, err = requestSendsSystemMessages(route, raw)
	return required, err
}

// Features supported by every candidate cannot narrow the selection. Avoid
// traversing prompt containers merely to rediscover that they are acceptable.
func sharedRequestCapabilities(selections []routingSelection) Capabilities {
	shared := Capabilities{Streaming: true, FunctionCalling: true, ToolChoice: true, ToolChoiceNone: true, StructuredOutputs: true, SystemMessages: true}
	for _, selection := range selections {
		c := selection.deployment.Capabilities
		shared.Streaming = shared.Streaming && c.Streaming
		shared.FunctionCalling = shared.FunctionCalling && c.FunctionCalling
		shared.ToolChoice = shared.ToolChoice && c.ToolChoice
		shared.ToolChoiceNone = shared.ToolChoiceNone && c.ToolChoiceNone
		shared.StructuredOutputs = shared.StructuredOutputs && c.StructuredOutputs
		shared.SystemMessages = shared.SystemMessages && c.SystemMessages
	}
	return shared
}

func validateRequestCapabilities(required, supported Capabilities) error {
	for _, feature := range []struct {
		name                string
		required, supported bool
	}{
		{"streaming", required.Streaming, supported.Streaming},
		{"function calling", required.FunctionCalling, supported.FunctionCalling},
		{"tool choice", required.ToolChoice, supported.ToolChoice},
		{"tool choice none", required.ToolChoiceNone, supported.ToolChoiceNone},
		{"structured outputs", required.StructuredOutputs, supported.StructuredOutputs},
		{"system messages", required.SystemMessages, supported.SystemMessages},
	} {
		if feature.required && !feature.supported {
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: feature.name + " is not supported for the selected deployment"}
		}
	}
	return nil
}
