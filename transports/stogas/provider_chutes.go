package stogas

import (
	"encoding/json"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const chutesDefaultOutputTokens = 1024

var chutesAllowedChatFields = map[string]bool{
	"frequency_penalty":     true,
	"max_completion_tokens": true,
	"max_tokens":            true,
	"messages":              true,
	"metadata":              true,
	"model":                 true,
	"presence_penalty":      true,
	"provider":              true,
	"repetition_penalty":    true,
	"reasoning":             true,
	"reasoning_effort":      true,
	"response_format":       true,
	"rules":                 true,
	"seed":                  true,
	"stop":                  true,
	"stream":                true,
	"stream_options":        true,
	"store":                 true,
	"temperature":           true,
	"tool_choice":           true,
	"tools":                 true,
	"top_k":                 true,
	"top_p":                 true,
}

func (a ChutesAdapter) ValidateRequest(state *State) error {
	if err := a.DefaultAdapter.ValidateRequest(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteChat {
		return catalog.ErrUnsupportedRequest
	}
	return validateChutesChatPolicy(state)
}

func (a ChutesAdapter) SanitizeRequest(state *State) error {
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	control := chutesReasoningControl{}
	if requested, ok := state.Resolution.ReasoningEffort(); ok {
		mapped, ok := chutesReasoningWireControl(state.Resolution.Deployment.ID, requested)
		if !ok {
			return invalidRequest("reasoning effort is not supported for the selected Chutes deployment")
		}
		control = mapped
	} else if enabled, ok := state.Resolution.ReasoningEnabled(); ok {
		mapped, ok := chutesReasoningEnabledWireControl(state.Resolution.Deployment.ID, enabled)
		if !ok {
			return invalidRequest("binary reasoning control is not supported for the selected Chutes deployment")
		}
		control = mapped
	}
	state.Resolution.PrepareChutesChatWire(chutesDefaultOutputTokens, control.Effort, control.Thinking)
	return nil
}

type chutesReasoningControl struct {
	Effort   string
	Thinking *bool
}

func chutesReasoningWireControl(deploymentID string, requested string) (chutesReasoningControl, bool) {
	switch deploymentID {
	case "chutes-kimi-k3":
		if requested != "low" && requested != "high" && requested != "max" {
			return chutesReasoningControl{}, false
		}
		thinking := true
		return chutesReasoningControl{Effort: requested, Thinking: &thinking}, true
	case "chutes-deepseek-v4-flash-0731", "chutes-glm-5.2":
		if requested != "none" && requested != "high" && requested != "max" {
			return chutesReasoningControl{}, false
		}
		thinking := requested != "none"
		return chutesReasoningControl{Effort: requested, Thinking: &thinking}, true
	default:
		return chutesReasoningControl{}, false
	}
}

func chutesReasoningEnabledWireControl(deploymentID string, enabled bool) (chutesReasoningControl, bool) {
	switch deploymentID {
	case "chutes-deepseek-v3.2",
		"chutes-gemma-4-31b-turbo",
		"chutes-glm-5.1",
		"chutes-kimi-k2.6",
		"chutes-nemotron-3-nano-omni-30b",
		"chutes-qwen3-32b",
		"chutes-qwen3.5-397b-a17b",
		"chutes-qwen3.6-27b":
		return chutesReasoningControl{Thinking: &enabled}, true
	default:
		return chutesReasoningControl{}, false
	}
}

func prepareChutesChatBody(ctx *schemas.BifrostContext, request *schemas.BifrostChatRequest, streaming bool) ([]byte, *schemas.BifrostError) {
	if ctx == nil || request == nil {
		return nil, &schemas.BifrostError{
			IsBifrostError: true,
			Error:          &schemas.ErrorField{Message: catalog.ErrUnsupportedRequest.Error()},
		}
	}
	ctx.SetValue(schemas.BifrostContextKeyPassthroughExtraParams, true)
	return prepareOpenAIChatBody(ctx, request, streaming)
}

func validateChutesChatPolicy(state *State) error {
	raw := state.Resolution.RawBody()
	for name := range raw {
		if !chutesAllowedChatFields[name] {
			return invalidRequest(name + " is not supported for Chutes deployments")
		}
	}
	if err := validateChutesNumberRange(raw, "temperature", func(value float64) bool { return value >= 0 }); err != nil {
		return err
	}
	if err := validateChutesNumberRange(raw, "top_p", func(value float64) bool { return value > 0 && value <= 1 }); err != nil {
		return err
	}
	if err := validateChutesIntegerRange(raw, "top_k", func(value int) bool { return value == -1 || value >= 1 }); err != nil {
		return err
	}
	if err := validateChutesNumberRange(raw, "repetition_penalty", func(value float64) bool { return value > 0 && value <= 2 }); err != nil {
		return err
	}
	for _, name := range []string{"frequency_penalty", "presence_penalty"} {
		if err := validateChutesNumberRange(raw, name, func(value float64) bool { return value >= -2 && value <= 2 }); err != nil {
			return err
		}
	}
	for _, name := range []string{"max_completion_tokens", "max_tokens"} {
		if err := validateChutesIntegerRange(raw, name, func(value int) bool { return value >= 1 }); err != nil {
			return err
		}
	}
	if err := validateReasoningParameters(raw, map[string]bool{"effort": true, "enabled": true}); err != nil {
		return err
	}
	if err := validateChutesResponseFormat(raw["response_format"], state.Resolution.Deployment.Capabilities.StructuredOutputs); err != nil {
		return err
	}
	tools, err := validateChatTools(raw["tools"], chatToolCapabilities{})
	if err != nil {
		return err
	}
	if len(tools) > 0 && !state.Resolution.Deployment.Capabilities.FunctionCalling {
		return invalidRequest("tools are not supported for the selected Chutes model")
	}
	return validateChatToolChoice(raw["tool_choice"], tools, chatToolCapabilities{})
}

func validateChutesNumberRange(raw map[string]json.RawMessage, name string, valid func(float64) bool) error {
	valueRaw, ok := raw[name]
	if !ok || strings.TrimSpace(string(valueRaw)) == "null" {
		return nil
	}
	var value float64
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be a number")
	}
	if !valid(value) {
		return invalidRequest(name + " is outside the Chutes supported range")
	}
	return nil
}

func validateChutesIntegerRange(raw map[string]json.RawMessage, name string, valid func(int) bool) error {
	valueRaw, ok := raw[name]
	if !ok || strings.TrimSpace(string(valueRaw)) == "null" {
		return nil
	}
	var value int
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be an integer")
	}
	if !valid(value) {
		return invalidRequest(name + " is outside the Chutes supported range")
	}
	return nil
}

func validateChutesResponseFormat(raw json.RawMessage, supported bool) error {
	if !rawJSONValueSet(raw) {
		return nil
	}
	if !supported {
		return invalidRequest("response_format is not supported for the selected Chutes model")
	}
	format, ok := rawObject(raw)
	if !ok {
		return invalidRequest("response_format must be an object")
	}
	formatType := rawString(format["type"])
	switch formatType {
	case "json_object":
		if !onlyRawKeys(format, "type") {
			return invalidRequest("response_format json_object supports only type")
		}
	case "json_schema":
		if !onlyRawKeys(format, "type", "json_schema") {
			return invalidRequest("response_format json_schema supports only type and json_schema")
		}
		schema, ok := rawObject(format["json_schema"])
		if !ok || !onlyRawKeysOptional(schema, "description", "name", "schema", "strict") {
			return invalidRequest("response_format.json_schema is invalid")
		}
		if strings.TrimSpace(rawString(schema["name"])) == "" {
			return invalidRequest("response_format.json_schema.name is required")
		}
		if _, ok := rawObject(schema["schema"]); !ok {
			return invalidRequest("response_format.json_schema.schema must be an object")
		}
		if strict, exists := schema["strict"]; exists {
			if err := validateRawJSONBool(strict, "response_format.json_schema.strict"); err != nil {
				return err
			}
		}
	default:
		return invalidRequest("response_format.type must be json_object or json_schema for Chutes")
	}
	return nil
}
