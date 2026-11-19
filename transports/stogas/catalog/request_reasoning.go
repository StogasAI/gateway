package catalog

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bytedance/sonic"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

type normalizedReasoning struct {
	Effort    *string
	Enabled   *bool
	MaxTokens *int
}

// A reasoning control only tunes how much the model thinks, so every deployment serves every
// control with the nearest setting that it has, and a deployment without reasoning serves the
// request without one. OpenRouter maps efforts and budgets onto each other in the same way and
// ignores the control for a model that has none.
//
// normalizeReasoningEffort maps a portable effort onto the deployment's controls. A deployment that
// takes a budget but no levels gets each positive effort as a budget, so that every provider sends
// the same number and the request log shows it. A model that always reasons gets none as its
// lowest setting.
func normalizeReasoningEffort(
	requested string,
	deployment Deployment,
	outputTokenLimit int,
) (normalizedReasoning, error) {
	if requested != "none" && reasoningEffortIndex(requested) < 0 {
		return normalizedReasoning{}, APIError{
			StatusCode: http.StatusBadRequest,
			Type:       ErrorTypeInvalidRequest,
			Message:    "reasoning effort must be one of: none, minimal, low, medium, high, xhigh, max",
		}
	}
	optional := deployment.Reasoning == "optional"
	switch {
	case deployment.Reasoning == "unsupported":
		return normalizedReasoning{}, nil
	case requested == "none" && optional:
		if len(deployment.ReasoningEfforts) == 0 && deployment.ReasoningMaxTokens == nil {
			enabled := false
			return normalizedReasoning{Enabled: &enabled}, nil
		}
		return normalizedReasoning{Effort: &requested}, nil
	case len(deployment.ReasoningEfforts) > 0:
		effort := nearestReasoningEffort(requested, deployment.ReasoningEfforts)
		return normalizedReasoning{Effort: &effort}, nil
	case deployment.ReasoningMaxTokens != nil:
		capability := *deployment.ReasoningMaxTokens
		if outputTokenLimit <= capability.Minimum {
			return reasoningOutsideOutputLimit(deployment, outputTokenLimit)
		}
		budget := capability.Minimum
		if requested != "none" {
			budget = reasoningBudget(requested, capability, outputTokenLimit)
		}
		return normalizedReasoning{MaxTokens: &budget}, nil
	case optional:
		enabled := true
		return normalizedReasoning{Enabled: &enabled}, nil
	}
	// The model always reasons and has no setting for how much.
	return normalizedReasoning{}, nil
}

// reasoningBudget is the effort's share of the output token limit above the deployment minimum, in
// the ratios that core gives providers that take only a budget. It stays below the output token
// limit, as Anthropic requires, and inside the deployment's bounds.
func reasoningBudget(effort string, capability ReasoningMaxTokens, outputTokenLimit int) int {
	// The effort is one of the scale and the limit is above the minimum, so core returns no error.
	budget, _ := providerUtils.GetBudgetTokensFromReasoningEffort(effort, capability.Minimum, outputTokenLimit)
	return min(max(budget, capability.Minimum), capability.Maximum)
}

// normalizeReasoningMaxTokens maps a reasoning token budget onto the deployment's controls: inside
// the deployment's bounds where it takes a budget, and otherwise as the effort whose share of the
// output token limit is nearest, in the ratios that core gives efforts.
func normalizeReasoningMaxTokens(maxTokens int, deployment Deployment, outputTokenLimit int) (normalizedReasoning, error) {
	if deployment.Reasoning == "unsupported" {
		return normalizedReasoning{}, nil
	}
	capability := deployment.ReasoningMaxTokens
	if capability == nil {
		effort := providerUtils.GetReasoningEffortFromBudgetTokens(maxTokens, 0, outputTokenLimit)
		return normalizeReasoningEffort(effort, deployment, outputTokenLimit)
	}
	budget := min(max(maxTokens, capability.Minimum), capability.Maximum)
	if budget >= outputTokenLimit {
		return reasoningOutsideOutputLimit(deployment, outputTokenLimit)
	}
	return normalizedReasoning{MaxTokens: &budget}, nil
}

// reasoningOutsideOutputLimit answers a request whose output token limit leaves no room for the
// deployment's smallest reasoning budget. The limit is what the client must get, so reasoning is
// off where the model can answer without it.
func reasoningOutsideOutputLimit(deployment Deployment, outputTokenLimit int) (normalizedReasoning, error) {
	if deployment.Reasoning == "optional" {
		return normalizeReasoningEffort("none", deployment, outputTokenLimit)
	}
	return normalizedReasoning{}, APIError{
		StatusCode: http.StatusBadRequest,
		Type:       ErrorTypeInvalidRequest,
		Message:    "reasoning needs an output token limit greater than the deployment minimum reasoning budget",
	}
}

func normalizeReasoningEnabled(enabled bool, deployment Deployment, outputTokenLimit int) (normalizedReasoning, error) {
	if !enabled {
		return normalizeReasoningEffort("none", deployment, outputTokenLimit)
	}
	if len(deployment.ReasoningEfforts) == 0 && deployment.ReasoningMaxTokens == nil {
		if deployment.Reasoning == "optional" {
			return normalizedReasoning{Enabled: &enabled}, nil
		}
		return normalizedReasoning{}, nil
	}
	return normalizeReasoningEffort("medium", deployment, outputTokenLimit)
}

func normalizeChatReasoning(reasoning *schemas.ChatReasoning, deployment Deployment, outputTokenLimit int) error {
	if reasoning == nil {
		return nil
	}
	if reasoning.Effort != nil && reasoning.Enabled != nil {
		if (*reasoning.Effort == "none") == *reasoning.Enabled {
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning.enabled conflicts with reasoning.effort"}
		}
		reasoning.Enabled = nil
	}
	if err := validateReasoningMaxTokens(reasoning.Effort, reasoning.Enabled, reasoning.MaxTokens); err != nil {
		return err
	}
	var (
		selection normalizedReasoning
		err       error
	)
	switch {
	case reasoning.MaxTokens != nil:
		selection, err = normalizeReasoningMaxTokens(*reasoning.MaxTokens, deployment, outputTokenLimit)
	case reasoning.Effort != nil:
		selection, err = normalizeReasoningEffort(*reasoning.Effort, deployment, outputTokenLimit)
	case reasoning.Enabled != nil:
		selection, err = normalizeReasoningEnabled(*reasoning.Enabled, deployment, outputTokenLimit)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	reasoning.Effort = selection.Effort
	reasoning.Enabled = selection.Enabled
	reasoning.MaxTokens = selection.MaxTokens
	return nil
}

// withoutChatReasoningMode is a copy of a Chat Completions reasoning control without its mode, which
// only selects the deployment: Translate gives a bridged request its deployment's own mode, and
// Bifrost would call any other deployment's Responses for a mode. A control without any setting
// is none.
func withoutChatReasoningMode(reasoning *schemas.ChatReasoning) *schemas.ChatReasoning {
	if reasoning == nil {
		return nil
	}
	copied := *reasoning
	copied.Mode = nil
	if copied == (schemas.ChatReasoning{}) {
		return nil
	}
	return &copied
}

// deploymentReasoning is a copy of a Responses reasoning control with the deployment's reasoning
// mode: the client's reasoning.mode only selected the deployment. A control without any setting is
// none.
func deploymentReasoning(reasoning *schemas.ResponsesParametersReasoning, deployment Deployment) *schemas.ResponsesParametersReasoning {
	copied := schemas.ResponsesParametersReasoning{}
	if reasoning != nil {
		copied = *reasoning
	}
	copied.Mode = nil
	if mode := deployment.Upstream.ReasoningMode; mode != "" {
		copied.Mode = &mode
	}
	if copied == (schemas.ResponsesParametersReasoning{}) {
		return nil
	}
	return &copied
}

func normalizeResponsesReasoning(reasoning *schemas.ResponsesParametersReasoning, deployment Deployment, outputTokenLimit int) error {
	if reasoning == nil {
		return nil
	}
	if err := validateReasoningMaxTokens(reasoning.Effort, nil, reasoning.MaxTokens); err != nil {
		return err
	}
	var (
		normalized normalizedReasoning
		err        error
	)
	switch {
	case reasoning.MaxTokens != nil:
		normalized, err = normalizeReasoningMaxTokens(*reasoning.MaxTokens, deployment, outputTokenLimit)
	case reasoning.Effort != nil:
		normalized, err = normalizeReasoningEffort(*reasoning.Effort, deployment, outputTokenLimit)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if normalized.Enabled != nil {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "the selected Responses deployment exposes only a reasoning on/off control"}
	}
	reasoning.Effort = normalized.Effort
	reasoning.MaxTokens = normalized.MaxTokens
	return nil
}

func nearestReasoningEffort(requested string, supported []string) string {
	requestedIndex := reasoningEffortIndex(requested)
	best := supported[0]
	bestIndex := reasoningEffortIndex(best)
	bestDistance := absInt(requestedIndex - bestIndex)
	for _, candidate := range supported[1:] {
		candidateIndex := reasoningEffortIndex(candidate)
		distance := absInt(requestedIndex - candidateIndex)
		if distance < bestDistance || (distance == bestDistance && candidateIndex > bestIndex) {
			best = candidate
			bestIndex = candidateIndex
			bestDistance = distance
		}
	}
	return best
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func reasoningEffortIndex(value string) int {
	for index, effort := range policy.ReasoningEfforts {
		if value == effort {
			return index
		}
	}
	return -1
}

// validateReasoningMaxTokens refuses a reasoning token budget beside a setting that contradicts
// it, which no deployment could serve.
func validateReasoningMaxTokens(effort *string, enabled *bool, maxTokens *int) error {
	if maxTokens == nil {
		return nil
	}
	if effort != nil {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning effort conflicts with a manual reasoning token limit"}
	}
	if enabled != nil && !*enabled {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "disabled reasoning conflicts with a manual reasoning token limit"}
	}
	return nil
}

var (
	chatRawReasoningFields = map[string]bool{
		"display":    true,
		"enabled":    true,
		"effort":     true,
		"max_tokens": true,
		"mode":       true,
	}
	responsesRawReasoningFields = map[string]bool{
		"context":    true,
		"effort":     true,
		"max_tokens": true,
		"mode":       true,
		"summary":    true,
	}
)

// foldGenerateSummary moves reasoning.generate_summary, OpenAI's former name of reasoning.summary,
// into reasoning.summary, so that every check and provider reads one field.
func foldGenerateSummary(rawData map[string]json.RawMessage) error {
	reasoning, ok, err := rawReasoningObject(rawData["reasoning"])
	if err != nil || !ok {
		// validateRawReasoningParameters names a reasoning value that is not an object.
		return nil
	}
	former, found := reasoning["generate_summary"]
	if !found {
		return nil
	}
	delete(reasoning, "generate_summary")
	if !rawJSONNull(former) {
		if summary, set := reasoning["summary"]; set && !rawJSONNull(summary) {
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning.generate_summary conflicts with reasoning.summary"}
		}
		reasoning["summary"] = former
	}
	encoded, err := sonic.Marshal(reasoning)
	if err != nil {
		return err
	}
	rawData["reasoning"] = encoded
	return nil
}

// rawReasoningFields holds only the small reasoning controls of a request, so that they decode
// with the same codecs used for the final request without materializing messages or tools.
func rawReasoningFields(raw map[string]json.RawMessage) ([]byte, map[string]json.RawMessage, error) {
	fields := make(map[string]json.RawMessage)
	for _, name := range []string{"reasoning", "reasoning_effort", "reasoning_max_tokens", "reasoning_display", "reasoning.effort"} {
		if value, ok := raw[name]; ok {
			fields[name] = value
		}
	}
	if len(fields) == 0 {
		return nil, nil, nil
	}
	data, err := sonic.Marshal(fields)
	if err != nil {
		return nil, nil, ErrInvalidJSON
	}
	return data, fields, nil
}

// chatRawReasoning decodes the reasoning controls of a Chat Completions request, aliases included.
func chatRawReasoning(raw map[string]json.RawMessage) (*schemas.ChatReasoning, error) {
	data, _, err := rawReasoningFields(raw)
	if data == nil || err != nil {
		return nil, err
	}
	var parameters schemas.ChatParameters
	if err := sonic.Unmarshal(data, &parameters); err != nil {
		return nil, ErrInvalidJSON
	}
	return parameters.Reasoning, nil
}

// requestReasoningValidation checks the reasoning controls against each candidate deployment.
// requested is the output token limit that the client set. A reasoning budget at or above it
// leaves no room for an answer on any deployment, so the request is refused before routing.
func requestReasoningValidation(raw map[string]json.RawMessage, route Route, requested *int) (func(Deployment, int) error, error) {
	fitsOutputLimit := func(budget *int) error {
		if budget != nil && requested != nil && *budget >= *requested {
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning.max_tokens must be less than the output token limit"}
		}
		return nil
	}
	if route == RouteChat {
		parsed, err := chatRawReasoning(raw)
		if parsed == nil || err != nil {
			return nil, err
		}
		if err := fitsOutputLimit(parsed.MaxTokens); err != nil {
			return nil, err
		}
		return func(deployment Deployment, outputLimit int) error {
			reasoning := *parsed
			if err := normalizeChatReasoning(&reasoning, deployment, outputLimit); err != nil || !deployment.bridges(RouteChat) {
				return err
			}
			// Translate gives the deployment the controls as Responses take them.
			request := schemas.BifrostChatRequest{Params: &schemas.ChatParameters{Reasoning: &reasoning}}
			return conversionGapError(request.ResponsesGap(), "Responses")
		}, nil
	}
	data, fields, err := rawReasoningFields(raw)
	if data == nil || err != nil {
		return nil, err
	}
	var parameters schemas.ResponsesParameters
	if err := sonic.Unmarshal(data, &parameters); err != nil {
		return nil, ErrInvalidJSON
	}
	if value, ok := fields["reasoning.effort"]; ok {
		var effort string
		if err := sonic.Unmarshal(value, &effort); err != nil {
			return nil, ErrInvalidJSON
		}
		if parameters.Reasoning == nil {
			parameters.Reasoning = &schemas.ResponsesParametersReasoning{}
		}
		parameters.Reasoning.Effort = &effort
	}
	if parameters.Reasoning != nil {
		if err := fitsOutputLimit(parameters.Reasoning.MaxTokens); err != nil {
			return nil, err
		}
	}
	return func(deployment Deployment, outputLimit int) error {
		switch {
		case parameters.Reasoning == nil:
			return nil
		case deployment.bridges(RouteResponses):
			// Translate gives the deployment the controls as Chat Completions take them.
			return normalizeChatReasoning(chatReasoning(parameters.Reasoning), deployment, outputLimit)
		}
		reasoning := *parameters.Reasoning
		return normalizeResponsesReasoning(&reasoning, deployment, outputLimit)
	}, nil
}

func validateRawReasoningParameters(rawData map[string]json.RawMessage, allowedFields map[string]bool, allowAliases bool, allowDottedEffort bool) error {
	reasoning, hasReasoning, err := rawReasoningObject(rawData["reasoning"])
	if err != nil {
		return err
	}
	if hasReasoning {
		for name := range reasoning {
			if !allowedFields[name] {
				return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning." + name + " is not supported"}
			}
		}
	}
	if allowAliases {
		for _, item := range []struct {
			alias string
			field string
		}{
			{"reasoning_effort", "effort"},
			{"reasoning_max_tokens", "max_tokens"},
			{"reasoning_display", "display"},
		} {
			if _, ok := rawData[item.alias]; ok && hasReasoning {
				if _, exists := reasoning[item.field]; exists {
					return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: item.alias + " conflicts with reasoning." + item.field}
				}
			}
		}
		if err := validateRawReasoningEffort(rawData["reasoning_effort"], "reasoning_effort"); err != nil {
			return err
		}
		if err := validateRawReasoningDisplay(rawData["reasoning_display"], "reasoning_display"); err != nil {
			return err
		}
		if err := validateRawReasoningPositiveInteger(rawData["reasoning_max_tokens"], "reasoning_max_tokens"); err != nil {
			return err
		}
	}
	if allowDottedEffort {
		if err := validateRawReasoningEffort(rawData["reasoning.effort"], "reasoning.effort"); err != nil {
			return err
		}
		if _, ok := rawData["reasoning.effort"]; ok && hasReasoning {
			if _, exists := reasoning["effort"]; exists {
				return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning.effort conflicts with reasoning.effort"}
			}
		}
	}
	if hasReasoning {
		if err := validateRawReasoningBool(reasoning["enabled"], "reasoning.enabled"); err != nil {
			return err
		}
		if err := validateRawReasoningEffort(reasoning["effort"], "reasoning.effort"); err != nil {
			return err
		}
		if err := validateRawReasoningDisplay(reasoning["display"], "reasoning.display"); err != nil {
			return err
		}
		if err := validateRawReasoningPositiveInteger(reasoning["max_tokens"], "reasoning.max_tokens"); err != nil {
			return err
		}
		if err := validateRawReasoningSummary(reasoning["summary"], "reasoning.summary"); err != nil {
			return err
		}
		if _, _, err := rawReasoningString(reasoning["context"], "reasoning.context"); err != nil {
			return err
		}
	}
	return nil
}

func rawReasoningObject(raw json.RawMessage) (map[string]json.RawMessage, bool, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil, false, nil
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err != nil {
		return nil, false, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning must be an object"}
	}
	return object, true, nil
}

func validateRawReasoningEffort(raw json.RawMessage, name string) error {
	value, ok, err := rawReasoningString(raw, name)
	if err != nil || !ok {
		return err
	}
	if strings.TrimSpace(value) == "" {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be a string"}
	}
	return nil
}

func validateRawReasoningBool(raw json.RawMessage, name string) error {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	var value bool
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be a boolean"}
	}
	return nil
}

func validateRawReasoningDisplay(raw json.RawMessage, name string) error {
	_, _, err := rawReasoningString(raw, name)
	return err
}

func validateRawReasoningSummary(raw json.RawMessage, name string) error {
	_, _, err := rawReasoningString(raw, name)
	return err
}

func rawReasoningString(raw json.RawMessage, name string) (string, bool, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return "", false, nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", true, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be a string"}
	}
	return value, true, nil
}

func validateRawReasoningPositiveInteger(raw json.RawMessage, name string) error {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	var value int
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be an integer"}
	}
	if value < 1 {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " is outside the supported range"}
	}
	return nil
}
