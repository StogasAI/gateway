package catalog

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
)

var canonicalReasoningEfforts = []string{"minimal", "low", "medium", "high", "xhigh", "max"}

type normalizedReasoning struct {
	Effort  *string
	Enabled *bool
}

func normalizeReasoningEffort(
	requested string,
	deployment Deployment,
) (normalizedReasoning, error) {
	if requested == "none" {
		switch deployment.ReasoningAvailability {
		case "unsupported":
			return normalizedReasoning{}, nil
		case "optional":
			if len(deployment.ReasoningEfforts) == 0 {
				enabled := false
				return normalizedReasoning{Enabled: &enabled}, nil
			}
			effort := requested
			return normalizedReasoning{Effort: &effort}, nil
		default:
			return normalizedReasoning{}, APIError{
				StatusCode: http.StatusBadRequest,
				Type:       ErrorTypeInvalidRequest,
				Message:    "reasoning cannot be disabled for the selected deployment",
			}
		}
	}
	if reasoningEffortIndex(requested) < 0 {
		return normalizedReasoning{}, APIError{
			StatusCode: http.StatusBadRequest,
			Type:       ErrorTypeInvalidRequest,
			Message:    "reasoning effort must be one of: none, minimal, low, medium, high, xhigh, max",
		}
	}
	if deployment.ReasoningAvailability == "unsupported" {
		return normalizedReasoning{}, APIError{
			StatusCode: http.StatusBadRequest,
			Type:       ErrorTypeInvalidRequest,
			Message:    "reasoning is not supported for the selected deployment",
		}
	}
	if len(deployment.ReasoningEfforts) == 0 {
		if deployment.ReasoningAvailability == "optional" {
			enabled := true
			return normalizedReasoning{Enabled: &enabled}, nil
		}
		return normalizedReasoning{}, APIError{
			StatusCode: http.StatusBadRequest,
			Type:       ErrorTypeInvalidRequest,
			Message:    "the selected deployment always reasons but does not expose effort selection; use reasoning.enabled",
		}
	}
	effort := nearestReasoningEffort(requested, deployment.ReasoningEfforts)
	return normalizedReasoning{Effort: &effort}, nil
}

func normalizeReasoningEnabled(enabled bool, deployment Deployment) (normalizedReasoning, error) {
	if !enabled {
		return normalizeReasoningEffort("none", deployment)
	}
	if deployment.ReasoningAvailability == "unsupported" {
		return normalizedReasoning{}, APIError{
			StatusCode: http.StatusBadRequest,
			Type:       ErrorTypeInvalidRequest,
			Message:    "reasoning is not supported for the selected deployment",
		}
	}
	if len(deployment.ReasoningEfforts) == 0 {
		if deployment.ReasoningAvailability == "optional" {
			value := true
			return normalizedReasoning{Enabled: &value}, nil
		}
		return normalizedReasoning{}, nil
	}
	return normalizeReasoningEffort("medium", deployment)
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
	if err := validateReasoningMaxTokens(
		reasoning.Effort,
		reasoning.Enabled,
		reasoning.MaxTokens,
		deployment,
		outputTokenLimit,
	); err != nil {
		return err
	}
	if reasoning.MaxTokens != nil {
		reasoning.Enabled = nil
		return nil
	}
	var (
		selection normalizedReasoning
		err       error
	)
	switch {
	case reasoning.Effort != nil:
		selection, err = normalizeReasoningEffort(*reasoning.Effort, deployment)
	case reasoning.Enabled != nil:
		selection, err = normalizeReasoningEnabled(*reasoning.Enabled, deployment)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	reasoning.Effort = selection.Effort
	reasoning.Enabled = selection.Enabled
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
	for index, effort := range canonicalReasoningEfforts {
		if value == effort {
			return index
		}
	}
	return -1
}

func validateReasoningMaxTokens(effort *string, enabled *bool, maxTokens *int, deployment Deployment, outputTokenLimit int) error {
	if maxTokens == nil {
		return nil
	}
	if effort != nil {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning effort conflicts with a manual reasoning token limit"}
	}
	if enabled != nil && !*enabled {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "disabled reasoning conflicts with a manual reasoning token limit"}
	}
	capability := deployment.ReasoningMaxTokens
	if capability == nil {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "manual reasoning token limits are not supported for the selected deployment; use reasoning.effort"}
	}
	if *maxTokens < capability.Minimum {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning.max_tokens must be at least the deployment minimum"}
	}
	if *maxTokens > capability.Maximum {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning.max_tokens exceeds the deployment maximum"}
	}
	if *maxTokens >= outputTokenLimit {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning.max_tokens must be less than the output token limit"}
	}
	return nil
}

var (
	chatRawReasoningFields = map[string]bool{
		"display":    true,
		"enabled":    true,
		"effort":     true,
		"max_tokens": true,
	}
	responsesRawReasoningFields = map[string]bool{
		"effort":           true,
		"generate_summary": true,
		"max_tokens":       true,
		"summary":          true,
	}
)

func validateRawReasoningParameters(rawData map[string]json.RawMessage, allowedFields map[string]bool, allowAliases bool, allowDottedEffort bool) error {
	reasoning, hasReasoning, err := rawReasoningObject(rawData["reasoning"])
	if err != nil {
		return err
	}
	if hasReasoning {
		for name := range reasoning {
			if !allowedFields[name] {
				return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning." + name + " is not supported by Stogas API"}
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
		if err := validateRawReasoningSummary(reasoning["generate_summary"], "reasoning.generate_summary"); err != nil {
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
