package catalog

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/bytedance/sonic"
)

type rejectPathTarget struct {
	raw     json.RawMessage
	missing bool
}

type rejectPathSegment struct {
	field  string
	filter bool
	value  string
}

func validateParameterRejectRules(name string, raw json.RawMessage, policy compiledParameter) error {
	rejectRules := parameterRejectRules(policy)
	if len(rejectRules) == 0 {
		return nil
	}
	for _, rule := range rejectRules {
		rejected, err := rejectsRequestValue(raw, rule)
		if err != nil {
			return ErrInvalidJSON
		}
		if rejected {
			if name == "tools" {
				return ErrUnsupportedTool
			}
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " is not allowed by catalog policy"}
		}
	}
	return nil
}

func validateParameterValue(name string, raw json.RawMessage, policy compiledParameter) error {
	if len(policy.Values) == 0 {
		return nil
	}
	value, ok := scalarPolicyValue(raw)
	if !ok || !stringSet(policy.Values)[value] {
		return APIError{
			StatusCode: http.StatusBadRequest,
			Type:       ErrorTypeInvalidRequest,
			Message:    name + " must be one of: " + strings.Join(policy.Values, ", "),
		}
	}
	return nil
}

func scalarPolicyValue(raw json.RawMessage) (string, bool) {
	var value string
	if err := sonic.Unmarshal(raw, &value); err == nil {
		return value, true
	}
	var scalar any
	if err := sonic.Unmarshal(raw, &scalar); err != nil {
		return "", false
	}
	switch typed := scalar.(type) {
	case bool:
		if typed {
			return "true", true
		}
		return "false", true
	case float64:
		return fmt.Sprintf("%v", typed), true
	default:
		return "", false
	}
}

func rejectsRequestValue(raw json.RawMessage, rule compiledRejectRule) (bool, error) {
	targets, err := rejectPathTargets(raw, rule.Path)
	if err != nil {
		return false, err
	}
	for _, target := range targets {
		rejected, err := rejectTargetValue(target, rule)
		if err != nil || rejected {
			return rejected, err
		}
	}
	return false, nil
}

func rejectPathTargets(raw json.RawMessage, path string) ([]rejectPathTarget, error) {
	segments, err := parseRejectPath(path)
	if err != nil {
		return nil, err
	}
	targets := []rejectPathTarget{{raw: raw}}
	for _, segment := range segments {
		next := make([]rejectPathTarget, 0, len(targets))
		for _, target := range targets {
			expanded, err := expandRejectPathTarget(target, segment)
			if err != nil {
				return nil, err
			}
			next = append(next, expanded...)
		}
		targets = next
	}
	return targets, nil
}

func parseRejectPath(path string) ([]rejectPathSegment, error) {
	if path == "$" {
		return nil, nil
	}
	if !strings.HasPrefix(path, "$") {
		return nil, fmt.Errorf("invalid catalog policy path %q", path)
	}
	rest := strings.TrimPrefix(path, "$")
	segments := []rejectPathSegment{}
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "[]"):
			segments = append(segments, rejectPathSegment{})
			rest = strings.TrimPrefix(rest, "[]")
		case strings.HasPrefix(rest, "["):
			end := strings.Index(rest, "]")
			if end < 0 {
				return nil, fmt.Errorf("invalid catalog policy path %q", path)
			}
			parts := strings.SplitN(rest[1:end], "=", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
				return nil, fmt.Errorf("invalid catalog policy path %q", path)
			}
			segments = append(segments, rejectPathSegment{
				field:  strings.TrimSpace(parts[0]),
				filter: true,
				value:  strings.ToLower(strings.TrimSpace(parts[1])),
			})
			rest = rest[end+1:]
		case strings.HasPrefix(rest, "."):
			rest = strings.TrimPrefix(rest, ".")
			end := strings.IndexAny(rest, ".[")
			if end < 0 {
				segments = append(segments, rejectPathSegment{field: rest})
				rest = ""
			} else {
				segments = append(segments, rejectPathSegment{field: rest[:end]})
				rest = rest[end:]
			}
		default:
			return nil, fmt.Errorf("invalid catalog policy path %q", path)
		}
	}
	return segments, nil
}

func expandRejectPathTarget(target rejectPathTarget, segment rejectPathSegment) ([]rejectPathTarget, error) {
	if target.missing {
		return []rejectPathTarget{target}, nil
	}
	if segment.field == "" {
		var values []json.RawMessage
		if err := sonic.Unmarshal(target.raw, &values); err != nil {
			return nil, nil
		}
		targets := make([]rejectPathTarget, 0, len(values))
		for _, value := range values {
			targets = append(targets, rejectPathTarget{raw: value})
		}
		return targets, nil
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(target.raw, &object); err != nil {
		return nil, nil
	}
	if segment.filter {
		if rawStringField(object, segment.field) == segment.value {
			return []rejectPathTarget{target}, nil
		}
		return nil, nil
	}
	value, ok := object[segment.field]
	if !ok {
		return []rejectPathTarget{{missing: true}}, nil
	}
	return []rejectPathTarget{{raw: value}}, nil
}

func rejectTargetValue(target rejectPathTarget, rule compiledRejectRule) (bool, error) {
	if target.missing {
		return rule.Missing || len(rule.RequiredKeys) > 0 || len(rule.ValuesExcept) > 0, nil
	}
	if rule.Exists {
		return true, nil
	}
	if len(rule.RequiredKeys) > 0 || len(rule.AllowedKeys) > 0 {
		var object map[string]json.RawMessage
		if err := sonic.Unmarshal(target.raw, &object); err != nil {
			return false, err
		}
		if rejectsObjectShape(object, rule) {
			return true, nil
		}
	}
	if len(rule.Values) > 0 || len(rule.Prefixes) > 0 || len(rule.ValuesExcept) > 0 {
		value, ok := rawString(target.raw)
		if !ok {
			return true, nil
		}
		return rejectsStringValue(value, rule), nil
	}
	return false, nil
}

func rejectsObjectShape(object map[string]json.RawMessage, rule compiledRejectRule) bool {
	if len(rule.RequiredKeys) > 0 {
		for _, key := range rule.RequiredKeys {
			if _, ok := object[key]; !ok {
				return true
			}
		}
	}
	if len(rule.AllowedKeys) > 0 {
		allowed := stringSet(rule.AllowedKeys)
		for key := range object {
			if !allowed[strings.ToLower(strings.TrimSpace(key))] {
				return true
			}
		}
	}
	return false
}

func rawString(raw json.RawMessage) (string, bool) {
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(value)), true
}

func rejectsStringValue(value string, rule compiledRejectRule) bool {
	if value == "" {
		return false
	}
	denied := stringSetFromAny(rule.Values)
	if denied[value] || deniedPrefix(value, rule.Prefixes) {
		return true
	}
	if len(rule.ValuesExcept) > 0 {
		allowed := stringSetFromAny(rule.ValuesExcept)
		return !allowed[value]
	}
	return false
}

func deniedPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		normalized := strings.ToLower(strings.TrimSpace(prefix))
		if value == normalized || strings.HasPrefix(value, normalized+"-") || strings.HasPrefix(value, normalized+"_") {
			return true
		}
	}
	return false
}

func rawStringField(object map[string]json.RawMessage, key string) string {
	raw, ok := object[key]
	if !ok {
		return ""
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized != "" {
			set[normalized] = true
		}
	}
	return set
}

func stringSetFromAny(values []any) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		stringValue, ok := value.(string)
		if !ok {
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(stringValue))
		if normalized != "" {
			set[normalized] = true
		}
	}
	return set
}
