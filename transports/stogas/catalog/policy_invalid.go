package catalog

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/bytedance/sonic"
)

type invalidPathTarget struct {
	raw     json.RawMessage
	missing bool
}

type invalidPathSegment struct {
	field  string
	filter bool
	value  string
}

func validateInvalidParameterRules(name string, raw json.RawMessage, policy compiledParameter) error {
	rejectRules := parameterRejectRules(policy)
	if len(rejectRules) == 0 {
		return nil
	}
	for _, rule := range rejectRules {
		invalid, err := invalidRequestValue(raw, rule)
		if err != nil {
			return ErrInvalidJSON
		}
		if invalid {
			if name == "tools" {
				return ErrUnsupportedTool
			}
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " is not allowed by catalog policy"}
		}
	}
	return nil
}

func invalidRequestValue(raw json.RawMessage, rule compiledRejectRule) (bool, error) {
	targets, err := invalidPathTargets(raw, rule.Path)
	if err != nil {
		return false, err
	}
	for _, target := range targets {
		invalid, err := invalidTargetValue(target, rule)
		if err != nil || invalid {
			return invalid, err
		}
	}
	return false, nil
}

func invalidPathTargets(raw json.RawMessage, path string) ([]invalidPathTarget, error) {
	segments, err := parseInvalidPath(path)
	if err != nil {
		return nil, err
	}
	targets := []invalidPathTarget{{raw: raw}}
	for _, segment := range segments {
		next := make([]invalidPathTarget, 0, len(targets))
		for _, target := range targets {
			expanded, err := expandInvalidPathTarget(target, segment)
			if err != nil {
				return nil, err
			}
			next = append(next, expanded...)
		}
		targets = next
	}
	return targets, nil
}

func parseInvalidPath(path string) ([]invalidPathSegment, error) {
	if path == "$" {
		return nil, nil
	}
	if !strings.HasPrefix(path, "$") {
		return nil, fmt.Errorf("invalid catalog policy path %q", path)
	}
	rest := strings.TrimPrefix(path, "$")
	segments := []invalidPathSegment{}
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "[]"):
			segments = append(segments, invalidPathSegment{})
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
			segments = append(segments, invalidPathSegment{
				field:  strings.TrimSpace(parts[0]),
				filter: true,
				value:  strings.ToLower(strings.TrimSpace(parts[1])),
			})
			rest = rest[end+1:]
		case strings.HasPrefix(rest, "."):
			rest = strings.TrimPrefix(rest, ".")
			end := strings.IndexAny(rest, ".[")
			if end < 0 {
				segments = append(segments, invalidPathSegment{field: rest})
				rest = ""
			} else {
				segments = append(segments, invalidPathSegment{field: rest[:end]})
				rest = rest[end:]
			}
		default:
			return nil, fmt.Errorf("invalid catalog policy path %q", path)
		}
	}
	return segments, nil
}

func expandInvalidPathTarget(target invalidPathTarget, segment invalidPathSegment) ([]invalidPathTarget, error) {
	if target.missing {
		return []invalidPathTarget{target}, nil
	}
	if segment.field == "" {
		var values []json.RawMessage
		if err := sonic.Unmarshal(target.raw, &values); err != nil {
			return nil, nil
		}
		targets := make([]invalidPathTarget, 0, len(values))
		for _, value := range values {
			targets = append(targets, invalidPathTarget{raw: value})
		}
		return targets, nil
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(target.raw, &object); err != nil {
		return nil, nil
	}
	if segment.filter {
		if rawStringField(object, segment.field) == segment.value {
			return []invalidPathTarget{target}, nil
		}
		return nil, nil
	}
	value, ok := object[segment.field]
	if !ok {
		return []invalidPathTarget{{missing: true}}, nil
	}
	return []invalidPathTarget{{raw: value}}, nil
}

func invalidTargetValue(target invalidPathTarget, rule compiledRejectRule) (bool, error) {
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
		if invalidObjectShape(object, rule) {
			return true, nil
		}
	}
	if len(rule.Values) > 0 || len(rule.Prefixes) > 0 || len(rule.ValuesExcept) > 0 {
		value, ok := rawString(target.raw)
		if !ok {
			return true, nil
		}
		return invalidStringValue(value, rule), nil
	}
	return false, nil
}

func invalidObjectShape(object map[string]json.RawMessage, rule compiledRejectRule) bool {
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

func invalidStringValue(value string, rule compiledRejectRule) bool {
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
