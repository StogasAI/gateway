package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

var (
	errInvalidJSON  = errors.New("invalid JSON in PII redaction input")
	ErrNestingLimit = errors.New("PII redaction nesting limit exceeded")
)

type Surface uint8

const (
	SurfaceChat Surface = iota + 1
	SurfaceResponses
)

var (
	chatTextFields      = [...]string{"messages", "tools", "functions", "response_format", "prediction", "context_management", "stop", "stop_sequences"}
	responsesTextFields = [...]string{"input", "instructions", "tools", "text", "context_management", "stop", "stop_sequences"}
)

type jsonReplacement struct {
	start int
	end   int
	value []byte
	items uint32
}

type jsonValueContext uint8

const (
	jsonContextGeneral jsonValueContext = iota
	jsonContextChatMessages
	jsonContextChatMessage
	jsonContextResponsesInput
	jsonContextResponsesInputItem
)

// RedactRequestFields changes only provider-bound text containers. Routing,
// model, sampling, cache, storage, identity, and protocol controls are never
// inspected or changed.
func (r *Redactor) RedactRequestFields(raw map[string]json.RawMessage, surface Surface) error {
	if r == nil {
		return nil
	}
	startedAt := time.Now()
	defer func() {
		r.duration += time.Since(startedAt)
	}()
	var fields []string
	switch surface {
	case SurfaceChat:
		fields = chatTextFields[:]
	case SurfaceResponses:
		fields = responsesTextFields[:]
	default:
		return errInvalidJSON
	}
	type update struct {
		field string
		value json.RawMessage
	}
	baseItems := r.items
	var updates []update
	for _, field := range fields {
		value, ok := raw[field]
		if !ok || len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			continue
		}
		context := jsonContextGeneral
		if surface == SurfaceChat && field == "messages" {
			context = jsonContextChatMessages
		} else if surface == SurfaceResponses && field == "input" {
			context = jsonContextResponsesInput
		}
		redacted, changed, err := r.redactJSONContext(value, context)
		if err != nil {
			r.items = baseItems
			return err
		}
		if changed {
			updates = append(updates, update{field: field, value: redacted})
		}
	}
	for _, changed := range updates {
		raw[changed.field] = changed.value
	}
	return nil
}

func (r *Redactor) redactJSON(source []byte) ([]byte, bool, error) {
	return r.redactJSONContext(source, jsonContextGeneral)
}

func (r *Redactor) redactJSONContext(source []byte, context jsonValueContext) ([]byte, bool, error) {
	baseItems := r.items
	var replacements []jsonReplacement
	position, err := r.walkJSONValue(source, skipJSONSpace(source, 0), true, &replacements, 0, context)
	if err != nil || skipJSONSpace(source, position) != len(source) {
		r.items = baseItems
		if err == nil {
			err = errInvalidJSON
		}
		return nil, false, err
	}
	if len(replacements) == 0 {
		return source, false, nil
	}

	size := len(source)
	for _, replacement := range replacements {
		size += len(replacement.value) - (replacement.end - replacement.start)
	}
	out := make([]byte, 0, size)
	position = 0
	for _, replacement := range replacements {
		if replacement.start < position || replacement.end < replacement.start || replacement.end > len(source) {
			r.items = baseItems
			return nil, false, errInvalidJSON
		}
		out = append(out, source[position:replacement.start]...)
		out = append(out, replacement.value...)
		position = replacement.end
	}
	out = append(out, source[position:]...)
	return out, true, nil
}

func (r *Redactor) walkJSONValue(source []byte, position int, allow bool, replacements *[]jsonReplacement, depth int, context jsonValueContext) (int, error) {
	if depth > 128 {
		return position, ErrNestingLimit
	}
	if position >= len(source) {
		return position, errInvalidJSON
	}
	switch source[position] {
	case '"':
		end, escaped, err := jsonStringEnd(source, position)
		if err != nil || !allow {
			return end, err
		}
		return end, r.redactJSONString(source, position, end, escaped, replacements)
	case '{':
		return r.walkJSONObject(source, position, allow, replacements, depth+1, context)
	case '[':
		return r.walkJSONArray(source, position, allow, replacements, depth+1, context)
	default:
		end := position
		for end < len(source) && source[end] != ',' && source[end] != '}' && source[end] != ']' && source[end] != ' ' && source[end] != '\t' && source[end] != '\r' && source[end] != '\n' {
			end++
		}
		if end == position || !validJSONPrimitive(source[position:end]) {
			return position, errInvalidJSON
		}
		return end, nil
	}
}

func (r *Redactor) walkJSONObject(source []byte, position int, allow bool, replacements *[]jsonReplacement, depth int, context jsonValueContext) (int, error) {
	baseReplacements := len(*replacements)
	baseItems := r.items
	hasEncryptedContent := false
	hasReasoningDetails := false
	reasoningStart := -1
	reasoningEnd := -1
	itemType := ""
	position = skipJSONSpace(source, position+1)
	if position < len(source) && source[position] == '}' {
		return position + 1, nil
	}
	for {
		if position >= len(source) || source[position] != '"' {
			return position, errInvalidJSON
		}
		keyEnd, keyEscaped, err := jsonStringEnd(source, position)
		if err != nil {
			return position, err
		}
		key, err := classifyJSONKey(source[position:keyEnd], keyEscaped)
		if err != nil {
			return position, errInvalidJSON
		}
		position = skipJSONSpace(source, keyEnd)
		if position >= len(source) || source[position] != ':' {
			return position, errInvalidJSON
		}
		position = skipJSONSpace(source, position+1)
		if position >= len(source) {
			return position, errInvalidJSON
		}
		if key == jsonKeyEncryptedContent {
			present := false
			if source[position] == '"' {
				valueEnd, _, valueErr := jsonStringEnd(source, position)
				if valueErr != nil {
					return position, valueErr
				}
				present = valueEnd > position+2
			}
			hasEncryptedContent = present
		}
		if key == jsonKeyType {
			itemType = ""
			if source[position] == '"' {
				valueEnd, _, valueErr := jsonStringEnd(source, position)
				if valueErr != nil {
					return position, valueErr
				}
				value, valueErr := decodeJSONString(source[position:valueEnd])
				if valueErr == nil {
					itemType = value
				}
			}
		}
		valueAllowed := allow
		valueContext := jsonContextGeneral
		if context == jsonContextResponsesInputItem && key == jsonKeyEncryptedContent && source[position] == '"' {
			// The request policy permits encrypted_content here only on a valid
			// top-level reasoning replay item. Do not scan a large opaque ciphertext;
			// the complete object is preserved below when its effective markers match.
			valueAllowed = false
		}
		if context == jsonContextChatMessage && key == jsonKeyReasoningDetails {
			// Anthropic reasoning details contain provider-signed or encrypted
			// history. Preserve this exact protocol value. The request policy
			// validates its shape before any provider receives it.
			hasReasoningDetails = source[position] == '['
			if hasReasoningDetails {
				valueAllowed = false
			}
		}
		if context == jsonContextChatMessage && key == jsonKeyReasoning {
			reasoningStart = position
		}
		switch key {
		case jsonKeySkipScalar, jsonKeyType:
			// Protocol identifiers are not prompt text. If a tool schema uses one
			// of these names for an object or array, its nested descriptions still
			// need redaction.
			if source[position] != '{' && source[position] != '[' {
				valueAllowed = false
			}
		}
		position, err = r.walkJSONValue(source, position, valueAllowed, replacements, depth, valueContext)
		if err != nil {
			return position, err
		}
		if context == jsonContextChatMessage && key == jsonKeyReasoning {
			reasoningEnd = position
		}
		position = skipJSONSpace(source, position)
		if position >= len(source) {
			return position, errInvalidJSON
		}
		switch source[position] {
		case ',':
			position = skipJSONSpace(source, position+1)
		case '}':
			if context == jsonContextChatMessage && hasReasoningDetails && reasoningStart >= 0 {
				r.discardJSONReplacements(replacements, baseReplacements, reasoningStart, reasoningEnd)
			}
			protected := context == jsonContextResponsesInputItem && itemType == "reasoning" && hasEncryptedContent
			if protected {
				*replacements = (*replacements)[:baseReplacements]
				r.items = baseItems
			}
			return position + 1, nil
		default:
			return position, errInvalidJSON
		}
	}
}

func (r *Redactor) walkJSONArray(source []byte, position int, allow bool, replacements *[]jsonReplacement, depth int, context jsonValueContext) (int, error) {
	position = skipJSONSpace(source, position+1)
	if position < len(source) && source[position] == ']' {
		return position + 1, nil
	}
	for {
		var err error
		childContext := jsonContextGeneral
		switch context {
		case jsonContextChatMessages:
			childContext = jsonContextChatMessage
		case jsonContextResponsesInput:
			childContext = jsonContextResponsesInputItem
		}
		position, err = r.walkJSONValue(source, position, allow, replacements, depth, childContext)
		if err != nil {
			return position, err
		}
		position = skipJSONSpace(source, position)
		if position >= len(source) {
			return position, errInvalidJSON
		}
		switch source[position] {
		case ',':
			position = skipJSONSpace(source, position+1)
		case ']':
			return position + 1, nil
		default:
			return position, errInvalidJSON
		}
	}
}

func (r *Redactor) redactJSONString(source []byte, start, end int, escaped bool, replacements *[]jsonReplacement) error {
	encoded := source[start:end]
	if !escaped {
		baseItems := r.items
		redacted, changed, err := r.redactBytes(source[start+1 : end-1])
		if err != nil {
			return err
		}
		if changed {
			*replacements = append(*replacements, jsonReplacement{start: start + 1, end: end - 1, value: redacted, items: r.items - baseItems})
		}
		return nil
	}
	decoded, err := decodeJSONString(encoded)
	if err != nil {
		return errInvalidJSON
	}
	baseItems := r.items
	redacted, changed, err := r.redactBytes([]byte(decoded))
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	encodedRedacted, err := json.Marshal(string(redacted))
	if err != nil {
		return err
	}
	*replacements = append(*replacements, jsonReplacement{start: start, end: end, value: encodedRedacted, items: r.items - baseItems})
	return nil
}

func (r *Redactor) discardJSONReplacements(replacements *[]jsonReplacement, first, start, end int) {
	if start < 0 || end < start || first < 0 || first > len(*replacements) {
		return
	}
	values := *replacements
	write := first
	for read := first; read < len(values); read++ {
		replacement := values[read]
		if replacement.start >= start && replacement.end <= end {
			r.items -= replacement.items
			continue
		}
		values[write] = replacement
		write++
	}
	*replacements = values[:write]
}

func jsonStringEnd(source []byte, start int) (int, bool, error) {
	if start >= len(source) || source[start] != '"' {
		return start, false, errInvalidJSON
	}
	escaped := false
	hadEscape := false
	for position := start + 1; position < len(source); position++ {
		if escaped {
			escaped = false
			switch source[position] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				if position+4 >= len(source) {
					return position, hadEscape, errInvalidJSON
				}
				for _, character := range source[position+1 : position+5] {
					if !isJSONHex(character) {
						return position, hadEscape, errInvalidJSON
					}
				}
				position += 4
			default:
				return position, hadEscape, errInvalidJSON
			}
			continue
		}
		if source[position] < 0x20 {
			return position, hadEscape, errInvalidJSON
		}
		switch source[position] {
		case '\\':
			escaped = true
			hadEscape = true
		case '"':
			return position + 1, hadEscape, nil
		}
	}
	return len(source), hadEscape, errInvalidJSON
}

func isJSONHex(value byte) bool {
	return isASCIIDigit(value) || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func validJSONPrimitive(value []byte) bool {
	if bytes.Equal(value, []byte("true")) || bytes.Equal(value, []byte("false")) || bytes.Equal(value, []byte("null")) {
		return true
	}
	position := 0
	if position < len(value) && value[position] == '-' {
		position++
	}
	if position >= len(value) {
		return false
	}
	if value[position] == '0' {
		position++
		if position < len(value) && isASCIIDigit(value[position]) {
			return false
		}
	} else {
		if value[position] < '1' || value[position] > '9' {
			return false
		}
		for position < len(value) && isASCIIDigit(value[position]) {
			position++
		}
	}
	if position < len(value) && value[position] == '.' {
		position++
		fractionStart := position
		for position < len(value) && isASCIIDigit(value[position]) {
			position++
		}
		if position == fractionStart {
			return false
		}
	}
	if position < len(value) && (value[position] == 'e' || value[position] == 'E') {
		position++
		if position < len(value) && (value[position] == '+' || value[position] == '-') {
			position++
		}
		exponentStart := position
		for position < len(value) && isASCIIDigit(value[position]) {
			position++
		}
		if position == exponentStart {
			return false
		}
	}
	return position == len(value)
}

func decodeJSONString(encoded []byte) (string, error) {
	var decoded string
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return "", err
	}
	return decoded, nil
}

func skipJSONSpace(source []byte, position int) int {
	for position < len(source) {
		switch source[position] {
		case ' ', '\t', '\r', '\n':
			position++
		default:
			return position
		}
	}
	return position
}

type jsonKeyKind uint8

const (
	jsonKeyOther jsonKeyKind = iota
	jsonKeySkipScalar
	jsonKeyEncryptedContent
	jsonKeyType
	jsonKeyReasoning
	jsonKeyReasoningDetails
)

func classifyJSONKey(encoded []byte, escaped bool) (jsonKeyKind, error) {
	var key string
	if escaped {
		decoded, err := decodeJSONString(encoded)
		if err != nil {
			return jsonKeyOther, err
		}
		key = decoded
	} else {
		key = string(encoded[1 : len(encoded)-1])
	}
	switch key {
	case "encrypted_content":
		return jsonKeyEncryptedContent, nil
	case "type":
		return jsonKeyType, nil
	case "reasoning":
		return jsonKeyReasoning, nil
	case "reasoning_details":
		return jsonKeyReasoningDetails, nil
	case "id", "item_id", "call_id", "tool_call_id", "file_id", "container_id", "conversation_id",
		"request_id", "session_id", "previous_response_id", "prompt_cache_key", "prompt_cache_isolation_key",
		"model", "name", "role":
		return jsonKeySkipScalar, nil
	default:
		return jsonKeyOther, nil
	}
}
