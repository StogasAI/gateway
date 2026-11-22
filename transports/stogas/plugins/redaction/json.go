package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	errInvalidJSON  = errors.New("invalid JSON in PII redaction input")
	ErrNestingLimit = errors.New("PII redaction nesting limit exceeded")
)

type Surface uint8

// ValidateASCII checks original decoded text using the same field selection as
// redaction. Protocol identifiers and opaque replay fields remain untouched.
func ValidateASCII(raw map[string]json.RawMessage, surface Surface) error {
	r := &Redactor{asciiOnly: true}
	return r.RedactRequestFields(raw, surface, nil)
}

const (
	SurfaceChat Surface = iota + 1
	SurfaceResponses
)

var (
	chatTextFields      = [...]string{"messages", "tools", "functions", "response_format", "prediction", "context_management", "stop", "stop_sequences"}
	responsesTextFields = [...]string{"input", "instructions", "tools", "text", "context_management", "stop", "stop_sequences"}
)

// jsonSpan is the source range of one value and what its walk measured of its text.
type jsonSpan struct {
	start, end int
	text       inputText
}

type jsonReplacement struct {
	start int
	end   int
	value []byte
	items uint32
	// restored counts the placeholders of the string that got their values back, and refused
	// is the kind of value that a refusing redaction found in it.
	restored uint32
	refused  Entity
}

type jsonValueContext uint8

const (
	jsonContextGeneral jsonValueContext = iota
	jsonContextChatMessages
	jsonContextChatMessage
	jsonContextResponsesInput
	jsonContextResponsesInputItem
	jsonContextContent
	jsonContextContentBlock
	jsonContextFile
	jsonContextResponsesTools
	jsonContextResponsesTool
	jsonContextReasoningDetails
	jsonContextReasoningDetail
	jsonContextSearchAction
	jsonContextSearchResults
	jsonContextSearchResult
	// The contexts below read a response. Only the reply's own content is text: a Chat
	// choice's message or delta, and a Responses output. The fields around them are protocol
	// values, or settings that the provider repeats from the request.
	jsonContextReplyChat
	jsonContextReplyChoices
	jsonContextReplyChoice
	jsonContextReplyResponses
	jsonContextReplyEvent
)

// RedactRequestFields changes only provider-bound text containers. Routing,
// model, sampling, cache, storage, identity, and protocol controls are never
// inspected or changed. reserveExpansion, when provided, admits cumulative
// added bytes before retaining larger replacements. A failure leaves raw intact.
func (r *Redactor) RedactRequestFields(raw map[string]json.RawMessage, surface Surface, reserveExpansion func(int) error) error {
	if r == nil {
		return nil
	}
	startedAt := time.Now()
	r.expansion, r.reserveExpansion = 0, reserveExpansion
	defer func() {
		r.duration += time.Since(startedAt)
		r.reserveExpansion = nil
		r.part = partUnknown
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
	baseItems, baseInput := r.items, r.input
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
		} else if surface == SurfaceResponses && field == "tools" {
			context = jsonContextResponsesTools
		}
		r.part = requestFieldPart(field, value)
		redacted, changed, err := r.redactJSONContext(value, context)
		if err != nil {
			r.items = baseItems
			r.input = baseInput
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

func (r *Redactor) redactJSONContext(source []byte, context jsonValueContext) ([]byte, bool, error) {
	baseItems, baseInput := r.items, r.input
	var replacements []jsonReplacement
	position, err := r.walkJSONValue(source, skipJSONSpace(source, 0), true, &replacements, 0, context)
	if err != nil || skipJSONSpace(source, position) != len(source) {
		r.items = baseItems
		r.input = baseInput
		if err == nil {
			err = errInvalidJSON
		}
		return nil, false, err
	}
	if len(replacements) == 0 {
		return source, false, nil
	}
	// A refusal counts only once the walk has passed every marker of protected replay, as an
	// ASCII violation does.
	for _, replacement := range replacements {
		if replacement.refused != 0 {
			r.items = baseItems
			r.input = baseInput
			return nil, false, &RefusedError{Entity: replacement.refused}
		}
	}
	if r.asciiOnly {
		// Object markers can appear after their text. Resolve protected replay
		// before reporting a violation, just as redaction discards replacements.
		r.items = baseItems
		r.input = baseInput
		return nil, false, ErrNonASCII
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
			r.input = baseInput
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
		if r.reply && context == jsonContextResponsesInputItem && !r.keepPlaceholders {
			// A reasoning item gets no value back (RedactReply).
			_, itemType, _ := objectRoleAndType(source, position)
			r.keepPlaceholders = itemType == "reasoning"
			end, err := r.walkJSONObject(source, position, allow, replacements, depth+1, context)
			r.keepPlaceholders = false
			return end, err
		}
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
	baseItems, baseInput, baseRestored := r.items, r.input, r.restored
	// A generated image is base64 that no detector reads. A reply holds megabytes of it, so the
	// walk learns the item's type before it reaches the image.
	generatedImage := false
	keepPlaceholders := r.keepPlaceholders
	if r.reply && context == jsonContextResponsesInputItem {
		_, early, _ := objectRoleAndType(source, position)
		generatedImage = early == "image_generation_call"
	}
	hasEncryptedContent := false
	// A reasoning detail with a signature or encrypted data, and a reasoning item with encrypted
	// content or a signature, is the provider's own: a provider refuses a changed one, so it stays
	// as the client sent it, and so does the reasoning text of a detail's message, which the
	// request's checks compare with it. Only the provider that checks it gets such reasoning.
	// Other reasoning history is text like any other.
	hasSignature, hasData := false, false
	sealedDetails := r.sealedDetails
	var reasoningTexts []jsonSpan
	itemType := ""
	// An MCP tool's connection settings reach the provider as the client sent them: its
	// credentials and server address are not prompt text, and a redacted token would fail. So do
	// the settings of a hosted container, whose network policy holds the domains that its code
	// may reach and the secrets that it sends them.
	var toolSettings []jsonSpan
	// A web search that a reply returned holds Claude's encrypted results, which Claude refuses
	// changed. Their spans wait for the item's type.
	searchResults := len(r.searchResults)
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
		switch key {
		case jsonKeyEncryptedContent:
			if hasEncryptedContent, err = jsonStringHasText(source, position); err != nil {
				return position, err
			}
		case jsonKeySignature:
			if hasSignature, err = jsonStringHasText(source, position); err != nil {
				return position, err
			}
		case jsonKeyData:
			if hasData, err = jsonStringHasText(source, position); err != nil {
				return position, err
			}
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
		switch context {
		case jsonContextReplyChat:
			valueAllowed = allow && key == jsonKeyChoices
			valueContext = jsonContextReplyChoices
		case jsonContextReplyChoice:
			valueAllowed = allow && key == jsonKeyMessage
			valueContext = jsonContextChatMessage
		case jsonContextReplyResponses:
			valueAllowed = allow && key == jsonKeyOutput
			valueContext = jsonContextResponsesInput
		case jsonContextReplyEvent:
			switch key {
			case jsonKeyItem:
				valueContext = jsonContextResponsesInputItem
			case jsonKeyPart:
				valueContext = jsonContextContentBlock
			case jsonKeyResponse:
				valueContext = jsonContextReplyResponses
			}
		}
		if r.reply {
			// A reply's media, encrypted values, signatures, citations and metadata are the
			// provider's values, and its log probabilities repeat its text token by token.
			switch key {
			case jsonKeyOpaqueMedia, jsonKeyLogProbs, jsonKeyProviderData:
				valueAllowed = false
			case jsonKeyContext:
				if context == jsonContextChatMessage {
					valueAllowed = false
				}
			case jsonKeyData, jsonKeyEncryptedContent, jsonKeySignature, jsonKeyOpaqueText:
				if source[position] == '"' {
					valueAllowed = false
				}
			case jsonKeyResult:
				if generatedImage {
					valueAllowed = false
				}
			}
		}
		// A tool output in parts holds text and attachments as a message's content does.
		if (context == jsonContextChatMessage || context == jsonContextResponsesInputItem) && key == jsonKeyContent ||
			context == jsonContextResponsesInputItem && key == jsonKeyOutput {
			valueContext = jsonContextContent
		}
		if context == jsonContextContentBlock {
			switch key {
			case jsonKeyFile:
				valueContext = jsonContextFile
			case jsonKeyOpaqueMedia:
				valueAllowed = false
			}
		}
		if context == jsonContextFile && key == jsonKeyOpaqueMedia {
			valueAllowed = false
		}
		if context == jsonContextResponsesInputItem && key == jsonKeyEncryptedContent && source[position] == '"' {
			// The request policy permits encrypted_content here only on a valid
			// top-level reasoning replay item. Do not scan a large opaque ciphertext;
			// the complete object is preserved below when its effective markers match.
			valueAllowed = false
		}
		if context == jsonContextChatMessage && key == jsonKeyReasoningDetails {
			valueContext = jsonContextReasoningDetails
		}
		if context == jsonContextResponsesInputItem && key == jsonKeyAction {
			valueContext = jsonContextSearchAction
		}
		if context == jsonContextSearchAction && key == jsonKeySources {
			valueContext = jsonContextSearchResults
		}
		if context == jsonContextReasoningDetail && (key == jsonKeySignature || key == jsonKeyData) && source[position] == '"' {
			valueAllowed = false
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
		settingStart, settingInput := position, r.input
		// A function call's arguments are a JSON document in a string, and so is the text of a
		// reply to a request that asked for JSON output.
		argumentsJSON := r.argumentsJSON
		if key == jsonKeyArguments || r.reply && r.jsonOutput && key == jsonKeyContent {
			r.argumentsJSON = true
		}
		// The provider runs the call of a hosted tool and writes the result into the call's own
		// item, so the result is a tool result and the rest of the item is the model's.
		if r.reply && context == jsonContextChatMessage && (key == jsonKeyReasoning || key == jsonKeyReasoningDetails) {
			r.keepPlaceholders = true
		}
		part := r.part
		if !r.reply && r.part == PartAssistant &&
			(context == jsonContextResponsesInputItem && (key == jsonKeyOutput || key == jsonKeyCallResult) ||
				context == jsonContextSearchAction && key == jsonKeySources) {
			r.part = PartToolResults
		}
		position, err = r.walkJSONValue(source, position, valueAllowed, replacements, depth, valueContext)
		r.argumentsJSON, r.part = argumentsJSON, part
		if context == jsonContextChatMessage {
			r.keepPlaceholders = keepPlaceholders
		}
		if err != nil {
			return position, err
		}
		if context == jsonContextResponsesTool && key == jsonKeyToolSetting {
			toolSettings = append(toolSettings, jsonSpan{start: settingStart, end: position, text: r.input.minus(settingInput)})
		}
		if context == jsonContextChatMessage && key == jsonKeyReasoning {
			reasoningTexts = append(reasoningTexts, jsonSpan{start: settingStart, end: position, text: r.input.minus(settingInput)})
		}
		if context == jsonContextSearchResult && key == jsonKeyEncryptedContent && source[settingStart] == '"' {
			r.searchResults = append(r.searchResults, jsonSpan{start: settingStart, end: position, text: r.input.minus(settingInput)})
		}
		position = skipJSONSpace(source, position)
		if position >= len(source) {
			return position, errInvalidJSON
		}
		switch source[position] {
		case ',':
			position = skipJSONSpace(source, position+1)
		case '}':
			if context == jsonContextChatMessage && r.sealedDetails != sealedDetails {
				for _, text := range reasoningTexts {
					r.discardJSONReplacements(replacements, baseReplacements, text.start, text.end)
					r.input = r.input.minus(text.text)
				}
			}
			if context == jsonContextResponsesInputItem {
				if itemType == "web_search_call" {
					for _, result := range r.searchResults[searchResults:] {
						r.discardJSONReplacements(replacements, baseReplacements, result.start, result.end)
						r.input = r.input.minus(result.text)
					}
				}
				r.searchResults = r.searchResults[:searchResults]
			}
			if context == jsonContextResponsesTool && (itemType == "mcp" || itemType == "code_interpreter" || itemType == "shell") {
				for _, setting := range toolSettings {
					// A shell that the client runs lists skills that the model reads.
					if _, kind, _ := objectRoleAndType(source, setting.start); itemType == "shell" && (kind == "" || kind == "local") {
						continue
					}
					r.discardJSONReplacements(replacements, baseReplacements, setting.start, setting.end)
					r.input = r.input.minus(setting.text)
				}
			}
			sealed := context == jsonContextReasoningDetail && (hasSignature || hasData)
			if sealed {
				r.sealedDetails++
			}
			if sealed || context == jsonContextResponsesInputItem && itemType == "reasoning" && (hasEncryptedContent || hasSignature) {
				*replacements = (*replacements)[:baseReplacements]
				r.items = baseItems
				r.input = baseInput
				r.restored = baseRestored
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
		case jsonContextResponsesTools:
			childContext = jsonContextResponsesTool
		case jsonContextContent:
			childContext = jsonContextContentBlock
		case jsonContextReasoningDetails:
			childContext = jsonContextReasoningDetail
		case jsonContextSearchResults:
			childContext = jsonContextSearchResult
		case jsonContextReplyChoices:
			childContext = jsonContextReplyChoice
		}
		// Each message of a request, and each item of its input, is one part of the request.
		part := r.part
		if !r.reply && (context == jsonContextChatMessages || context == jsonContextResponsesInput) {
			r.part = partUnknown
			if !r.policy.uniform() {
				r.part = objectPart(source, position, context)
			}
		}
		position, err = r.walkJSONValue(source, position, allow, replacements, depth, childContext)
		r.part = part
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
	decoded := source[start+1 : end-1]
	if escaped {
		text, err := decodeJSONString(encoded)
		if err != nil {
			return errInvalidJSON
		}
		decoded = []byte(text)
	}
	// A reply gets the request's values back before its own redactions read it.
	text, restored := decoded, uint32(0)
	if !r.keepPlaceholders {
		text, restored = r.values.restore(decoded, r.argumentsJSON)
	}
	baseItems := r.items
	redacted, changed, err := r.redactBytes(text)
	if errors.Is(err, ErrNonASCII) {
		return r.recordASCIIViolation(start, end, replacements)
	}
	if refused := (*RefusedError)(nil); errors.As(err, &refused) {
		return r.recordRefusal(start, end, refused.Entity, replacements)
	}
	if err != nil {
		return err
	}
	r.measure(text, redacted)
	if r.asciiOnly {
		return nil
	}
	if !escaped && restored == 0 {
		// The text had no escape and a placeholder needs none.
		if changed {
			*replacements = append(*replacements, jsonReplacement{start: start + 1, end: end - 1, value: redacted, items: r.items - baseItems})
		}
		return nil
	}
	// Normalize escaped text once, including when no PII matched. Retaining an
	// inflated wire encoding makes every later request codec decode it again.
	// HTML escaping can expand an otherwise unchanged field sixfold merely
	// because one matched value shared a string with an escaped character.
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(string(redacted)); err != nil {
		return err
	}
	encodedRedacted := buffer.Bytes()[:buffer.Len()-1]
	if !changed && restored == 0 && bytes.Equal(encodedRedacted, encoded) {
		return nil
	}
	// redactBytes reserved what its placeholders added to text.
	if err := r.reserveGrowth(len(encodedRedacted) - len(encoded) - max(0, len(redacted)-len(text))); err != nil {
		return err
	}
	r.restored += restored
	*replacements = append(*replacements, jsonReplacement{start: start, end: end, value: encodedRedacted, items: r.items - baseItems, restored: restored})
	return nil
}

// recordRefusal keeps a refusal for the end of the walk, which reports it unless protected
// replay holds its text.
func (r *Redactor) recordRefusal(start, end int, entity Entity, replacements *[]jsonReplacement) error {
	if r.items >= maxMatchesPerRequest {
		return ErrMatchLimit
	}
	r.items++
	*replacements = append(*replacements, jsonReplacement{start: start, end: end, items: 1, refused: entity})
	return nil
}

func (r *Redactor) recordASCIIViolation(start, end int, replacements *[]jsonReplacement) error {
	if r.items >= maxMatchesPerRequest {
		return ErrMatchLimit
	}
	r.items++
	*replacements = append(*replacements, jsonReplacement{start: start, end: end, items: 1})
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
			r.restored -= replacement.restored
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

// jsonStringHasText reports whether the value at position is a string that is not empty.
func jsonStringHasText(source []byte, position int) (bool, error) {
	if source[position] != '"' {
		return false, nil
	}
	end, _, err := jsonStringEnd(source, position)
	return end > position+2, err
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
	jsonKeyToolSetting
	jsonKeyEncryptedContent
	jsonKeySignature
	jsonKeyData
	jsonKeyType
	jsonKeyReasoning
	jsonKeyReasoningDetails
	jsonKeyContent
	jsonKeyOutput
	jsonKeyFile
	jsonKeyOpaqueMedia
	jsonKeyAction
	jsonKeySources
	jsonKeyArguments
	jsonKeyCallResult
	// The keys below matter only in a response.
	jsonKeyChoices
	jsonKeyMessage
	jsonKeyItem
	jsonKeyPart
	jsonKeyResponse
	jsonKeyLogProbs
	jsonKeyOpaqueText
	jsonKeyResult
	jsonKeyProviderData
	jsonKeyContext
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
	case "content":
		return jsonKeyContent, nil
	case "output":
		return jsonKeyOutput, nil
	case "file":
		return jsonKeyFile, nil
	case "file_data", "file_url", "image_url", "input_audio":
		return jsonKeyOpaqueMedia, nil
	case "encrypted_content":
		return jsonKeyEncryptedContent, nil
	case "action":
		return jsonKeyAction, nil
	case "sources":
		return jsonKeySources, nil
	case "arguments":
		return jsonKeyArguments, nil
	case "outputs", "results", "error":
		return jsonKeyCallResult, nil
	case "choices":
		return jsonKeyChoices, nil
	case "message":
		return jsonKeyMessage, nil
	case "item":
		return jsonKeyItem, nil
	case "part":
		return jsonKeyPart, nil
	case "response":
		return jsonKeyResponse, nil
	case "logprobs":
		return jsonKeyLogProbs, nil
	case "b64_json", "partial_image_b64", "obfuscation":
		return jsonKeyOpaqueText, nil
	case "result":
		return jsonKeyResult, nil
	case "annotations", "annotation", "extra_content":
		return jsonKeyProviderData, nil
	case "context":
		return jsonKeyContext, nil
	case "type":
		return jsonKeyType, nil
	case "signature":
		return jsonKeySignature, nil
	case "data":
		return jsonKeyData, nil
	case "reasoning", "reasoning_content":
		return jsonKeyReasoning, nil
	case "reasoning_details":
		return jsonKeyReasoningDetails, nil
	case "server_url", "connector_id", "tunnel_id", "authorization", "headers",
		"allowed_tools", "allowed_callers", "require_approval", "container", "environment":
		return jsonKeyToolSetting, nil
	case "id", "item_id", "call_id", "tool_call_id", "file_id", "container_id", "conversation_id",
		"request_id", "session_id", "previous_response_id", "prompt_cache_key", "prompt_cache_isolation_key",
		"model", "name", "namespace", "role", "server_label", "approval_request_id":
		return jsonKeySkipScalar, nil
	default:
		return jsonKeyOther, nil
	}
}

// requestFieldPart is the part of a request that one of its top-level text fields belongs to.
// Messages and input items each say their own.
func requestFieldPart(field string, value []byte) Part {
	switch field {
	case "messages":
		return partUnknown
	case "input":
		// An input that is one string is the user's message.
		if position := skipJSONSpace(value, 0); position < len(value) && value[position] == '"' {
			return PartUser
		}
		return partUnknown
	case "instructions", "context_management":
		return PartSystem
	case "prediction":
		return PartUser
	}
	return PartTools
}

// objectPart is the part of a request that a message, or an item of a Responses input, belongs
// to. An object that does not say, or says twice, is read as every part, so no redaction of
// the request passes it by.
func objectPart(source []byte, position int, context jsonValueContext) Part {
	role, itemType, ok := objectRoleAndType(source, position)
	if !ok {
		return partUnknown
	}
	if context == jsonContextResponsesInput && itemType != "" && itemType != "message" {
		// The model makes a call and the client returns its output.
		switch {
		case role != "":
			return partUnknown
		case itemType == "mcp_approval_response", itemType == "mcp_list_tools", strings.HasSuffix(itemType, "_output"):
			return PartToolResults
		case itemType == "reasoning", itemType == "compaction", itemType == "mcp_approval_request", strings.HasSuffix(itemType, "_call"):
			return PartAssistant
		}
		return partUnknown
	}
	switch role {
	case "system", "developer":
		return PartSystem
	case "user":
		return PartUser
	case "assistant":
		return PartAssistant
	case "tool", "function":
		return PartToolResults
	}
	return partUnknown
}

// objectRoleAndType reads the role and the type of the object at position without walking its
// values. It fails for a value that is no object, for malformed JSON, and for an object that
// holds either key twice or with a value that is no string, since readers disagree on which of
// two keys counts.
func objectRoleAndType(source []byte, position int) (role, itemType string, ok bool) {
	if position >= len(source) || source[position] != '{' {
		return "", "", false
	}
	position = skipJSONSpace(source, position+1)
	if position < len(source) && source[position] == '}' {
		return "", "", true
	}
	seenRole, seenType := false, false
	for {
		keyEnd, keyEscaped, err := jsonStringEnd(source, position)
		if err != nil {
			return "", "", false
		}
		key := string(source[position+1 : keyEnd-1])
		if keyEscaped {
			if key, err = decodeJSONString(source[position:keyEnd]); err != nil {
				return "", "", false
			}
		}
		position = skipJSONSpace(source, keyEnd)
		if position >= len(source) || source[position] != ':' {
			return "", "", false
		}
		position = skipJSONSpace(source, position+1)
		if key == "role" || key == "type" {
			valueEnd, _, err := jsonStringEnd(source, position)
			if err != nil {
				return "", "", false
			}
			value, err := decodeJSONString(source[position:valueEnd])
			if err != nil {
				return "", "", false
			}
			if key == "role" {
				if seenRole {
					return "", "", false
				}
				role, seenRole = value, true
			} else {
				if seenType {
					return "", "", false
				}
				itemType, seenType = value, true
			}
			position = valueEnd
		} else if position, ok = jsonValueEnd(source, position); !ok {
			return "", "", false
		}
		position = skipJSONSpace(source, position)
		if position >= len(source) {
			return "", "", false
		}
		switch source[position] {
		case ',':
			position = skipJSONSpace(source, position+1)
		case '}':
			return role, itemType, true
		default:
			return "", "", false
		}
	}
}

// jsonValueEnd returns the position after the value at position. It checks only what it needs
// to find the end: the walk that follows validates the value.
func jsonValueEnd(source []byte, position int) (int, bool) {
	depth := 0
	for position < len(source) {
		switch source[position] {
		case '"':
			end, _, err := jsonStringEnd(source, position)
			if err != nil {
				return position, false
			}
			position = end
			if depth == 0 {
				return position, true
			}
			continue
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				return position, true
			}
			depth--
			if depth == 0 {
				return position + 1, true
			}
		case ',':
			if depth == 0 {
				return position, true
			}
		}
		position++
	}
	return position, false
}
