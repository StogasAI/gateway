package schemas

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/tidwall/gjson"
)

// schemaKeywords are the keywords of a JSON Schema object that the fields of the struct holding
// it do not name, kept as written. ToolFunctionParameters and ResponsesTextConfigFormatJSONSchema
// carry them, so that a schema reaches the provider with every keyword the client wrote, as a
// Chat Completions response_format, which core keeps raw, already does. A provider conversion
// that builds its own schema from the fields leaves them out.
type schemaKeywords []schemaKeyword

type schemaKeyword struct {
	name string
	// key is the name as a JSON string.
	key   string
	value json.RawMessage
}

// structFieldNames returns the lower-case JSON names of a struct type's fields, as the decoder
// matches them without regard to case.
func structFieldNames(t reflect.Type) map[string]struct{} {
	names := make(map[string]struct{}, t.NumField())
	for field := range t.Fields() {
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		switch name {
		case "-":
			continue
		case "":
			name = field.Name
		}
		names[strings.ToLower(name)] = struct{}{}
	}
	return names
}

// readSchemaKeywords returns the members of the JSON object data whose names fields does not hold.
// Of members with the same name, it keeps the value of the last, as the decoder does.
func readSchemaKeywords(data []byte, fields map[string]struct{}) schemaKeywords {
	object := gjson.ParseBytes(data)
	if !object.IsObject() {
		return nil
	}
	var keywords schemaKeywords
	var at map[string]int
	object.ForEach(func(key, value gjson.Result) bool {
		name := key.String()
		if _, named := fields[strings.ToLower(name)]; named {
			return true
		}
		if i, seen := at[name]; seen {
			keywords[i].value = json.RawMessage(value.Raw)
			return true
		}
		if at == nil {
			at = make(map[string]int)
		}
		at[name] = len(keywords)
		keywords = append(keywords, schemaKeyword{name: name, key: key.Raw, value: json.RawMessage(value.Raw)})
		return true
	})
	return keywords
}

// mapSchemaKeywords returns the entries of a decoded schema whose names fields does not hold, in
// the order of keys, which holds every name of schema.
func mapSchemaKeywords(schema map[string]interface{}, keys []string, fields map[string]struct{}) schemaKeywords {
	var keywords schemaKeywords
	for _, name := range keys {
		value, exists := schema[name]
		if _, named := fields[strings.ToLower(name)]; named || !exists {
			continue
		}
		key, err := Marshal(name)
		if err != nil {
			continue
		}
		raw, err := MarshalSorted(value)
		if err != nil {
			continue
		}
		keywords = append(keywords, schemaKeyword{name: name, key: string(key), value: raw})
	}
	return keywords
}

// appendTo adds the keywords to the end of the encoded JSON object raw.
func (k schemaKeywords) appendTo(raw []byte) []byte {
	start, end := bytes.IndexByte(raw, '{'), bytes.LastIndexByte(raw, '}')
	if len(k) == 0 || start < 0 || end < start {
		return raw
	}
	out := make([]byte, 0, len(raw)+64*len(k))
	out = append(out, raw[:end]...)
	empty := len(bytes.TrimSpace(raw[start+1:end])) == 0
	for _, keyword := range k {
		if !empty {
			out = append(out, ',')
		}
		empty = false
		out = append(out, keyword.key...)
		out = append(out, ':')
		out = append(out, keyword.value...)
	}
	return append(out, raw[end:]...)
}

// addTo puts the keywords into a decoded schema.
func (k schemaKeywords) addTo(schema map[string]interface{}) {
	for _, keyword := range k {
		schema[keyword.name] = keyword.value
	}
}

var (
	toolFunctionParameterFields = structFieldNames(reflect.TypeFor[ToolFunctionParameters]())
	responsesJSONSchemaFields   = structFieldNames(reflect.TypeFor[ResponsesTextConfigFormatJSONSchema]())
)
