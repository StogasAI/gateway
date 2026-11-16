package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// hoistAdditionalTools moves the tools of each additional_tools input item into the top-level
// tools, the form that every check, policy, hold and provider reads. Codex declares its tools in
// such an item instead of in tools for the models whose metadata selects OpenAI's Responses Lite,
// such as GPT-6.1 Sol, and adds another item when its tools change during a conversation. Tools
// merge as Bifrost core merges them (core/responsestools.go): a later declaration of a function or
// custom tool replaces the earlier one in its place, a namespace declared again gains the new
// members, and the members of the functions namespace are top-level tools. A namespace whose
// members all replaced earlier tools is left out, since it declares nothing of its own.
func hoistAdditionalTools(rawData map[string]json.RawMessage) error {
	raw := rawData["input"]
	// JSON can spell the type only plainly or with \u escapes, so input without either holds no
	// such item.
	if !bytes.Contains(raw, []byte("additional_tools")) && !bytes.Contains(raw, []byte(`\u`)) {
		return nil
	}
	items, err := rawjson.Array(raw)
	if err != nil {
		return nil
	}
	kept := make([]json.RawMessage, 0, len(items))
	var declared []json.RawMessage
	for index, itemRaw := range items {
		item, err := rawjson.Object(itemRaw)
		if err != nil || rawStringValue(item["type"]) != "additional_tools" {
			kept = append(kept, itemRaw)
			continue
		}
		tools, err := additionalToolsOf(item, fmt.Sprintf("input[%d]", index))
		if err != nil {
			return err
		}
		declared = append(declared, tools...)
	}
	if len(kept) == len(items) {
		return nil
	}
	var top []json.RawMessage
	if rawTools, ok := rawData["tools"]; ok {
		if top, err = rawjson.Array(rawTools); err != nil {
			return invalidInputItem("tools", "tools must be an array")
		}
	}
	merged, err := mergeToolDeclarations(top, declared)
	if err != nil {
		return err
	}
	rawData["input"] = joinRawArray(kept)
	if len(merged) > 0 {
		rawData["tools"] = joinRawArray(merged)
	}
	return nil
}

// additionalToolsOf checks an additional_tools item and returns its tools. Its role, which
// OpenAI requires to be developer, selects nothing once the tools are top-level ones.
func additionalToolsOf(item map[string]json.RawMessage, path string) ([]json.RawMessage, error) {
	for key, value := range item {
		if rawJSONNull(value) {
			continue
		}
		switch key {
		case "type", "tools":
		case "id", "role":
			if !bytes.HasPrefix(bytes.TrimSpace(value), []byte(`"`)) {
				return nil, invalidInputItem(path+"."+key, path+"."+key+" must be a string")
			}
		default:
			return nil, invalidInputItem(path+"."+key, path+"."+key+" is not supported")
		}
	}
	tools, err := rawjson.Array(item["tools"])
	if err != nil {
		return nil, invalidInputItem(path+".tools", path+".tools must be an array")
	}
	for index, tool := range tools {
		if _, err := rawjson.Object(tool); err != nil {
			field := fmt.Sprintf("%s.tools[%d]", path, index)
			return nil, invalidInputItem(field, field+" must be an object")
		}
	}
	return tools, nil
}

func invalidInputItem(param, message string) error {
	return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: message, Param: param}
}

// toolSlot is where a declared tool sits in the merged list: its index there, and its index among
// that namespace's members, or -1 for a top-level tool.
type toolSlot struct{ index, member int }

type mergedNamespace struct {
	object  map[string]json.RawMessage
	members []json.RawMessage
	// declaredOnly marks a namespace that only additional_tools items declare.
	declaredOnly bool
}

// mergeToolDeclarations combines the top-level tools with the declared ones, in order. A tool
// that is not an object, or a namespace without a member list, stays as it is for the tool checks
// to name.
func mergeToolDeclarations(top, declared []json.RawMessage) ([]json.RawMessage, error) {
	merged := make([]json.RawMessage, 0, len(top))
	namespaces := make(map[string]int)
	entries := make(map[int]*mergedNamespace)
	slots := make(map[[2]string]toolSlot)
	place := func(key [2]string, tool json.RawMessage, add func() toolSlot) {
		slot, seen := slots[key]
		switch {
		case !seen:
			slots[key] = add()
		case slot.member < 0:
			merged[slot.index] = tool
		default:
			entries[slot.index].members[slot.member] = tool
		}
	}
	add := func(raw json.RawMessage, declaredOnly bool) {
		tool, err := rawjson.Object(raw)
		if err != nil {
			merged = append(merged, raw)
			return
		}
		kind, name := rawStringValue(tool["type"]), rawStringValue(tool["name"])
		switch {
		case kind == "namespace" && name != "":
			members, err := rawjson.Array(tool["tools"])
			if err != nil {
				merged = append(merged, raw)
				return
			}
			index, seen := namespaces[name]
			if !seen {
				index = len(merged)
				namespaces[name] = index
				entries[index] = &mergedNamespace{object: tool, declaredOnly: declaredOnly}
				merged = append(merged, nil)
			} else if !declaredOnly {
				entries[index].declaredOnly = false
			}
			namespace := name
			if name == providerutils.DefaultToolNamespace {
				namespace = ""
			}
			entry := entries[index]
			for _, member := range members {
				appendMember := func() toolSlot {
					entry.members = append(entry.members, member)
					return toolSlot{index: index, member: len(entry.members) - 1}
				}
				object, err := rawjson.Object(member)
				memberName := ""
				if err == nil {
					memberName = rawStringValue(object["name"])
				}
				if memberName == "" {
					appendMember()
					continue
				}
				place([2]string{namespace, memberName}, member, appendMember)
			}
		case (kind == "function" || kind == "custom") && name != "":
			place([2]string{"", name}, raw, func() toolSlot {
				merged = append(merged, raw)
				return toolSlot{index: len(merged) - 1, member: -1}
			})
		default:
			merged = append(merged, raw)
		}
	}
	for _, tool := range top {
		add(tool, false)
	}
	for _, tool := range declared {
		add(tool, true)
	}
	result := make([]json.RawMessage, 0, len(merged))
	for index, tool := range merged {
		entry := entries[index]
		if entry == nil {
			result = append(result, tool)
			continue
		}
		if len(entry.members) == 0 && entry.declaredOnly {
			continue
		}
		entry.object["tools"] = joinRawArray(entry.members)
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(entry.object); err != nil {
			return nil, ErrInvalidJSON
		}
		result = append(result, bytes.TrimSuffix(encoded.Bytes(), []byte("\n")))
	}
	return result, nil
}

// joinRawArray encodes values as a JSON array without decoding them again.
func joinRawArray(values []json.RawMessage) json.RawMessage {
	size := 2
	for _, value := range values {
		size += len(value) + 1
	}
	joined := make([]byte, 0, size)
	joined = append(joined, '[')
	for index, value := range values {
		if index > 0 {
			joined = append(joined, ',')
		}
		joined = append(joined, value...)
	}
	return append(joined, ']')
}
