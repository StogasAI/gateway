package exporter

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// The captured bodies become the conventions' messages, each part named by its
// type: JSON text on a span under the 1.41 conventions, and a structured value
// decoded from that text under 0.1. The writers below copy the bodies' own
// JSON values into the text and never decode them, so a body of any shape
// takes little memory beside the trace. A part or item that the conventions
// have no type for stays as the caller or the provider wrote it, which their
// schemas allow for any object with a type.

type fields = map[string]json.RawMessage

func members(raw []byte) fields {
	object, _ := rawjson.Object(raw)
	return object
}

func elements(raw []byte) []json.RawMessage {
	list, _ := rawjson.Array(raw)
	return list
}

// inner is the text of a JSON string between its quotes, still escaped, and
// nil for any other value.
func inner(raw []byte) []byte {
	if len(raw) < 2 || raw[0] != '"' {
		return nil
	}
	return raw[1 : len(raw)-1]
}

// word reads a short string such as a type or a role.
func word(raw []byte) string {
	text := inner(raw)
	if bytes.IndexByte(text, '\\') < 0 {
		return string(text)
	}
	var decoded string
	_ = json.Unmarshal(raw, &decoded)
	return decoded
}

func (p *protobuf) put(text string) { p.data = append(p.data, text...) }

// value writes a JSON value, null for an absent one.
func (p *protobuf) value(raw []byte) {
	if len(raw) == 0 {
		p.put("null")
		return
	}
	p.data = append(p.data, raw...)
}

// next starts an element of the list being written.
func (p *protobuf) next() {
	if p.data[len(p.data)-1] != '[' {
		p.put(",")
	}
}

// jsonList is an attribute whose value is a JSON list, as text or, when the
// list is written apart in the text buffer, as a structured value.
type jsonList struct {
	key                     string
	start, pair, item, text int
}

func (p *protobuf) beginList(key string) jsonList {
	list := jsonList{key: key, start: len(p.data)}
	if p.text != nil {
		p.data, p.text = p.text[:0], p.data
		p.put("[")
		return list
	}
	list.pair = p.open(9)
	p.string(1, key)
	list.item = p.open(2)
	list.text = p.open(1)
	p.put("[")
	return list
}

// endList closes the attribute, and leaves none when the list is empty.
func (p *protobuf) endList(list jsonList) {
	empty := p.data[len(p.data)-1] == '['
	if list.pair == 0 {
		text := append(p.data, ']')
		p.data, p.text = p.text, text
		if !empty {
			p.structuredAttribute(9, list.key, text)
		}
		return
	}
	if empty {
		p.data = p.data[:list.start]
		return
	}
	p.put("]")
	p.close(list.text)
	p.close(list.item)
	p.close(list.pair)
}

// contentAttributes writes the messages. Under the 1.41 conventions, each
// output message names its finish reason, which 0.1 left to the span's.
func (p *protobuf) contentAttributes(responses bool, reason string, bodies *traceBodies) {
	var finish []byte
	if p.conventions == conventions141 {
		finish, _ = json.Marshal(reason)
	}
	if request := members(bodies.request); request != nil {
		if instructions := inner(request["instructions"]); len(instructions) > 0 {
			list := p.beginList("gen_ai.system_instructions")
			p.textPart("text", instructions)
			p.endList(list)
		}
		list := p.beginList("gen_ai.input.messages")
		switch input := request["input"]; {
		case !responses:
			for _, message := range elements(request["messages"]) {
				if message := members(message); message != nil {
					p.chatMessage(message, nil)
				}
			}
		case len(inner(input)) > 0:
			p.put(`{"role":"user","parts":[`)
			p.textPart("text", inner(input))
			p.put("]}")
		default:
			p.responsesMessages(elements(input), nil)
		}
		p.endList(list)
		list = p.beginList("gen_ai.tool.definitions")
		for _, tool := range elements(request["tools"]) {
			p.toolDefinition(members(tool))
		}
		p.endList(list)
	}
	list := p.beginList("gen_ai.output.messages")
	switch {
	case bodies.events != nil && responses:
		p.responsesMessages(responsesStreamItems(bodies.events), finish)
	case bodies.events != nil:
		p.chatStream(bodies.events, finish)
	case responses:
		p.responsesMessages(elements(members(bodies.response)["output"]), finish)
	default:
		for _, choice := range elements(members(bodies.response)["choices"]) {
			choice := members(choice)
			if message := members(choice["message"]); message != nil {
				p.chatMessage(message, choiceFinish(choice["finish_reason"], finish))
			}
		}
	}
	p.endList(list)
}

// choiceFinish is a choice's own finish reason as JSON, or else the record's,
// and nil when messages name none.
func choiceFinish(raw, finish []byte) []byte {
	if reason := word(raw); reason != "" && finish != nil {
		finish, _ = json.Marshal(finishReason(reason))
	}
	return finish
}

// beginMessage starts a message and its parts. An output message has a finish
// reason.
func (p *protobuf) beginMessage(role, name, finish []byte) {
	p.next()
	p.put(`{"role":`)
	p.value(role)
	if len(inner(name)) > 0 {
		p.put(`,"name":`)
		p.value(name)
	}
	if finish != nil {
		p.put(`,"finish_reason":`)
		p.value(finish)
	}
	p.put(`,"parts":[`)
}

// textPart writes a part that holds text under "content": text, reasoning or
// a refusal.
func (p *protobuf) textPart(kind string, content []byte) {
	p.next()
	p.put(`{"type":"` + kind + `","content":"`)
	p.data = append(p.data, content...)
	p.put(`"}`)
}

// toolCall writes a call of a client tool. A function's arguments arrive as
// JSON text, and a trace tool reads them as the value itself.
func (p *protobuf) toolCall(id, name, arguments []byte, parse bool) {
	p.next()
	p.put(`{"type":"tool_call","id":`)
	p.value(id)
	p.put(`,"name":`)
	if inner(name) == nil {
		name = []byte(`""`)
	}
	p.value(name)
	p.put(`,"arguments":`)
	var decoded string
	if parse && json.Unmarshal(arguments, &decoded) == nil && json.Valid([]byte(decoded)) {
		p.put(decoded)
	} else {
		p.value(arguments)
	}
	p.put("}")
}

func (p *protobuf) toolResponse(id, response []byte) {
	p.next()
	p.put(`{"type":"tool_call_response","id":`)
	p.value(id)
	p.put(`,"response":`)
	p.value(response)
	p.put("}")
}

// attachment names an attachment by where its data is: a URL, inline data,
// which the capture replaced by its media type, size and SHA-256, or a
// provider file ID. The conventions require a modality: the part's own, such
// as document for a file, unless inline data names another. It reports false
// for a part that names none.
func (p *protobuf) attachment(data, fileID []byte, modality string) bool {
	description := members(data)
	switch {
	case inner(data) != nil:
		p.next()
		p.put(`{"type":"uri","uri":`)
		p.value(data)
	case description != nil:
		p.next()
		p.put(`{"type":"blob","size":`)
		p.value(description["size"])
		p.put(`,"sha256":`)
		p.value(description["sha256"])
		if mediaType := description["media_type"]; len(inner(mediaType)) > 0 {
			p.put(`,"mime_type":`)
			p.value(mediaType)
			if kind, _, _ := strings.Cut(word(mediaType), "/"); kind == "image" || kind == "audio" || kind == "video" {
				modality = kind
			}
		}
	case len(inner(fileID)) > 0:
		p.next()
		p.put(`{"type":"file","file_id":`)
		p.value(fileID)
	default:
		return false
	}
	p.put(`,"modality":"` + modality + `"}`)
	return true
}

// contentParts writes the content of a message of either interface: text, or
// a list of typed parts.
func (p *protobuf) contentParts(content []byte) {
	if text := inner(content); len(text) > 0 {
		p.textPart("text", text)
		return
	}
	for _, raw := range elements(content) {
		part := members(raw)
		kind := word(part["type"])
		written := false
		switch kind {
		case "text", "input_text", "output_text":
			p.textPart("text", inner(part["text"]))
			written = true
		case "image_url":
			written = p.attachment(members(part["image_url"])["url"], nil, "image")
		case "input_audio":
			written = p.attachment(members(part["input_audio"])["data"], nil, "audio")
		case "file":
			file := members(part["file"])
			written = p.attachment(file["file_data"], file["file_id"], "document")
		case "input_image":
			written = p.attachment(part["image_url"], part["file_id"], "image")
		case "input_file":
			data := part["file_data"]
			if data == nil {
				data = part["file_url"]
			}
			written = p.attachment(data, part["file_id"], "document")
		case "refusal":
			p.textPart("refusal", inner(part["refusal"]))
			written = true
		}
		if !written && kind != "" {
			p.next()
			p.value(raw)
		}
	}
}

func (p *protobuf) chatMessage(message fields, finish []byte) {
	role := message["role"]
	if inner(role) == nil {
		role = []byte(`"assistant"`)
	}
	p.beginMessage(role, message["name"], finish)
	if word(role) == "tool" {
		p.toolResponse(message["tool_call_id"], message["content"])
		p.put("]}")
		return
	}
	// Core writes a reply's reasoning under both names.
	reasoning := inner(message["reasoning"])
	if len(reasoning) == 0 {
		reasoning = inner(message["reasoning_content"])
	}
	if len(reasoning) > 0 {
		p.textPart("reasoning", reasoning)
	}
	p.contentParts(message["content"])
	if refusal := inner(message["refusal"]); len(refusal) > 0 {
		p.textPart("refusal", refusal)
	}
	for _, call := range elements(message["tool_calls"]) {
		call := members(call)
		function := members(call["function"])
		p.toolCall(call["id"], function["name"], function["arguments"], true)
	}
	p.put("]}")
}

// chatStream joins the deltas of each choice into the message that a reply
// without a stream would hold. Text deltas are JSON strings, whose escaped
// text joins into one string as it is.
func (p *protobuf) chatStream(events [][]byte, finish []byte) {
	type call struct{ id, name, arguments []byte }
	type choice struct {
		role, finish                []byte
		content, reasoning, refusal []byte
		calls                       map[string]*call
	}
	choices := map[string]*choice{}
	for _, event := range events {
		for _, raw := range elements(members(event)["choices"]) {
			source := members(raw)
			index := string(source["index"])
			current := choices[index]
			if current == nil {
				current = &choice{role: []byte(`"assistant"`), calls: map[string]*call{}}
				choices[index] = current
			}
			if reason := source["finish_reason"]; len(inner(reason)) > 0 {
				current.finish = reason
			}
			delta := members(source["delta"])
			if role := delta["role"]; len(inner(role)) > 0 {
				current.role = role
			}
			current.content = append(current.content, inner(delta["content"])...)
			if reasoning := inner(delta["reasoning"]); len(reasoning) > 0 {
				current.reasoning = append(current.reasoning, reasoning...)
			} else {
				current.reasoning = append(current.reasoning, inner(delta["reasoning_content"])...)
			}
			current.refusal = append(current.refusal, inner(delta["refusal"])...)
			for _, raw := range elements(delta["tool_calls"]) {
				source := members(raw)
				function := members(source["function"])
				index := string(source["index"])
				started := current.calls[index]
				if started == nil {
					started = &call{arguments: []byte{'"'}}
					current.calls[index] = started
				}
				if id := source["id"]; len(inner(id)) > 0 {
					started.id = id
				}
				if name := function["name"]; len(inner(name)) > 0 {
					started.name = name
				}
				started.arguments = append(started.arguments, inner(function["arguments"])...)
			}
		}
	}
	for _, index := range sortedIndexes(choices) {
		current := choices[index]
		p.beginMessage(current.role, nil, choiceFinish(current.finish, finish))
		if len(current.reasoning) > 0 {
			p.textPart("reasoning", current.reasoning)
		}
		if len(current.content) > 0 {
			p.textPart("text", current.content)
		}
		if len(current.refusal) > 0 {
			p.textPart("refusal", current.refusal)
		}
		for _, index := range sortedIndexes(current.calls) {
			started := current.calls[index]
			p.toolCall(started.id, started.name, append(started.arguments, '"'), true)
		}
		p.put("]}")
	}
}

// sortedIndexes orders the keys, which are the digits of each index.
func sortedIndexes[V any](values map[string]V) []string {
	indexes := make([]string, 0, len(values))
	for index := range values {
		indexes = append(indexes, index)
	}
	slices.SortFunc(indexes, func(a, b string) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return strings.Compare(a, b)
	})
	return indexes
}

// responsesMessages writes Responses items as messages. The items of one model
// turn, such as its reasoning, its text and its tool calls, are separate items
// in a row, and they become the parts of one assistant message. A call that
// the client runs, such as a function or a shell command, has a call ID, which
// its output item answers in a tool message. A call without one, such as a web
// search, ran at the provider.
func (p *protobuf) responsesMessages(items []json.RawMessage, finish []byte) {
	assistant := false
	for _, raw := range items {
		item := members(raw)
		kind := word(item["type"])
		client := len(inner(item["call_id"])) > 0 && word(item["execution"]) != "server"
		// An approval answers the model as a client tool's output does.
		answer := client && strings.HasSuffix(kind, "_output") || kind == "mcp_approval_response"
		role := []byte(`"assistant"`)
		switch {
		case kind == "message" || kind == "" && inner(item["role"]) != nil:
			if kind = "message"; inner(item["role"]) != nil {
				role = item["role"]
			}
		case kind == "":
			continue
		case answer:
			role = []byte(`"tool"`)
		}
		if word(role) != "assistant" || !assistant {
			if assistant {
				p.put("]}")
			}
			p.beginMessage(role, nil, finish)
			assistant = word(role) == "assistant"
		}
		switch {
		case kind == "message":
			p.contentParts(item["content"])
		case kind == "reasoning":
			p.next()
			p.put(`{"type":"reasoning","content":"`)
			empty := len(p.data)
			for _, field := range [...]string{"summary", "content"} {
				for _, part := range elements(item[field]) {
					if text := inner(members(part)["text"]); len(text) > 0 {
						if len(p.data) > empty {
							p.put(`\n\n`)
						}
						p.data = append(p.data, text...)
					}
				}
			}
			p.put(`"}`)
		case client && strings.HasSuffix(kind, "_call"):
			// A function's arguments are JSON text. OpenAI's other client tools
			// take text or an object under their own key, and name the tool by
			// the item's type.
			name := item["name"]
			if len(inner(name)) == 0 {
				name = quote(strings.TrimSuffix(kind, "_call"))
			}
			arguments, parse := item["arguments"], true
			for _, key := range [...]string{"input", "action", "operation"} {
				if arguments == nil {
					arguments, parse = item[key], false
				}
			}
			p.toolCall(item["call_id"], name, arguments, parse)
		case client && strings.HasSuffix(kind, "_output"):
			response := item["output"]
			if response == nil {
				response = p.without(item, "type", "id", "call_id", "execution")
			}
			p.toolResponse(item["call_id"], response)
		case strings.HasSuffix(kind, "_call"):
			p.serverToolPart("server_tool_call", strings.TrimSuffix(kind, "_call"), item)
		case strings.HasSuffix(kind, "_output"):
			p.serverToolPart("server_tool_call_response", strings.TrimSuffix(kind, "_output"), item)
		default:
			p.next()
			p.value(raw)
		}
		if !assistant {
			p.put("]}")
		}
	}
	if assistant {
		p.put("]}")
	}
}

// serverToolPart writes an item of a tool that the provider ran, such as a
// web_search_call, as the conventions' server tool call or response: the
// item's own fields under the tool's type, such as web_search. A call's ID
// names it, and the output of OpenAI's own tool search has no ID of its call.
func (p *protobuf) serverToolPart(part, tool string, item fields) {
	p.next()
	p.put(`{"type":"` + part + `"`)
	if id := item["id"]; part == "server_tool_call" && len(inner(id)) > 0 {
		p.put(`,"id":`)
		p.value(id)
	}
	if part == "server_tool_call" {
		name := item["name"]
		if len(inner(name)) == 0 {
			name = quote(tool)
		}
		p.put(`,"name":`)
		p.value(name)
	}
	details := fields{}
	for key, value := range item {
		if key != "id" {
			details[key] = value
		}
	}
	details["type"] = quote(tool)
	p.put(`,"` + part + `":`)
	p.object(details)
	p.put("}")
}

func quote(text string) []byte {
	quoted, _ := json.Marshal(text)
	return quoted
}

// without is an object of the item's fields other than the keys.
func (p *protobuf) without(item fields, keys ...string) []byte {
	rest := fields{}
	for key, value := range item {
		if !slices.Contains(keys, key) {
			rest[key] = value
		}
	}
	saved := p.data
	p.data = nil
	p.object(rest)
	object := p.data
	p.data = saved
	return object
}

// responsesStreamItems reads the output of a Responses stream from the event
// that ends it, which holds the whole response, or else the items that had
// finished when the stream stopped.
func responsesStreamItems(events [][]byte) []json.RawMessage {
	var finished []json.RawMessage
	for i := len(events) - 1; i >= 0; i-- {
		event := members(events[i])
		switch word(event["type"]) {
		case "response.completed", "response.incomplete", "response.failed":
			if output, err := rawjson.Array(members(event["response"])["output"]); err == nil {
				return output
			}
		case "response.output_item.done":
			if item := event["item"]; item != nil {
				finished = append(finished, item)
			}
		}
	}
	slices.Reverse(finished)
	return finished
}

// toolDefinition names a tool as the conventions do: a function tool by its
// name, description and parameters, and any other by its type.
func (p *protobuf) toolDefinition(tool fields) {
	kind := tool["type"]
	if len(inner(kind)) == 0 {
		return
	}
	definition := fields{}
	for key, value := range tool {
		definition[key] = value
	}
	// Chat Completions holds a function's fields one level down.
	if function := members(tool["function"]); function != nil {
		delete(definition, "function")
		for key, value := range function {
			definition[key] = value
		}
		definition["type"] = kind
	}
	if len(inner(definition["name"])) == 0 {
		definition["name"] = kind
	}
	p.next()
	p.object(definition)
}

// object writes the fields as a JSON object in the order of their keys, so a
// trace repeats its bytes.
func (p *protobuf) object(values fields) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	p.put("{")
	for i, key := range keys {
		if i > 0 {
			p.put(",")
		}
		p.data = append(p.data, quote(key)...)
		p.put(":")
		p.value(values[key])
	}
	p.put("}")
}
