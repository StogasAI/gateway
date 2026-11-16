package catalog

import (
	"bytes"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"sync"

	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
	"golang.org/x/net/idna"
)

// requestTools are the tools that a request lists, as routing and policies read them from the
// body as sent. A tool counts as one the model may call unless tool_choice rules out its type, so
// a choice that forces one function or one MCP server still counts every tool of that type.
type requestTools struct {
	hosted hostedToolUse
	facts  *requestFacts
}

// hostedToolUse is the hosted tools that a request lists, and those of them that its tool_choice
// lets the model call. A deployment must take every listed tool's declaration, and only the
// callable ones can send request content anywhere.
type hostedToolUse struct {
	listed, enabled []HostedTool
}

// requestFacts are the request fields that policies read about tools and messages. Every
// candidate of a request shares them.
type requestFacts struct {
	// clientTools are the names of the tools that the model may call and the client runs: function
	// and custom tools, and shell and apply_patch under those names.
	clientTools []string
	// mcpServers name the remote MCP servers that the model may call: a URL's host, or a connector
	// or tunnel ID, all lowercase. mcpTools lists server/name for each tool that the request allows
	// on one of them, or server/* when it doesn't name the server's tools.
	mcpServers, mcpTools []string
	// systemMessages reports whether the request sends a system or developer message, or
	// instructions. Only policies that read it scan the messages.
	systemMessages func() bool
}

// readRequestTools reads a request's tools in one pass. Only Responses requests list hosted tools.
func readRequestTools(route Route, raw map[string]json.RawMessage) requestTools {
	facts := &requestFacts{clientTools: []string{}, mcpServers: []string{}, mcpTools: []string{}}
	facts.systemMessages = sync.OnceValue(func() bool {
		sends, _ := requestSendsSystemMessages(route, raw)
		return sends
	})
	result := requestTools{facts: facts}
	var tools []map[string]json.RawMessage
	if list, err := rawjson.Array(raw["tools"]); err == nil {
		for _, rawTool := range list {
			if tool, err := rawjson.Object(rawTool); err == nil {
				tools = append(tools, tool)
			}
		}
	}
	switch route {
	case RouteResponses:
		// A tool in a namespace counts by its own name, and so does a tool that a tool search in the
		// input loaded.
		list := ResponsesToolList(append(tools, ResponsesLoadedTools(raw["input"])...))
		declared := make([]string, 0, len(list))
		for _, entry := range list {
			if kind := rawStringValue(entry.Tool["type"]); kind != "" {
				declared = append(declared, kind)
			}
		}
		callable := EffectiveResponsesToolTypes(raw, declared)
		result.hosted = hostedToolUse{listed: hostedToolsOf(declared), enabled: hostedToolsOf(callable)}
		types := make(map[schemas.ResponsesToolType]bool, len(callable))
		for _, kind := range callable {
			types[CanonicalResponsesToolType(kind)] = true
		}
		for _, entry := range list {
			switch kind := CanonicalResponsesToolType(rawStringValue(entry.Tool["type"])); {
			case !types[kind]:
			case kind == schemas.ResponsesToolTypeFunction || kind == schemas.ResponsesToolTypeCustom:
				facts.clientTools = append(facts.clientTools, rawStringValue(entry.Tool["name"]))
			// OpenAI's shell and apply_patch tools have no name of their own; the model calls them by
			// their type, which no function or custom tool beside them may have.
			case kind == schemas.ResponsesToolTypeShell || kind == schemas.ResponsesToolTypeApplyPatch:
				facts.clientTools = append(facts.clientTools, string(kind))
			case kind == schemas.ResponsesToolTypeMCP:
				facts.addMCPServer(entry.Tool)
			}
		}
	case RouteChat:
		if rawStringValue(raw["tool_choice"]) != "none" {
			for _, tool := range tools {
				if function, ok := rawObjectValue(tool["function"]); ok && rawStringValue(tool["type"]) == "function" {
					facts.clientTools = append(facts.clientTools, rawStringValue(function["name"]))
				}
			}
		}
		if functions, err := rawjson.Array(raw["functions"]); err == nil && rawStringValue(raw["function_call"]) != "none" {
			for _, rawFunction := range functions {
				if function, ok := rawObjectValue(rawFunction); ok {
					facts.clientTools = append(facts.clientTools, rawStringValue(function["name"]))
				}
			}
		}
	}
	facts.clientTools = sortedNames(facts.clientTools)
	facts.mcpServers = sortedNames(facts.mcpServers)
	facts.mcpTools = sortedNames(facts.mcpTools)
	return result
}

// NamespacedTool is a tool that a Responses request declares, at the top level or in a namespace.
type NamespacedTool struct {
	// Namespace names the namespace that holds the tool. It is empty for a top-level tool and for a
	// tool in the namespace functions, in which OpenAI's models call top-level tools.
	Namespace string
	Tool      map[string]json.RawMessage
}

// ResponsesToolList lists a Responses request's tools with the tools of each namespace in its
// place, which are the tools that the model calls.
func ResponsesToolList(tools []map[string]json.RawMessage) []NamespacedTool {
	list := make([]NamespacedTool, 0, len(tools))
	for _, tool := range tools {
		if CanonicalResponsesToolType(rawStringValue(tool["type"])) != schemas.ResponsesToolTypeNamespace {
			list = append(list, NamespacedTool{Tool: tool})
			continue
		}
		namespace := rawStringValue(tool["name"])
		if namespace == providerutils.DefaultToolNamespace {
			namespace = ""
		}
		members, _ := rawjson.Array(tool["tools"])
		for _, raw := range members {
			if member, err := rawjson.Object(raw); err == nil {
				list = append(list, NamespacedTool{Namespace: namespace, Tool: member})
			}
		}
	}
	return list
}

// ResponsesLoadedTools returns the tools that the tool_search_output items of a Responses input
// load. The model calls them as it calls the request's own tools, and a search that the client
// runs can load tools that the request does not declare.
func ResponsesLoadedTools(input json.RawMessage) []map[string]json.RawMessage {
	// JSON can spell the type only plainly or with \u escapes, so input without either holds no
	// such item.
	if !bytes.Contains(input, []byte("tool_search_output")) && !bytes.Contains(input, []byte(`\u`)) {
		return nil
	}
	items, err := rawjson.Array(input)
	if err != nil {
		return nil
	}
	var loaded []map[string]json.RawMessage
	for _, raw := range items {
		item, err := rawjson.Object(raw)
		if err != nil || rawStringValue(item["type"]) != "tool_search_output" {
			continue
		}
		tools, _ := rawjson.Array(item["tools"])
		for _, rawTool := range tools {
			if tool, err := rawjson.Object(rawTool); err == nil {
				loaded = append(loaded, tool)
			}
		}
	}
	return loaded
}

// addMCPServer adds an MCP tool's servers and the tools that it allows on them.
func (f *requestFacts) addMCPServer(tool map[string]json.RawMessage) {
	names := mcpAllowedToolNames(tool["allowed_tools"])
	for _, server := range mcpServerNames(tool) {
		f.mcpServers = append(f.mcpServers, server)
		if len(names) == 0 {
			f.mcpTools = append(f.mcpTools, server+"/*")
		}
		for _, name := range names {
			f.mcpTools = append(f.mcpTools, server+"/"+name)
		}
	}
}

// mcpServerNames names the server of an MCP tool by each of server_url, connector_id and
// tunnel_id that it sets, so a list of allowed servers checks whichever one the provider uses.
// A URL reads as its host, with a Unicode host in its ASCII form. A URL without a host, or a tool
// that names no server, reads as an empty name, which no allowed server matches.
func mcpServerNames(tool map[string]json.RawMessage) []string {
	var names []string
	if address := rawStringValue(tool["server_url"]); address != "" {
		host := ""
		if parsed, err := url.Parse(address); err == nil {
			host = strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
			if ascii, err := idna.Lookup.ToASCII(host); err == nil {
				host = ascii
			}
		}
		names = append(names, host)
	}
	for _, key := range []string{"connector_id", "tunnel_id"} {
		if id := rawStringValue(tool[key]); id != "" {
			names = append(names, strings.ToLower(id))
		}
	}
	if len(names) == 0 {
		return []string{""}
	}
	return names
}

// mcpAllowedToolNames reads the tool names in allowed_tools, as a list or as a filter's
// tool_names. None means the request doesn't name the server's tools: a missing list, an empty
// one, or a filter by read_only alone.
func mcpAllowedToolNames(raw json.RawMessage) []string {
	if filter, ok := rawObjectValue(raw); ok && filter != nil {
		raw = filter["tool_names"]
	}
	list, err := rawjson.Array(raw)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(list))
	for _, item := range list {
		if name := rawStringValue(item); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// sortedNames sorts names and drops repeats. An empty name stays, so that a list of allowed
// names refuses it.
func sortedNames(names []string) []string {
	slices.Sort(names)
	return slices.Compact(names)
}

// requestSendsSystemMessages reports whether a request sends a system or developer message, or
// Responses instructions.
func requestSendsSystemMessages(route Route, raw map[string]json.RawMessage) (bool, error) {
	messageField := "messages"
	if route == RouteResponses {
		messageField = "input"
		instructions := bytes.TrimSpace(raw["instructions"])
		if len(instructions) != 0 && !bytes.Equal(instructions, []byte("null")) && !bytes.Equal(instructions, []byte(`""`)) {
			return true, nil
		}
	}
	value := bytes.TrimSpace(raw[messageField])
	if len(value) == 0 || value[0] != '[' {
		return false, nil
	}
	var messages []struct{ Role string }
	if err := json.Unmarshal(value, &messages); err != nil {
		return false, ErrInvalidJSON
	}
	return slices.ContainsFunc(messages, func(message struct{ Role string }) bool {
		return message.Role == "system" || message.Role == "developer"
	}), nil
}
