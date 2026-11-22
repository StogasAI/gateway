package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// ProviderState is what a request keeps or reads in its provider account through OpenAI's API: a
// reply that the provider stores (store), a stored reply that it continues (previous_response_id),
// a conversation that it adds to (conversation), the vector stores that file search searches, the
// container that code interpreter or a hosted shell runs in, or a generated image that the input
// sends back by its ID. Each lives in one account, so only a customer's own credential serves such
// a request, never Stogas's, and only on the provider's own API, which no translation carries.
//
// OpenAI's prompt templates (prompt) stay refused: a template can hold instructions, tools and
// output settings that the gateway never sees, so policies on tools and the checks of the reply
// could not hold.
type ProviderState struct {
	// Fields lists the fields that keep or read provider state, in this order: store where the
	// provider gets store: true, each of previous_response_id and conversation that the request
	// sends, vector_store_ids where a file search reads vector stores, container where code
	// interpreter or a hosted shell runs in one, and image_generation_call where the input sends
	// back a generated image by its ID.
	Fields []string
	// Store is the store value that the provider gets: the client's, or, where the client sends
	// none, true for a request that continues a stored reply or a conversation, as OpenAI's own
	// default would, because a reply that the provider does not keep ends the chain. Otherwise
	// the gateway sends false where OpenAI's default stores, so nothing stays at the provider
	// unless the request asks.
	Store bool
	// Keeps reports whether the provider keeps the request's content after the call: it stores
	// the reply, adds the turn to a conversation, or runs a container, which keeps the files that
	// its tool mounts and its code writes until it expires.
	Keeps bool
	// Held names the first field whose earlier conversation the provider holds and the gateway
	// never reads: previous_response_id or conversation. Its size is unknown, and it can hold the
	// calls that the input answers.
	Held string
	// Reads is the path of the first field that names content in one account, which the model
	// reads and no input check can: Held, a file search's vector stores, such as
	// tools[0].vector_store_ids, a container tool's container, files and stored skills, the
	// container of a call that the input sends back while a container tool is listed, which OpenAI
	// runs the next calls in (captures openai/code-interpreter and openai/hosted-shell), or an image
	// generation call that the input sends back, which OpenAI reads from the stored reply (capture
	// openai/image-generation-replay).
	Reads string
	// Container is the path of the first container tool, such as tools[1]. OpenAI bills a
	// container to the account by the session, a price that no reply reports, so only the
	// account's owner pays for it.
	Container string
	// Network is the path of the first thing that can let a container's code reach the network:
	// a network policy that allows domains, or a container that the request names or sends back,
	// which keeps the network policy that it was made with and that the gateway never sees.
	Network string
}

// readProviderState reads what a request keeps or reads at its provider, after planning has
// dropped the fields that are null and continuation IDs that are empty. Chat Completions has only
// store. The interface's checks refuse a value of the wrong type.
func readProviderState(route Route, raw map[string]json.RawMessage) ProviderState {
	var state ProviderState
	var held []string
	if route == RouteResponses {
		for _, name := range [...]string{"previous_response_id", "conversation"} {
			if _, ok := raw[name]; ok {
				held = append(held, name)
			}
		}
	}
	store, set := raw["store"]
	state.Store = rawJSONTrue(store) || !set && len(held) > 0
	if state.Store {
		state.Fields = append(state.Fields, "store")
	}
	state.Fields = append(state.Fields, held...)
	if len(held) > 0 {
		state.Held, state.Reads = held[0], held[0]
	}
	if route == RouteResponses {
		vectorStores := false
		tools, _ := rawjson.Array(raw["tools"])
		for index, rawTool := range tools {
			tool, err := rawjson.Object(rawTool)
			if err != nil {
				continue
			}
			path := fmt.Sprintf("tools[%d]", index)
			switch hosted, _ := HostedToolOf(tool); hosted {
			case HostedToolFileSearch:
				vectorStores = true
				state.read(path + ".vector_store_ids")
			case HostedToolCodeInterpreter, HostedToolShell:
				if state.Container == "" {
					state.Container = path
				}
				named, read := containerRead(tool, path)
				state.read(read)
				if state.Network == "" {
					state.Network = named
				}
				if state.Network == "" {
					state.Network = networkAllowed(tool, path)
				}
			}
		}
		if vectorStores {
			state.Fields = append(state.Fields, "vector_store_ids")
		}
		if state.Container != "" {
			state.Fields = append(state.Fields, "container")
			replayed := replayedContainer(raw["input"])
			state.read(replayed)
			if state.Network == "" {
				state.Network = replayed
			}
		}
		if image := replayedImageCall(raw["input"]); image != "" {
			state.Fields = append(state.Fields, "image_generation_call")
			state.read(image)
		}
	}
	state.Keeps = state.Store || slices.Contains(held, "conversation") || state.Container != ""
	return state
}

// read records path, unless it is empty or an earlier field names content in one account.
func (s *ProviderState) read(path string) {
	if s.Reads == "" {
		s.Reads = path
	}
}

// containerOptions returns a container tool's container options and their path: code
// interpreter's container, or a hosted shell's environment.
func containerOptions(tool map[string]json.RawMessage, path string) (json.RawMessage, string) {
	if hosted, _ := HostedToolOf(tool); hosted == HostedToolShell {
		return tool["environment"], path + ".environment"
	}
	return tool["container"], path + ".container"
}

// containerRead returns the path of the container that a container tool names, code interpreter's
// by its ID or a hosted shell's by reference, and the path of the first thing in its account that
// the tool names: that container, the files that the tool mounts, or a skill that a hosted shell
// loads from the account. Either is "" when the tool names none.
func containerRead(tool map[string]json.RawMessage, path string) (named, read string) {
	options, place := containerOptions(tool, path)
	if rawStringValue(options) != "" {
		return place, place
	}
	object, _ := rawObjectValue(options)
	if rawStringValue(object["container_id"]) != "" {
		return place + ".container_id", place + ".container_id"
	}
	if files, _ := rawjson.Array(object["file_ids"]); len(files) > 0 {
		return "", place + ".file_ids"
	}
	skills, _ := rawjson.Array(object["skills"])
	for index, rawSkill := range skills {
		if skill, _ := rawObjectValue(rawSkill); rawStringValue(skill["type"]) == "skill_reference" {
			return "", fmt.Sprintf("%s.skills[%d]", place, index)
		}
	}
	return "", ""
}

// networkAllowed returns the path of a container tool's network policy when it allows domains, or
// "". A container that the request makes reaches no network otherwise.
func networkAllowed(tool map[string]json.RawMessage, path string) string {
	options, place := containerOptions(tool, path)
	object, _ := rawObjectValue(options)
	policy, _ := rawObjectValue(object["network_policy"])
	if kind := rawStringValue(policy["type"]); kind != "" && kind != "disabled" {
		return place + ".network_policy"
	}
	return ""
}

// replayedContainer is the path of the container that the input's first call of code interpreter
// or of a hosted shell names, or "". JSON spells a member's name plainly or with \u escapes, so
// input without either names no container.
func replayedContainer(input json.RawMessage) string {
	if !bytes.Contains(input, []byte("container_id")) && !bytes.Contains(input, []byte(`\u`)) {
		return ""
	}
	items, _ := rawjson.Array(input)
	for index, rawItem := range items {
		item, _ := rawObjectValue(rawItem)
		switch rawStringValue(item["type"]) {
		case "code_interpreter_call":
			if rawStringValue(item["container_id"]) != "" {
				return fmt.Sprintf("input[%d].container_id", index)
			}
		case "shell_call":
			if environment, _ := rawObjectValue(item["environment"]); rawStringValue(environment["container_id"]) != "" {
				return fmt.Sprintf("input[%d].environment.container_id", index)
			}
		}
	}
	return ""
}

// replayedImageCall is the path of the input's first image generation call that names an image by
// its ID, or "". Planning has reduced each such call to its type and ID (keepImageCallIDs).
func replayedImageCall(input json.RawMessage) string {
	if !bytes.Contains(input, []byte("image_generation_call")) && !bytes.Contains(input, []byte(`\u`)) {
		return ""
	}
	items, _ := rawjson.Array(input)
	for index, rawItem := range items {
		if item, _ := rawObjectValue(rawItem); rawStringValue(item["type"]) == "image_generation_call" && rawStringValue(item["id"]) != "" {
			return fmt.Sprintf("input[%d]", index)
		}
	}
	return ""
}

// field names the field that a refusal names: the content that the request reads, store, or the
// container tool.
func (s ProviderState) field() string {
	switch {
	case s.Reads != "":
		return s.Reads
	case s.Container != "" && !s.Store:
		return s.Container
	}
	return "store"
}

// keepsProviderState reports whether the deployment takes provider state on route: OpenAI's own API
// for every model, and Azure's for OpenAI's models. A deployment that takes the request through
// the translation, or Claude on Azure, takes none.
func (d Deployment) keepsProviderState(provider schemas.ModelProvider, route Route) bool {
	if d.bridges(route) {
		return false
	}
	return provider == schemas.OpenAI || provider == schemas.Azure && d.Upstream.ModelFormat == "OpenAI"
}

// filterProviderState keeps the deployments that take the request's provider state.
func filterProviderState(selections []routingSelection, state ProviderState, route Route) ([]routingSelection, []ruledOut, error) {
	if len(state.Fields) == 0 {
		return selections, nil, nil
	}
	field := state.field()
	refusal := providerStateRefusal(field, field+" needs one of OpenAI's models on OpenAI or Azure, which keep it in your provider account.")
	kept := selections[:0]
	var removed []ruledOut
	for _, selection := range selections {
		if selection.deployment.keepsProviderState(selection.provider, route) {
			kept = append(kept, selection)
			continue
		}
		removed = append(removed, ruledOut{selection, refusal})
	}
	if len(kept) == 0 {
		return nil, nil, refusal
	}
	return kept, removed, nil
}

// ProviderStateUnsupported is the code of a request whose provider state no pair can take.
const ProviderStateUnsupported = "provider_state_unsupported"

// providerStateRefusal refuses field for reason and says how the request does without it.
func providerStateRefusal(field, reason string) APIError {
	fix := "Send the whole conversation in input."
	switch {
	case field == "store":
		fix = "Omit store or set it to false."
	case strings.HasPrefix(field, "tools["):
		fix = "Remove the tool."
	case strings.HasPrefix(field, "input["):
		fix = "Remove the call from input."
	}
	return APIError{StatusCode: http.StatusBadRequest, Code: ProviderStateUnsupported, Type: ErrorTypeInvalidRequest, Param: field, Message: reason + " " + fix}
}

// ManagedRefusal refuses the request's provider state on one of Stogas's credentials, whose
// accounts every organization shares, or is nil for a request that keeps and reads nothing there.
func (s ProviderState) ManagedRefusal() error {
	if len(s.Fields) == 0 {
		return nil
	}
	field := s.field()
	return providerStateRefusal(field, field+" needs your own provider credential, because Stogas's provider accounts keep nothing for a request.")
}

// heldInputCheckRefusal refuses held content where a policy checks every input, since the gateway
// never reads it.
func heldInputCheckRefusal(field, check string) error {
	return providerStateRefusal(field, field+" names content that your provider account holds, which "+check+" cannot check.")
}

// heldStateAccounts refuses held content that more than one credential could serve. It names an
// object in the account that holds it, and nothing tells which credential that is, so routing
// must not choose one.
func heldStateAccounts(field string, candidates []*ResolvedRequest, credentials map[*ResolvedRequest][]int) error {
	count, fix := credentialSpread(candidates, credentials)
	if count <= 1 {
		return nil
	}
	return APIError{
		StatusCode: http.StatusBadRequest, Code: ProviderStateUnsupported, Type: ErrorTypeInvalidRequest, Param: field,
		Message: fmt.Sprintf("%s names content that one provider account holds, and this request can use %d credentials; %s", field, count, fix),
	}
}
