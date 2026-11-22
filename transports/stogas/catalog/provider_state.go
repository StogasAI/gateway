package catalog

import (
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
// a conversation that it adds to (conversation), or the vector stores that file search searches.
// Each lives in one account, so only a customer's own credential serves such a request, never
// Stogas's, and only on the provider's own API, which no translation carries.
//
// OpenAI's prompt templates (prompt) stay refused: a template can hold instructions, tools and
// output settings that the gateway never sees, so policies on tools and the checks of the reply
// could not hold.
type ProviderState struct {
	// Fields lists the fields that keep or read provider state, in wire order: store where the
	// provider gets store: true, each of previous_response_id and conversation that the request
	// sends, and vector_store_ids where a file search reads vector stores.
	Fields []string
	// Store is the store value that the provider gets: the client's, or, where the client sends
	// none, true for a request that continues a stored reply or a conversation, as OpenAI's own
	// default would, because a reply that the provider does not keep ends the chain. Otherwise
	// the gateway sends false where OpenAI's default stores, so nothing stays at the provider
	// unless the request asks.
	Store bool
	// Keeps reports whether the provider keeps the request's content after the call: it stores
	// the reply, or adds the turn to a conversation.
	Keeps bool
	// Held names the first field whose earlier conversation the provider holds and the gateway
	// never reads: previous_response_id or conversation. Its size is unknown, and it can hold the
	// calls that the input answers.
	Held string
	// Reads is the path of the first field that names content in one account, which the model
	// reads and no input check can: Held, or a file search's vector stores, such as
	// tools[0].vector_store_ids.
	Reads string
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
	state.Keeps = state.Store || slices.Contains(held, "conversation")
	if state.Store {
		state.Fields = append(state.Fields, "store")
	}
	state.Fields = append(state.Fields, held...)
	if len(held) > 0 {
		state.Held, state.Reads = held[0], held[0]
	}
	if route != RouteResponses {
		return state
	}
	tools, _ := rawjson.Array(raw["tools"])
	for index, rawTool := range tools {
		tool, err := rawjson.Object(rawTool)
		if err != nil || CanonicalResponsesToolType(rawStringValue(tool["type"])) != schemas.ResponsesToolTypeFileSearch {
			continue
		}
		if !slices.Contains(state.Fields, "vector_store_ids") {
			state.Fields = append(state.Fields, "vector_store_ids")
		}
		if state.Reads == "" {
			state.Reads = fmt.Sprintf("tools[%d].vector_store_ids", index)
		}
	}
	return state
}

// field names the field that a refusal names: the content that the request reads, or store.
func (s ProviderState) field() string {
	if s.Reads != "" {
		return s.Reads
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
