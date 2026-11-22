package catalog

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// HostedTool is a tool that the provider, or a service that it calls, runs only when a request
// lists it.
type HostedTool string

const (
	HostedToolWebSearch HostedTool = "web_search"
	HostedToolWebFetch  HostedTool = "web_fetch"
	HostedToolMCP       HostedTool = "mcp"
)

// HostedTools lists every hosted tool in canonical order.
var HostedTools = []HostedTool{HostedToolWebSearch, HostedToolWebFetch, HostedToolMCP}

func hostedToolRank(tool HostedTool) int { return slices.Index(HostedTools, tool) }

// HostedToolOffer is a hosted tool that a deployment's route runs for it, with the call meters
// that the tool bills.
type HostedToolOffer struct {
	DataHandling HostedToolDataHandling `json:"dataHandling"`
	Pricing      Pricing                `json:"pricing"`
}

// HostedToolDataHandling is where a tool's own processing sends request content and what it
// keeps. Each set field can only make the deployment's value worse.
type HostedToolDataHandling struct {
	ProcessingLocation string       `json:"processingLocation,omitzero"`
	StorageLocation    string       `json:"storageLocation,omitzero"`
	RetentionDays      Stated[int]  `json:"retentionDays,omitzero"`
	TrainingUse        Stated[bool] `json:"trainingUse,omitzero"`
	ZeroDataRetention  *bool        `json:"zeroDataRetention,omitzero"`
	EndToEndEncrypted  *bool        `json:"endToEndEncrypted,omitzero"`
	TEE                *bool        `json:"tee,omitzero"`
	TEEVerified        *bool        `json:"teeVerified,omitzero"`
	// SharedWith lists the companies that the tool sends request content to.
	SharedWith []string `json:"sharedWith,omitzero"`
	// WithoutCertifications lists the deployment's certifications that do not cover the tool.
	WithoutCertifications []string `json:"withoutCertifications,omitzero"`
}

// Stated is a tool's retention or training use, which the catalog can state as unknown. Unset
// leaves the deployment's value; a nil Value is unknown.
type Stated[T any] struct {
	Set   bool
	Value *T
}

// MarshalJSON writes a set fact as the catalog states it: its value, or null when unknown.
func (s Stated[T]) MarshalJSON() ([]byte, error) { return jsonv2.Marshal(s.Value) }

func (s *Stated[T]) UnmarshalJSONFrom(decoder *jsontext.Decoder) error {
	var value *T
	if err := jsonv2.UnmarshalDecode(decoder, &value); err != nil {
		return err
	}
	s.Set, s.Value = true, value
	return nil
}

// HostedToolForType reads a Responses tool type, versioned or not, as the hosted tool that it
// runs, if it runs one.
func HostedToolForType(kind string) (HostedTool, bool) { return hostedToolForType(kind) }

// EffectiveDataHandling gives the facts of one request: the deployment's data handling, with the
// facts that each account option of its credential sets, joined with that of each hosted tool that
// the request lets the model call, so a fact holds for everything the request can cause. Options
// come first and tools join after, so an option cannot hide what a tool does. Inference itself
// stays where the deployment's own facts say. A name never makes a tool hosted: only a tool's type
// does (hostedToolForType), so a client's function named web_search changes nothing.
//
// A request that stores (ProviderState.Keeps) asks the provider to keep its content, which it then
// keeps for as long as it decides, OpenAI for at least 30 days and a conversation until someone
// deletes it, where the deployment keeps what it stores. No option or agreement of the account
// covers that content: OpenAI keeps it under Modified Abuse Monitoring. Zero Data Retention makes
// OpenAI ignore store, but no option states such a rule, so a request that stores reads as stored
// on every account.
func (d Deployment) EffectiveDataHandling(options []HeldOption, tools []HostedTool, stores bool) DataHandling {
	handling := d.DataHandling
	var applied []AccountOption
	for _, option := range d.AccountOptions {
		if slices.ContainsFunc(options, func(held HeldOption) bool { return held.ID == option.ID }) {
			option.set(&handling)
			applied = append(applied, option)
		}
	}
	if stores {
		handling.RetentionDays, applied = nil, nil
		if handling.StorageLocation = d.DataHandling.StorageLocation; handling.StorageLocation == "none" {
			handling.StorageLocation = "unknown"
		}
	}
	for _, tool := range tools {
		offer, ok := d.HostedTools[tool]
		if !ok {
			continue
		}
		effect := offer.DataHandling
		if effect.ProcessingLocation != "" {
			handling.ProcessingLocation = d.Locations.Join(handling.ProcessingLocation, effect.ProcessingLocation)
		}
		if effect.StorageLocation != "" {
			handling.StorageLocation = d.Locations.Join(handling.StorageLocation, effect.StorageLocation)
		}
		if effect.RetentionDays.Set {
			switch {
			case handling.RetentionDays == nil:
			case effect.RetentionDays.Value == nil:
				handling.RetentionDays = nil
			case *effect.RetentionDays.Value > *handling.RetentionDays:
				days := *effect.RetentionDays.Value
				handling.RetentionDays = &days
			}
		}
		// Training use only worsens: false, then unknown, then true.
		if effect.TrainingUse.Set && !isTrue(handling.TrainingUse) {
			handling.TrainingUse = effect.TrainingUse.Value
		}
		handling.ZeroDataRetention = handling.ZeroDataRetention && !isFalse(effect.ZeroDataRetention)
		handling.EndToEndEncrypted = handling.EndToEndEncrypted && !isFalse(effect.EndToEndEncrypted)
		handling.TEE = handling.TEE && !isFalse(effect.TEE)
		handling.TEEVerified = handling.TEEVerified && !isFalse(effect.TEEVerified)
		if len(effect.SharedWith) > 0 {
			handling.SharedWith = slices.Compact(slices.Sorted(slices.Values(slices.Concat(handling.SharedWith, effect.SharedWith))))
		}
		if len(effect.WithoutCertifications) > 0 {
			handling.Certifications = slices.DeleteFunc(slices.Clone(handling.Certifications), func(id string) bool {
				return slices.Contains(effect.WithoutCertifications, id)
			})
		}
	}
	// The joined facts keep what a deployment's own must (validateDeploymentDataHandling): a tool
	// that keeps or trains on content ends zero data retention whether or not its record says so,
	// and one that leaves the TEE ends what rests on it.
	handling.ZeroDataRetention = handling.ZeroDataRetention && handling.StorageLocation == "none" &&
		handling.RetentionDays != nil && *handling.RetentionDays == 0 && isFalse(handling.TrainingUse)
	handling.TEEVerified = handling.TEEVerified && handling.TEE
	handling.EndToEndEncrypted = handling.EndToEndEncrypted && handling.TEE
	grant(&handling, applied)
	return handling
}

func isTrue(value *bool) bool  { return value != nil && *value }
func isFalse(value *bool) bool { return value != nil && !*value }

// validateHostedTools checks a deployment's tools on one route: each is known and sets only facts
// that it can make worse, web search prices exactly the call meters of its wire, so no search bills
// at zero, and nothing else prices them. validateLocations checks the tools' locations.
func validateHostedTools(owner string, claudeWire bool, tools map[HostedTool]HostedToolOffer, deployment Pricing) error {
	required, foreign := webSearchMeters(claudeWire)
	for tool, offer := range tools {
		if hostedToolRank(tool) < 0 {
			return fmt.Errorf("%s offers unknown hosted tool %q", owner, tool)
		}
		effect := offer.DataHandling
		if !certificationsInOrder(effect.WithoutCertifications) {
			return fmt.Errorf("%s has an invalid list of certifications that do not cover %s", owner, tool)
		}
		if effect.RetentionDays.Set && effect.RetentionDays.Value != nil && *effect.RetentionDays.Value < 0 ||
			isFalse(effect.TrainingUse.Value) || isTrue(effect.ZeroDataRetention) || isTrue(effect.EndToEndEncrypted) ||
			isTrue(effect.TEE) || isTrue(effect.TEEVerified) {
			return fmt.Errorf("%s has %s data handling that would improve the deployment's", owner, tool)
		}
		meters := 0
		if tool == HostedToolWebSearch {
			meters = len(required)
			for _, meter := range required {
				if len(offer.Pricing[meter]) == 0 {
					return fmt.Errorf("%s offers web search without a price for %s", owner, meter)
				}
			}
		}
		if len(offer.Pricing) != meters {
			return fmt.Errorf("%s prices %s on a meter that it does not bill", owner, tool)
		}
	}
	for _, meter := range slices.Concat(required, foreign) {
		if len(deployment[meter]) > 0 {
			return fmt.Errorf("%s prices %s, which only web search on its wire charges", owner, meter)
		}
	}
	return nil
}

// webSearchMeters are the call meters that a wire charges web search on, and those it does not.
func webSearchMeters(claudeWire bool) (required, foreign []string) {
	anthropic := []string{meterAnthropicWebSearchCalls}
	openai := []string{
		meterOpenAIResponsesWebSearchCalls,
		meterOpenAIResponsesWebSearchPreviewCalls,
		meterOpenAIResponsesWebSearchPreviewNonReasoningCalls,
	}
	if claudeWire {
		return anthropic, openai
	}
	return openai, anthropic
}

func hostedToolsOf(kinds []string) []HostedTool {
	var tools []HostedTool
	for _, kind := range kinds {
		if tool, ok := hostedToolForType(kind); ok && !slices.Contains(tools, tool) {
			tools = append(tools, tool)
		}
	}
	slices.SortFunc(tools, func(a, b HostedTool) int { return hostedToolRank(a) - hostedToolRank(b) })
	return tools
}

// filterHostedTools keeps the candidates whose route runs every hosted tool that the request
// lists, since the others refuse the tool's declaration, and lists the others as ruled out. The
// tools' data handling is for policies to weigh.
func filterHostedTools(selections []routingSelection, listed []HostedTool, trace *routingTrace) ([]routingSelection, []ruledOut, error) {
	if len(listed) == 0 {
		return selections, nil, nil
	}
	kept := selections[:0]
	var removed []ruledOut
	for _, selection := range selections {
		missing := selection.deployment.missingHostedTools(listed)
		if len(missing) == 0 {
			kept = append(kept, selection)
			continue
		}
		removed = append(removed, ruledOut{selection, hostedToolsUnavailable(listed, true)})
		if trace != nil {
			names := make([]string, len(missing))
			for i, tool := range missing {
				names[i] = string(tool)
			}
			trace.remove(RemovedCandidate{
				Reason: RemovedHostedTool, Provider: selection.provider, Deployment: selection.deployment.ID,
				Model: selection.deployment.ModelID, Tools: names,
			})
		}
	}
	if len(kept) == 0 {
		return nil, nil, hostedToolsUnavailable(listed, false)
	}
	return kept, removed, nil
}

func (d Deployment) missingHostedTools(tools []HostedTool) []HostedTool {
	var missing []HostedTool
	for _, tool := range tools {
		if _, ok := d.HostedTools[tool]; !ok {
			missing = append(missing, tool)
		}
	}
	return missing
}

// hostedToolsUnavailable is the error for a request whose hosted tools no candidate runs, or,
// for credentials, no candidate that the request's credentials reach.
func hostedToolsUnavailable(tools []HostedTool, credentials bool) APIError {
	names := make([]string, len(tools))
	for i, tool := range tools {
		names[i] = string(tool)
	}
	subject, fix := "No deployment for this request runs ", "choose another model."
	if credentials {
		subject, fix = "No deployment that your credentials reach runs ", "check each credential's Region, hostings and Azure deployments."
	}
	message := subject + names[0] + ". Remove the tool or " + fix
	if len(names) > 1 {
		message = subject + "all of " + strings.Join(names, ", ") + ". Remove a tool or " + fix
	}
	return APIError{Code: ErrUnsupportedTool.Code, StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: message, Param: "tools"}
}

// hostedToolForType reads a Responses tool type, versioned or not, as the hosted tool it runs.
func hostedToolForType(kind string) (HostedTool, bool) {
	switch CanonicalResponsesToolType(kind) {
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview:
		return HostedToolWebSearch, true
	case schemas.ResponsesToolTypeWebFetch:
		return HostedToolWebFetch, true
	case schemas.ResponsesToolTypeMCP:
		return HostedToolMCP, true
	}
	return "", false
}

// readsHostedCall reports whether the deployment takes back an earlier call of a hosted tool. Only
// a route that runs the tool takes its calls, and only in the form that its provider reads: OpenAI
// takes web searches with their IDs (openAIWebSearchCallID), and Claude takes web searches with the
// encrypted content of every result and web fetches with what they got. Codex keeps only a
// search's query, so Claude does not read a search that Codex sends back. The calls that the
// deployment does not read go, as reasoning that it does not read goes.
func (r *ResolvedRequest) readsHostedCall(item *schemas.ResponsesMessage) bool {
	tool := HostedToolWebSearch
	if *item.Type == schemas.ResponsesMessageTypeWebFetchCall {
		tool = HostedToolWebFetch
	}
	call := item.ResponsesToolMessage
	if _, runs := r.Deployment.HostedTools[tool]; !runs || call == nil {
		return false
	}
	switch {
	case UsesClaudeWire(r.Provider, r.Deployment.ModelID):
		if tool == HostedToolWebFetch {
			return call.ResponsesWebFetchCall != nil && call.ResponsesWebFetchCall.ResultType != ""
		}
		return call.Action != nil && claudeSearchResults(call.Action.ResponsesWebSearchToolCallAction)
	case r.RunsOpenAIModel() && r.WireRoute() == RouteResponses:
		return tool == HostedToolWebSearch && item.ID != nil && openAIWebSearchCallID(*item.ID)
	}
	return false
}

// claudeSearchResults reports whether a web search holds Claude's results, each with its encrypted
// content, which is what Claude reads of them.
func claudeSearchResults(search *schemas.ResponsesWebSearchToolCallAction) bool {
	if search == nil || len(search.Sources) == 0 {
		return false
	}
	for _, source := range search.Sources {
		if source.EncryptedContent == nil || *source.EncryptedContent == "" {
			return false
		}
	}
	return true
}

// openAIWebSearchCallID reports whether core sends a web search call to OpenAI with its ID: ws_ and
// more than digits. OpenAI takes any ID that begins with ws, even one that it never issued, and
// refuses another, such as Claude's (testdata/provider/openai/web-search-call-replay.json). Core
// sends any other call without its ID and status, because Gemini's calls take ws_ and a number
// (isNativeWebSearchCall), and no recording shows OpenAI taking that form.
func openAIWebSearchCallID(id string) bool {
	suffix, ok := strings.CutPrefix(id, "ws_")
	return ok && strings.Trim(suffix, "0123456789") != ""
}

// Anthropic's bash and text editor tools are functions whose schema Claude already knows. A
// request declares one by its dated type and fixed name, Claude calls it by that name with JSON
// arguments, and the client runs it and returns the result as for any function. These versions
// are the ones that every listed Claude model takes.
const (
	AnthropicBashToolType       = "bash_20250124"
	AnthropicTextEditorToolType = "text_editor_20250728"
)

// AnthropicClientToolName returns the name that Anthropic fixes for one of its client tools.
func AnthropicClientToolName(rawType string) (string, bool) {
	switch strings.TrimSpace(rawType) {
	case AnthropicBashToolType:
		return "bash", true
	case AnthropicTextEditorToolType:
		return "str_replace_based_edit_tool", true
	}
	return "", false
}

// CanonicalResponsesToolType names a versioned tool type, such as web_search_20250305, by the
// stable behavior it runs. Anthropic's client tools read as functions.
func CanonicalResponsesToolType(rawType string) schemas.ResponsesToolType {
	toolType := schemas.ResponsesToolType(strings.TrimSpace(rawType))
	if _, ok := AnthropicClientToolName(string(toolType)); ok {
		return schemas.ResponsesToolTypeFunction
	}
	switch {
	case toolType == schemas.ResponsesToolTypeWebSearchPreview:
		return toolType
	case strings.HasPrefix(string(toolType), "web_search_preview"):
		return schemas.ResponsesToolTypeWebSearchPreview
	case toolType == schemas.ResponsesToolTypeWebSearch:
		return toolType
	case strings.HasPrefix(string(toolType), "web_search"):
		return schemas.ResponsesToolTypeWebSearch
	case strings.HasPrefix(string(toolType), "web_fetch"):
		return schemas.ResponsesToolTypeWebFetch
	case strings.HasPrefix(string(toolType), "code_execution"):
		return schemas.ResponsesToolTypeCodeInterpreter
	// OpenAI's computer tool is computer, and Anthropic's dated computer tools read as OpenAI's
	// retired preview.
	case toolType == schemas.ResponsesToolTypeComputer:
		return toolType
	case strings.HasPrefix(string(toolType), "computer") && toolType != schemas.ResponsesToolTypeComputerUsePreview:
		return schemas.ResponsesToolTypeComputerUsePreview
	default:
		return toolType
	}
}

// EffectiveResponsesToolTypes lists the declared tool types that tool_choice leaves callable:
// none for "none", those that allowed_tools or a forced tool names, and otherwise all of them.
func EffectiveResponsesToolTypes(rawBody map[string]json.RawMessage, declared []string) []string {
	if rawBody == nil {
		return declared
	}
	choiceRaw, ok := rawBody["tool_choice"]
	if !ok || len(choiceRaw) == 0 || string(choiceRaw) == "null" {
		return declared
	}
	trimmed := strings.TrimSpace(string(choiceRaw))
	if trimmed == "" {
		return declared
	}
	if trimmed[0] == '"' {
		if rawStringValue(choiceRaw) == "none" {
			return nil
		}
		return declared
	}
	choice, ok := rawObjectValue(choiceRaw)
	if !ok {
		return declared
	}
	if rawStringValue(choice["type"]) == "allowed_tools" {
		rawAllowed, ok := choice["tools"]
		if !ok {
			return declared
		}
		allowed, err := rawjson.Array(rawAllowed)
		if err != nil {
			return declared
		}
		types := make([]schemas.ResponsesToolType, 0, len(allowed))
		for _, rawTool := range allowed {
			tool, _ := rawObjectValue(rawTool)
			types = append(types, CanonicalResponsesToolType(rawStringValue(tool["type"])))
		}
		return matchingDeclaredResponsesToolTypes(declared, types)
	}
	return matchingDeclaredResponsesToolTypes(declared, []schemas.ResponsesToolType{CanonicalResponsesToolType(rawStringValue(choice["type"]))})
}

// rawObjectValue reads a JSON object as the gateway's request checks do: null reads as an empty
// object, and a repeated member name fails.
func rawObjectValue(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, true
	}
	object, err := rawjson.Object(raw)
	return object, err == nil
}

func matchingDeclaredResponsesToolTypes(declared []string, allowed []schemas.ResponsesToolType) []string {
	if len(allowed) == 0 {
		return nil
	}
	matches := []string{}
	seen := map[schemas.ResponsesToolType]bool{}
	for _, allowedType := range allowed {
		if allowedType == "" || seen[allowedType] {
			continue
		}
		seen[allowedType] = true
		for _, declaredType := range declared {
			if CanonicalResponsesToolType(declaredType) == allowedType {
				matches = append(matches, string(allowedType))
				break
			}
		}
	}
	return matches
}
