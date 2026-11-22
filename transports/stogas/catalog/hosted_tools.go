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

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// HostedTool is a tool that the provider, or a service that it calls, runs only when a request
// lists it.
type HostedTool string

const (
	HostedToolWebSearch       HostedTool = "web_search"
	HostedToolWebFetch        HostedTool = "web_fetch"
	HostedToolMCP             HostedTool = "mcp"
	HostedToolFileSearch      HostedTool = "file_search"
	HostedToolCodeInterpreter HostedTool = "code_interpreter"
	HostedToolShell           HostedTool = "shell"
	HostedToolImageGeneration HostedTool = "image_generation"
)

// HostedTools lists every hosted tool in canonical order.
var HostedTools = []HostedTool{
	HostedToolWebSearch, HostedToolWebFetch, HostedToolMCP, HostedToolFileSearch, HostedToolCodeInterpreter, HostedToolShell,
	HostedToolImageGeneration,
}

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
	// Certifications lists the deployment's certifications that cover the tool, empty when none
	// does. Nil keeps them all.
	Certifications []string `json:"certifications,omitzero"`
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

// EffectiveDataHandling gives the facts of one request: the deployment's data handling, with the
// facts that each account option of its credential sets, joined with that of each hosted tool that
// the request lets the model call, so a fact holds for everything the request can cause. Options
// come first and tools join after, so an option cannot hide what a tool does. Inference itself
// stays where the deployment's own facts say. A name never makes a tool hosted: only a tool's type
// and a shell's environment do (HostedToolOf), so a client's function named web_search changes
// nothing.
//
// A request that stores (ProviderState.Keeps) asks the provider to keep its content, which it then
// keeps for as long as it decides, OpenAI for at least 30 days and a conversation until someone
// deletes it, where the deployment keeps what it stores. No option or agreement of the account
// covers that content: OpenAI keeps it under Modified Abuse Monitoring. Zero Data Retention makes
// OpenAI ignore store, but no option states such a rule, so a request that stores reads as stored
// on every account. A container keeps the files that its tool mounts and its code writes until it
// expires, which each use postpones, and Zero Data Retention changes none of that.
//
// A container that can reach the network (ProviderState.Network) can send content to the domains
// that it allows, third parties that the request or the container names, so the request reads as
// sending content where no fact holds, as a remote MCP tool does.
func (d Deployment) EffectiveDataHandling(options []HeldOption, tools []HostedTool, stores, network bool) DataHandling {
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
		if offer, ok := d.HostedTools[tool]; ok {
			d.join(&handling, offer.DataHandling)
		}
	}
	if network {
		d.join(&handling, unknownDestination)
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

// join makes handling hold for what a tool's processing does too.
func (d Deployment) join(handling *DataHandling, effect HostedToolDataHandling) {
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
	if effect.Certifications != nil {
		handling.Certifications = slices.DeleteFunc(slices.Clone(handling.Certifications), func(id string) bool {
			return !slices.Contains(effect.Certifications, id)
		})
	}
}

// unknownDestination is what sending content to a third party that the request names does, as the
// catalog states it for a remote MCP server: nothing is known of it, and no certification covers it.
var unknownDestination = HostedToolDataHandling{
	ProcessingLocation: "unknown", StorageLocation: "unknown",
	RetentionDays: Stated[int]{Set: true}, TrainingUse: Stated[bool]{Set: true},
	ZeroDataRetention: new(false), EndToEndEncrypted: new(false), TEE: new(false), TEEVerified: new(false),
	SharedWith: []string{HostingUnknown}, Certifications: []string{},
}

func isTrue(value *bool) bool  { return value != nil && *value }
func isFalse(value *bool) bool { return value != nil && !*value }

// validateHostedTools checks a deployment's tools on one route: each is known, sets only facts that
// it can make worse and lists only certifications of the route, web search and file search price
// exactly the call meters of their wire, so no call bills at zero, and nothing else prices them.
// Code interpreter, a hosted shell and image generation price nothing, so each serves only
// customers' own credentials and bills its tokens alone: OpenAI bills containers to the account by
// the session, which no request's reply reports (ProviderState.Container), and images at the image
// model's prices, whose cached part no reply reports (the loader's refusal of a managed offer).
// validateLocations checks the tools' locations.
func validateHostedTools(owner string, claudeWire bool, route compiledDeploymentRoute, deployment Pricing) error {
	required, foreign := webSearchMeters(claudeWire)
	for tool, offer := range route.HostedTools {
		if hostedToolRank(tool) < 0 {
			return fmt.Errorf("%s offers unknown hosted tool %q", owner, tool)
		}
		effect := offer.DataHandling
		if !certificationsInOrder(effect.Certifications) || !allIn(effect.Certifications, route.DataHandling.Certifications) {
			return fmt.Errorf("%s has an invalid list of certifications that cover %s", owner, tool)
		}
		if effect.RetentionDays.Set && effect.RetentionDays.Value != nil && *effect.RetentionDays.Value < 0 ||
			isFalse(effect.TrainingUse.Value) || isTrue(effect.ZeroDataRetention) || isTrue(effect.EndToEndEncrypted) ||
			isTrue(effect.TEE) || isTrue(effect.TEEVerified) {
			return fmt.Errorf("%s has %s data handling that would improve the deployment's", owner, tool)
		}
		var meters []string
		switch tool {
		case HostedToolWebSearch:
			meters = required
		case HostedToolFileSearch:
			// Only OpenAI's own Responses API runs file search.
			if claudeWire {
				return fmt.Errorf("%s offers file search on Claude's wire, which has none", owner)
			}
			meters = []string{meterOpenAIResponsesFileSearchCalls}
		case HostedToolCodeInterpreter, HostedToolShell:
			// Claude's code execution has another wire, prices and limits, which nothing serves yet.
			if claudeWire {
				return fmt.Errorf("%s offers %s on Claude's wire, which the gateway does not run", owner, tool)
			}
		case HostedToolImageGeneration:
			if claudeWire {
				return fmt.Errorf("%s offers image generation on Claude's wire, which has none", owner)
			}
		}
		for _, meter := range meters {
			if len(offer.Pricing[meter]) == 0 {
				return fmt.Errorf("%s offers %s without a price for %s", owner, tool, meter)
			}
		}
		if len(offer.Pricing) != len(meters) {
			return fmt.Errorf("%s prices %s on a meter that it does not bill", owner, tool)
		}
	}
	for _, meter := range slices.Concat(required, foreign, []string{meterOpenAIResponsesFileSearchCalls}) {
		if len(deployment[meter]) > 0 {
			return fmt.Errorf("%s prices %s, which only a hosted tool on its wire charges", owner, meter)
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

// addHostedTool adds tool to a list in canonical order, once.
func addHostedTool(tools []HostedTool, tool HostedTool) []HostedTool {
	if slices.Contains(tools, tool) {
		return tools
	}
	tools = append(tools, tool)
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

// HostedToolOf reads a Responses tool as the hosted tool that it runs, if it runs one: by its type,
// versioned or not, and for a shell by its environment. OpenAI runs a shell in a container, and
// the client runs one in a local environment or where the tool names none.
func HostedToolOf(tool map[string]json.RawMessage) (HostedTool, bool) {
	switch CanonicalResponsesToolType(rawStringValue(tool["type"])) {
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview:
		return HostedToolWebSearch, true
	case schemas.ResponsesToolTypeWebFetch:
		return HostedToolWebFetch, true
	case schemas.ResponsesToolTypeMCP:
		return HostedToolMCP, true
	case schemas.ResponsesToolTypeFileSearch:
		return HostedToolFileSearch, true
	case schemas.ResponsesToolTypeImageGeneration:
		return HostedToolImageGeneration, true
	case schemas.ResponsesToolTypeCodeInterpreter:
		// Claude's code execution tools read as code interpreter, but they are another tool, which
		// the gateway does not run.
		if rawStringValue(tool["type"]) == string(schemas.ResponsesToolTypeCodeInterpreter) {
			return HostedToolCodeInterpreter, true
		}
	case schemas.ResponsesToolTypeShell:
		environment, _ := rawObjectValue(tool["environment"])
		if kind := rawStringValue(environment["type"]); kind != "" && kind != "local" {
			return HostedToolShell, true
		}
	}
	return "", false
}

// hostedCallTool reads an input item as a step of a hosted tool, if it is one: a call of a search,
// a web fetch or code interpreter, or a call of a hosted shell or its output. shells holds the
// call IDs of the input's hosted shell calls (hostedShellCalls).
func hostedCallTool(item *schemas.ResponsesMessage, shells map[string]bool) (HostedTool, bool) {
	if item.Type == nil {
		return "", false
	}
	switch *item.Type {
	case schemas.ResponsesMessageTypeWebSearchCall:
		return HostedToolWebSearch, true
	case schemas.ResponsesMessageTypeWebFetchCall:
		return HostedToolWebFetch, true
	case schemas.ResponsesMessageTypeFileSearchCall:
		return HostedToolFileSearch, true
	case schemas.ResponsesMessageTypeCodeInterpreterCall:
		return HostedToolCodeInterpreter, true
	case schemas.ResponsesMessageTypeShellCall, schemas.ResponsesMessageTypeShellCallOutput:
		if call := item.ResponsesToolMessage; call != nil && call.CallID != nil && shells[*call.CallID] {
			return HostedToolShell, true
		}
	}
	return "", false
}

// hostedShellCalls returns the call IDs of the input's shell calls that ran in a container, which
// their outputs name.
func hostedShellCalls(input []schemas.ResponsesMessage) map[string]bool {
	var shells map[string]bool
	for index := range input {
		item := &input[index]
		if item.Type == nil || *item.Type != schemas.ResponsesMessageTypeShellCall || item.ResponsesToolMessage == nil ||
			item.ResponsesToolMessage.CallID == nil || item.ResponsesShellCall == nil || item.Environment == nil {
			continue
		}
		if kind := item.Environment.Type; kind != "" && kind != "local" {
			if shells == nil {
				shells = make(map[string]bool)
			}
			shells[*item.ResponsesToolMessage.CallID] = true
		}
	}
	return shells
}

// readsHostedCall reports whether the deployment takes back an earlier step of a hosted tool. Only
// a route that runs the tool takes its steps, and only in the form that its provider reads: OpenAI
// takes web searches with their IDs (openAIWebSearchCallID), file searches with their results, and
// every call of code interpreter and of a hosted shell, with the shell's outputs; Claude takes web
// searches with the encrypted content of every result and web fetches with what they got. Codex
// keeps only a search's query, so Claude does not read a search that Codex sends back. A file
// search without its results names a stored reply's search, whose results OpenAI would read where
// no input check can, and which it refuses when the reply was not stored (capture
// openai/file-search). The steps that the deployment does not read go, as reasoning that it does
// not read goes.
func (r *ResolvedRequest) readsHostedCall(item *schemas.ResponsesMessage, tool HostedTool) bool {
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
		switch tool {
		case HostedToolFileSearch:
			return call.ResponsesFileSearchToolCall != nil && call.ResponsesFileSearchToolCall.Results != nil
		case HostedToolWebSearch:
			return item.ID != nil && openAIWebSearchCallID(*item.ID)
		case HostedToolCodeInterpreter, HostedToolShell:
			return true
		}
	}
	return false
}

// ReadsHostedCallInput reports whether the deployment takes back a hosted call item as the client
// sent it, so that the checks of the input's order skip a call that the deployment never gets.
// shellCall marks a step of a hosted shell, whose output alone does not show where it ran.
func (r *ResolvedRequest) ReadsHostedCallInput(raw json.RawMessage, shellCall bool) bool {
	var item schemas.ResponsesMessage
	if sonic.Unmarshal(raw, &item) != nil {
		return false
	}
	if shellCall {
		return r.readsHostedCall(&item, HostedToolShell)
	}
	tool, hosted := hostedCallTool(&item, nil)
	return hosted && r.readsHostedCall(&item, tool)
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
