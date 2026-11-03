package catalog

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"net/http"
	"slices"
	"strconv"
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

// HostedToolOffer is a hosted tool that a deployment's route runs for it. Its call meters are
// already in the deployment's prices.
type HostedToolOffer struct {
	DataHandling HostedToolDataHandling `json:"dataHandling"`
}

// HostedToolDataHandling is where a tool's own processing sends request content and what it
// keeps. Each set field can only make the deployment's value worse.
type HostedToolDataHandling struct {
	ProcessingLocation string          `json:"processingLocation,omitzero"`
	StorageLocation    string          `json:"storageLocation,omitzero"`
	RetentionDays      RetentionEffect `json:"retentionDays,omitzero"`
	TrainingUse        *bool           `json:"trainingUse,omitzero"`
	ZeroDataRetention  *bool           `json:"zeroDataRetention,omitzero"`
	EndToEndEncrypted  *bool           `json:"endToEndEncrypted,omitzero"`
	TEE                *bool           `json:"tee,omitzero"`
	TEEVerified        *bool           `json:"teeVerified,omitzero"`
}

// RetentionEffect is a tool's retention. Unset leaves the deployment's; a nil Days is unknown.
type RetentionEffect struct {
	Set  bool
	Days *int
}

// MarshalJSON writes a set retention as the catalog states it: its days, or null when unknown.
func (r RetentionEffect) MarshalJSON() ([]byte, error) {
	if r.Days == nil {
		return []byte("null"), nil
	}
	return strconv.AppendInt(nil, int64(*r.Days), 10), nil
}

func (r *RetentionEffect) UnmarshalJSONFrom(decoder *jsontext.Decoder) error {
	var days *int
	if err := jsonv2.UnmarshalDecode(decoder, &days); err != nil {
		return err
	}
	r.Set, r.Days = true, days
	return nil
}

// HostedToolForType reads a Responses tool type, versioned or not, as the hosted tool that it
// runs, if it runs one.
func HostedToolForType(kind string) (HostedTool, bool) { return hostedToolForType(kind) }

// EffectiveDataHandling joins the deployment's data handling with that of each hosted tool that
// the request lets the model call, so a fact holds for everything the request can cause. Inference
// itself stays where the deployment's own facts say.
func (d Deployment) EffectiveDataHandling(tools []HostedTool) DataHandling {
	handling := d.DataHandling
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
			case effect.RetentionDays.Days == nil:
				handling.RetentionDays = nil
			case *effect.RetentionDays.Days > *handling.RetentionDays:
				days := *effect.RetentionDays.Days
				handling.RetentionDays = &days
			}
		}
		handling.TrainingUse = handling.TrainingUse || isTrue(effect.TrainingUse)
		handling.ZeroDataRetention = handling.ZeroDataRetention && !isFalse(effect.ZeroDataRetention)
		handling.EndToEndEncrypted = handling.EndToEndEncrypted && !isFalse(effect.EndToEndEncrypted)
		handling.TEE = handling.TEE && !isFalse(effect.TEE)
		handling.TEEVerified = handling.TEEVerified && !isFalse(effect.TEEVerified)
	}
	return handling
}

func isTrue(value *bool) bool  { return value != nil && *value }
func isFalse(value *bool) bool { return value != nil && !*value }

// validateHostedTools checks a deployment's tools on one route: each is known and sets only facts
// that it can make worse, and web search prices every call meter of its wire and nothing else, so
// no search bills at zero. validateLocations checks the tools' locations.
func validateHostedTools(owner string, claudeWire bool, tools map[HostedTool]HostedToolOffer, pricing Pricing) error {
	for tool, offer := range tools {
		if hostedToolRank(tool) < 0 {
			return fmt.Errorf("%s offers unknown hosted tool %q", owner, tool)
		}
		effect := offer.DataHandling
		if effect.RetentionDays.Set && effect.RetentionDays.Days != nil && *effect.RetentionDays.Days < 0 ||
			isFalse(effect.TrainingUse) || isTrue(effect.ZeroDataRetention) || isTrue(effect.EndToEndEncrypted) ||
			isTrue(effect.TEE) || isTrue(effect.TEEVerified) {
			return fmt.Errorf("%s has %s data handling that would improve the deployment's", owner, tool)
		}
	}
	required, foreign := webSearchMeters(claudeWire)
	_, search := tools[HostedToolWebSearch]
	for _, meter := range required {
		if search != (len(pricing[meter]) > 0) {
			return fmt.Errorf("%s prices %s only with web search", owner, meter)
		}
	}
	for _, meter := range foreign {
		if len(pricing[meter]) > 0 {
			return fmt.Errorf("%s prices %s, which its wire does not charge", owner, meter)
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

// hostedToolUse is the hosted tools that a request lists, and those of them that its tool_choice
// lets the model call. A deployment must take every listed tool's declaration, and only the
// callable ones can send request content anywhere.
type hostedToolUse struct {
	listed, enabled []HostedTool
}

// requestHostedTools reads a request's hosted tools in canonical order. Only Responses requests
// list them; Chat Completions takes function tools alone.
func requestHostedTools(route Route, raw map[string]json.RawMessage) hostedToolUse {
	rawTools, ok := raw["tools"]
	if route != RouteResponses || !ok {
		return hostedToolUse{}
	}
	tools, err := rawjson.Array(rawTools)
	if err != nil {
		return hostedToolUse{}
	}
	declared := make([]string, 0, len(tools))
	for _, rawTool := range tools {
		if tool, err := rawjson.Object(rawTool); err == nil {
			if kind := rawStringValue(tool["type"]); kind != "" {
				declared = append(declared, kind)
			}
		}
	}
	return hostedToolUse{listed: hostedToolsOf(declared), enabled: hostedToolsOf(EffectiveResponsesToolTypes(raw, declared))}
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

// CanonicalResponsesToolType names a versioned tool type, such as web_search_20250305, by the
// stable behavior it runs.
func CanonicalResponsesToolType(rawType string) schemas.ResponsesToolType {
	toolType := schemas.ResponsesToolType(strings.TrimSpace(rawType))
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
