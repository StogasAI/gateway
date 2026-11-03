package stogas

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// Remote MCP tools run on OpenAI's side. OpenAI lists a server's tools, asks the client to
// approve a call or makes the call itself, and reports each step as an output item that names
// the server by its label. A call needs the client's approval unless require_approval says
// never for its tool, and an approved call runs in the next request, which carries the approval.
//
// The gateway checks every MCP item against the declared servers, holds for each model pass
// that a listing or a call can add, counts each call as a hosted tool call, and keeps the
// server's credentials out of redaction, exports and the response's echo of the request.

// The keys of OpenAI's mcp tool. connector_id, server_url and tunnel_id name the server, and
// OpenAI checks that exactly one is set.
var mcpToolKeys = []string{
	"type", "server_label", "server_url", "connector_id", "tunnel_id", "server_description",
	"authorization", "headers", "allowed_tools", "allowed_callers", "require_approval", "defer_loading",
}

const maxMCPServerLabelBytes = 256

// mcpServer is one declared MCP tool as the gateway reads it.
type mcpServer struct {
	label string
	// unattended is true when require_approval lets some tool run without the client's approval.
	unattended bool
}

// responsesMCPSupported reports whether the deployment takes remote MCP tools: OpenAI's own
// Responses API, which documents approvals and zero data retention for them.
func responsesMCPSupported(state *State) bool {
	return state != nil && state.Resolution != nil && state.Resolution.Route == catalog.RouteResponses &&
		state.Resolution.Provider == schemas.OpenAI
}

// validateResponsesMCPTool reads one MCP tool. The typed decode of the request has already
// checked the type of each field that it keeps, and it drops keys that it does not know, so
// this refuses those keys rather than forward a tool that differs from the one that was sent.
func validateResponsesMCPTool(tool map[string]json.RawMessage, path string) (mcpServer, error) {
	if err := rejectUnsupportedResponsesToolKeys(tool, path, mcpToolKeys...); err != nil {
		return mcpServer{}, err
	}
	label, ok := rawStringValue(tool["server_label"])
	if !ok || !validMCPServerLabel(label) {
		return mcpServer{}, invalidRequest(path + ".server_label must name the server in 1 to 256 bytes without spaces at either end")
	}
	if err := validateMCPToolFilter(tool["allowed_tools"], path+".allowed_tools"); err != nil {
		return mcpServer{}, err
	}
	if raw := tool["allowed_callers"]; rawJSONValueSet(raw) {
		var callers []string
		if err := sonic.Unmarshal(raw, &callers); err != nil || len(callers) == 0 {
			return mcpServer{}, invalidRequest(path + ".allowed_callers must list callers")
		}
		for _, caller := range callers {
			if caller != "direct" {
				return mcpServer{}, invalidRequest(path + ".allowed_callers can only be direct, because programmatic calls need code execution, which is not supported")
			}
		}
	}
	if raw := tool["defer_loading"]; rawJSONValueSet(raw) {
		var deferred bool
		if err := sonic.Unmarshal(raw, &deferred); err != nil {
			return mcpServer{}, invalidRequest(path + ".defer_loading must be a boolean")
		}
		if deferred {
			return mcpServer{}, invalidRequest(path + ".defer_loading needs tool_search, which is not supported")
		}
	}
	unattended, err := mcpRunsWithoutApproval(tool["require_approval"], path+".require_approval")
	if err != nil {
		return mcpServer{}, err
	}
	return mcpServer{label: label, unattended: unattended}, nil
}

func validMCPServerLabel(label string) bool {
	if label == "" || len(label) > maxMCPServerLabelBytes || strings.TrimSpace(label) != label {
		return false
	}
	for _, character := range label {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// validateMCPToolFilter checks allowed_tools, or one side of require_approval, when it is a
// filter rather than a list of tool names. The forwarded filter leaves out an empty tool_names,
// which would widen it from no tool to every tool, so the gateway refuses one.
func validateMCPToolFilter(raw json.RawMessage, path string) error {
	filter, ok := rawObject(raw)
	if !ok {
		return nil
	}
	if err := rejectUnsupportedResponsesToolKeys(filter, path, "tool_names", "read_only"); err != nil {
		return err
	}
	if names, err := rawjson.Array(filter["tool_names"]); err == nil && len(names) == 0 {
		return invalidRequest(path + ".tool_names must name at least one tool")
	}
	return nil
}

// mcpRunsWithoutApproval reads require_approval. OpenAI asks for approval of every call by
// default, so only never, or a never filter, lets a call run on its own.
func mcpRunsWithoutApproval(raw json.RawMessage, path string) (bool, error) {
	if !rawJSONValueSet(raw) {
		return false, nil
	}
	if setting, ok := rawStringValue(raw); ok {
		switch setting {
		case "always":
			return false, nil
		case "never":
			return true, nil
		default:
			return false, invalidRequest(path + " must be always, never, or a filter of always and never")
		}
	}
	filters, ok := rawObject(raw)
	if !ok {
		return false, invalidRequest(path + " must be always, never, or a filter of always and never")
	}
	if err := rejectUnsupportedResponsesToolKeys(filters, path, "always", "never"); err != nil {
		return false, err
	}
	for _, side := range []string{"always", "never"} {
		if err := validateMCPToolFilter(filters[side], path+"."+side); err != nil {
			return false, err
		}
	}
	// A never filter frees the tools that it names or marks read-only. An empty one frees
	// nothing, but the hold does not depend on how OpenAI reads it.
	return rawJSONValueSet(filters["never"]), nil
}

// enabledMCPServers returns the declared MCP tools that tool_choice leaves callable.
func enabledMCPServers(rawBody map[string]json.RawMessage, rawTools []map[string]json.RawMessage) []mcpServer {
	var servers []mcpServer
	allowed := mcpLabelsAllowedByToolChoice(rawBody)
	for index, tool := range rawTools {
		if canonicalResponsesToolType(rawString(tool["type"])) != schemas.ResponsesToolTypeMCP {
			continue
		}
		server, err := validateResponsesMCPTool(tool, "tools["+strconv.Itoa(index)+"]")
		if err != nil {
			continue
		}
		if allowed == nil || allowed[server.label] {
			servers = append(servers, server)
		}
	}
	return servers
}

// mcpLabelsAllowedByToolChoice returns the MCP servers that tool_choice selects, an empty set
// when it allows no MCP call, and nil when it allows every server.
func mcpLabelsAllowedByToolChoice(rawBody map[string]json.RawMessage) map[string]bool {
	choice := rawBody["tool_choice"]
	if mode, ok := rawStringValue(choice); ok {
		if mode == "none" {
			return map[string]bool{}
		}
		return nil
	}
	object, ok := rawObject(choice)
	if !ok {
		return nil
	}
	selected := map[string]bool{}
	if rawString(object["type"]) == "allowed_tools" {
		var tools []map[string]json.RawMessage
		if sonic.Unmarshal(object["tools"], &tools) == nil {
			for _, tool := range tools {
				if canonicalResponsesToolType(rawString(tool["type"])) == schemas.ResponsesToolTypeMCP {
					selected[rawString(tool["server_label"])] = true
				}
			}
		}
		return selected
	}
	if canonicalResponsesToolType(rawString(object["type"])) == schemas.ResponsesToolTypeMCP {
		selected[rawString(object["server_label"])] = true
	}
	return selected
}

// mcpApprovedCalls counts the approvals in a request's input: each lets one call run.
func mcpApprovedCalls(rawInput json.RawMessage) int {
	items, err := rawjson.Array(rawInput)
	if err != nil {
		return 0
	}
	approved := 0
	for _, raw := range items {
		item, err := rawjson.Object(raw)
		if err != nil || rawString(item["type"]) != string(schemas.ResponsesMessageTypeMCPApprovalResponses) {
			continue
		}
		var approve bool
		if sonic.Unmarshal(item["approve"], &approve) == nil && approve {
			approved++
		}
	}
	return approved
}

func responsesMCPServerUnattended(servers []mcpServer) bool {
	for _, server := range servers {
		if server.unattended {
			return true
		}
	}
	return false
}

// openAIResponsesMCPHoldMeters holds input for every model pass that MCP can add. A listing
// joins the first pass and each call's output joins another, and no pass reads more than the
// deployment's input limit, so the hold covers the passes at that limit, less the input that
// the base hold already covers. Output stays within max_output_tokens for the whole response.
func openAIResponsesMCPHoldMeters(req openAIAdapterContext) []billing.MeterEstimate {
	if req.Route != openAIAdapterRouteResponses {
		return nil
	}
	servers := enabledMCPServers(req.RawBody, req.RawTools)
	if len(servers) == 0 {
		return nil
	}
	calls := mcpApprovedCalls(req.RawBody["input"])
	if responsesMCPServerUnattended(servers) {
		calls += responsesHostedToolHoldQuantity(req)
	}
	passLimit := req.Deployment.MaxInputTokens
	if passLimit <= 0 {
		return nil
	}
	tokens := (calls+1)*passLimit - max(req.InputTokenLimit, 0)
	if tokens <= 0 {
		return nil
	}
	return billing.AppendTokenMeterCost(nil, req.Deployment.Pricing, billing.MeterInputTokens, tokens, true, billing.TokenRateHighest)
}

// validateResponsesMCPInput checks an MCP item that a stateless request replays: an earlier
// listing, call or approval request, or the client's answer to an approval request.
func validateResponsesMCPInput(item map[string]json.RawMessage, path string, itemType string) error {
	switch itemType {
	case "mcp_list_tools":
		if err := rejectUnsupportedInputKeys(item, path, "type", "id", "server_label", "tools", "error"); err != nil {
			return err
		}
		if err := requireMCPInputStrings(item, path, "id", "server_label"); err != nil {
			return err
		}
		var tools []map[string]json.RawMessage
		if err := sonic.Unmarshal(item["tools"], &tools); err != nil || tools == nil {
			return invalidRequest(path + ".tools must list the server's tools")
		}
		for _, tool := range tools {
			if name, ok := rawStringValue(tool["name"]); !ok || name == "" {
				return invalidRequest(path + ".tools must name each tool")
			}
		}
		return optionalMCPInputStrings(item, path, "error")
	case "mcp_call":
		if err := rejectUnsupportedInputKeys(item, path, "type", "id", "server_label", "name", "arguments", "output", "error", "status", "approval_request_id"); err != nil {
			return err
		}
		if err := requireMCPInputStrings(item, path, "id", "server_label", "name"); err != nil {
			return err
		}
		if _, err := requiredInputString(item, "arguments", path, true); err != nil {
			return err
		}
		if raw := item["status"]; rawJSONValueSet(raw) {
			status, ok := rawStringValue(raw)
			if !ok || !stringInSet(status, "in_progress", "completed", "incomplete", "calling", "failed") {
				return invalidRequest(path + ".status is not supported")
			}
		}
		return optionalMCPInputStrings(item, path, "output", "approval_request_id")
	case "mcp_approval_request":
		if err := rejectUnsupportedInputKeys(item, path, "type", "id", "server_label", "name", "arguments"); err != nil {
			return err
		}
		if err := requireMCPInputStrings(item, path, "id", "server_label", "name"); err != nil {
			return err
		}
		_, err := requiredInputString(item, "arguments", path, true)
		return err
	case "mcp_approval_response":
		if err := rejectUnsupportedInputKeys(item, path, "type", "id", "approval_request_id", "approve", "reason"); err != nil {
			return err
		}
		if err := requireMCPInputStrings(item, path, "approval_request_id"); err != nil {
			return err
		}
		var approve bool
		if err := sonic.Unmarshal(item["approve"], &approve); err != nil {
			return invalidRequest(path + ".approve must be a boolean")
		}
		return optionalMCPInputStrings(item, path, "id", "reason")
	default:
		return invalidRequest(path + ".type is not supported")
	}
}

func requireMCPInputStrings(item map[string]json.RawMessage, path string, keys ...string) error {
	for _, key := range keys {
		if _, err := requiredInputString(item, key, path, false); err != nil {
			return err
		}
	}
	return nil
}

func optionalMCPInputStrings(item map[string]json.RawMessage, path string, keys ...string) error {
	for _, key := range keys {
		if raw := item[key]; rawJSONValueSet(raw) {
			if _, ok := rawStringValue(raw); !ok {
				return invalidRequest(path + "." + key + " must be a string")
			}
		}
	}
	return nil
}

func isResponsesMCPItemType(itemType string) bool {
	switch schemas.ResponsesMessageType(itemType) {
	case schemas.ResponsesMessageTypeMCPListTools, schemas.ResponsesMessageTypeMCPCall,
		schemas.ResponsesMessageTypeMCPApprovalRequest, schemas.ResponsesMessageTypeMCPApprovalResponses:
		return true
	default:
		return false
	}
}

// validateProviderResponsesMCPItem checks an MCP output item: a listing, a call or an
// approval request from a server that the request declared and tool_choice allows.
func validateProviderResponsesMCPItem(state *State, item *schemas.ResponsesMessage, observed *providerResponsesItem) error {
	tool := item.ResponsesToolMessage
	if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil || tool == nil ||
		tool.ServerLabel == nil || !providerResponsesMCPServerAllowed(state, *tool.ServerLabel) {
		return ErrProviderResponseMalformed
	}
	if tool.CallID != nil || tool.Namespace != nil || tool.Execution != nil || tool.Async != nil || tool.Action != nil ||
		tool.Caller != nil || tool.ToolsetName != nil || tool.ItemCaller != nil || tool.CreatedBy != nil ||
		tool.ResponsesFileSearchToolCall != nil || tool.ResponsesComputerToolCall != nil ||
		tool.ResponsesComputerToolCallOutput != nil || tool.ResponsesCodeInterpreterToolCall != nil ||
		tool.ResponsesCustomToolCall != nil || tool.ResponsesImageGenerationCall != nil ||
		tool.ResponsesShellCall != nil || tool.ResponsesApplyPatchCall != nil || tool.ResponsesAdvisorCall != nil ||
		tool.ResponsesToolSearchCall != nil || tool.ResponsesWebFetchCall != nil || tool.ResponsesCodeExecutionCall != nil {
		return ErrProviderResponseMalformed
	}
	switch *item.Type {
	case schemas.ResponsesMessageTypeMCPListTools:
		if tool.Name != nil || tool.Arguments != nil || tool.Output != nil ||
			tool.ResponsesMCPApprovalResponse != nil || tool.ResponsesMCPListTools == nil ||
			len(tool.ResponsesMCPListTools.Tools) > maxProviderResponseItems || !validMCPListError(tool.Error) {
			return ErrProviderResponseMalformed
		}
		for _, listed := range tool.ResponsesMCPListTools.Tools {
			if !validProviderText(listed.Name, maxProviderResponseBodySize, false) ||
				!validOptionalProviderText(listed.Description, maxProviderResponseBodySize, true) {
				return ErrProviderResponseMalformed
			}
		}
		return nil
	case schemas.ResponsesMessageTypeMCPApprovalRequest:
		if tool.Output != nil || tool.Error != nil || tool.ResponsesMCPListTools != nil ||
			tool.ResponsesMCPApprovalResponse != nil || !validMCPCallNameAndArguments(tool) {
			return ErrProviderResponseMalformed
		}
		observed.name = *tool.Name
		return recordProviderResponsesMCPApprovalRequest(state, observed.id)
	case schemas.ResponsesMessageTypeMCPCall:
		if tool.ResponsesMCPListTools != nil || !validMCPCallNameAndArguments(tool) ||
			tool.Output != nil && (tool.Output.ResponsesToolCallOutputStr == nil ||
				tool.Output.ResponsesFunctionToolCallOutputBlocks != nil || tool.Output.ResponsesComputerToolCallOutput != nil ||
				tool.Output.ResponsesShellCallOutput != nil ||
				!validProviderText(*tool.Output.ResponsesToolCallOutputStr, maxProviderResponseBodySize, true)) ||
			!validMCPCallError(tool.Error) || !validMCPCallApproval(tool.ResponsesMCPApprovalResponse) {
			return ErrProviderResponseMalformed
		}
		observed.name = *tool.Name
		return validateAndRecordProviderResponsesToolCall(state, item, observed, false)
	default:
		return ErrProviderResponseMalformed
	}
}

func validMCPCallNameAndArguments(tool *schemas.ResponsesToolMessage) bool {
	return tool.Name != nil && validProviderText(*tool.Name, maxProviderResponseBodySize, false) &&
		tool.Arguments != nil && (*tool.Arguments == "" || catalog.ValidateJSONObjectText(*tool.Arguments))
}

func validMCPListError(value *schemas.ResponsesToolMessageError) bool {
	return value == nil || value.ResponsesToolMessageErrorStruct == nil && value.ResponsesToolMessageErrorStr != nil &&
		validProviderText(*value.ResponsesToolMessageErrorStr, maxProviderResponseBodySize, true)
}

func validMCPCallError(value *schemas.ResponsesToolMessageError) bool {
	switch {
	case value == nil:
		return true
	case value.ResponsesToolMessageErrorStr != nil:
		return value.ResponsesToolMessageErrorStruct == nil &&
			validProviderText(*value.ResponsesToolMessageErrorStr, maxProviderResponseBodySize, true)
	case value.ResponsesToolMessageErrorStruct != nil:
		failure := value.ResponsesToolMessageErrorStruct
		return validProviderText(failure.Type, 256, false) &&
			validOptionalProviderText(failure.Message, maxProviderResponseBodySize, true) &&
			len(failure.Content) <= maxProviderResponseBodySize
	default:
		return false
	}
}

// A call that ran after an approval names it. The approval's own fields stay empty.
func validMCPCallApproval(approval *schemas.ResponsesMCPApprovalResponse) bool {
	return approval == nil || !approval.Approve && approval.Reason == nil &&
		validProviderResponseID(approval.ApprovalRequestID)
}

// recordProviderResponsesMCPApprovalRequest counts an approval request once as the tool call
// that a required tool_choice asks for. No call ran, so it is not a hosted tool call.
func recordProviderResponsesMCPApprovalRequest(state *State, id string) error {
	if state == nil {
		return nil
	}
	if state.responsesToolCallIDs == nil {
		state.responsesToolCallIDs = make(map[string]string)
	}
	if prior, seen := state.responsesToolCallIDs[id]; seen {
		if prior != id {
			return ErrProviderResponseMalformed
		}
		return nil
	}
	state.responsesToolCallIDs[id] = id
	state.responsesDeclaredCalls++
	return nil
}

func providerResponsesMCPServerAllowed(state *State, label string) bool {
	return providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeMCP) && state.providerTools().mcp[label]
}

// validateProviderResponsesMCPEvent follows the lifecycle events of a listing or a call. Each
// may be absent, but none may repeat or come after the item's end.
func validateProviderResponsesMCPEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if state == nil || response == nil || response.OutputIndex == nil {
		return ErrProviderResponseMalformed
	}
	item, ok := state.responsesItems[*response.OutputIndex]
	if !ok || item.done {
		return ErrProviderResponseMalformed
	}
	switch response.Type {
	case schemas.ResponsesStreamResponseTypeMCPListToolsInProgress, schemas.ResponsesStreamResponseTypeMCPCallInProgress:
		if item.stage != 0 {
			return ErrProviderResponseMalformed
		}
		item.stage = 1
	case schemas.ResponsesStreamResponseTypeMCPListToolsCompleted, schemas.ResponsesStreamResponseTypeMCPListToolsFailed,
		schemas.ResponsesStreamResponseTypeMCPCallCompleted, schemas.ResponsesStreamResponseTypeMCPCallFailed:
		if item.stage > 1 {
			return ErrProviderResponseMalformed
		}
		item.stage = 2
	default:
		return ErrProviderResponseMalformed
	}
	state.responsesItems[*response.OutputIndex] = item
	return nil
}

// validateProviderResponsesMCPArgumentsEvent collects a call's streamed arguments. A call that
// runs after an approval can arrive with its arguments already set and stream none.
func validateProviderResponsesMCPArgumentsEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if state == nil || response == nil || response.OutputIndex == nil {
		return ErrProviderResponseMalformed
	}
	item, ok := state.responsesItems[*response.OutputIndex]
	if !ok || item.done || item.valueDone {
		return ErrProviderResponseMalformed
	}
	switch response.Type {
	case schemas.ResponsesStreamResponseTypeMCPCallArgumentsDelta:
		if response.Delta == nil || !validProviderText(*response.Delta, maxProviderResponseBodySize, true) ||
			!validOptionalProviderText(response.Obfuscation, maxProviderResponseBodySize, false) {
			return ErrProviderResponseMalformed
		}
		if item.value == nil {
			item.value = &bytes.Buffer{}
		}
		if !appendProviderBuffer(item.value, *response.Delta) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesStreamResponseTypeMCPCallArgumentsDone:
		if response.Arguments == nil || *response.Arguments != "" && !catalog.ValidateJSONObjectText(*response.Arguments) ||
			item.value != nil && item.value.String() != *response.Arguments {
			return ErrProviderResponseMalformed
		}
		if item.value == nil {
			item.value = bytes.NewBufferString(*response.Arguments)
		}
		item.valueDone = true
	default:
		return ErrProviderResponseMalformed
	}
	state.responsesItems[*response.OutputIndex] = item
	return nil
}

// validateProviderResponsesCompletedMCPItem ends a streamed MCP item. Streamed arguments must
// be complete and match the call's final arguments.
func validateProviderResponsesCompletedMCPItem(streamItem providerResponsesItem, finalItem *schemas.ResponsesMessage) error {
	if streamItem.itemType != schemas.ResponsesMessageTypeMCPCall || streamItem.value == nil {
		return nil
	}
	if !streamItem.valueDone || finalItem == nil || finalItem.ResponsesToolMessage == nil ||
		finalItem.ResponsesToolMessage.Arguments == nil || *finalItem.ResponsesToolMessage.Arguments != streamItem.value.String() {
		return ErrProviderResponseMalformed
	}
	return nil
}

// omitResponsesMCPCredentials removes the credentials of each MCP tool from a copy of the
// request that the client gets back. The client sent them, and the echo need not repeat them.
func omitResponsesMCPCredentials(tools []schemas.ResponsesTool) []schemas.ResponsesTool {
	for index := range tools {
		if tools[index].Type == schemas.ResponsesToolTypeMCP && tools[index].ResponsesToolMCP != nil {
			server := *tools[index].ResponsesToolMCP
			server.Authorization = nil
			server.Headers = nil
			tools[index].ResponsesToolMCP = &server
		}
	}
	return tools
}
