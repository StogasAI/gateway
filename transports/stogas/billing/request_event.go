package billing

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

// ProviderAttempt is one provider call. ProviderRequestID is the ID from the provider's response
// headers, which its support asks for. ProviderResponseID is the ID of the provider's reply, which
// the client also received. ProviderModel is the model that the provider reported serving.
// ProviderInstanceID names the provider's machine that ran the call where the provider names one:
// the Chutes instance, by which with the call's time Chutes's records find an encrypted call.
// ProviderEncryptionKey is the SHA-256 of that instance's attested key, which the gateway
// encrypted the call to. ProviderMeasurement is the SHA-256 of the registers of the measurement
// in the provider's published list that the instance's attestation matched, which a reader can
// compute from that list; the provider's name and version for it are labels that nothing checks.
type ProviderAttempt struct {
	CatalogChainHash         string  `json:"catalog_chain_hash"`
	ResolvedCatalogChainHash string  `json:"resolved_catalog_chain_hash,omitempty"`
	Provider                 string  `json:"provider"`
	Status                   string  `json:"status"`
	StatusCode               *int    `json:"status_code"`
	ErrorCode                string  `json:"error_code,omitempty"`
	StartMS                  uint32  `json:"start_ms"`
	LatencyMS                uint32  `json:"latency_ms"`
	OutputObserved           bool    `json:"output_observed"`
	ProviderRequestID        string  `json:"provider_request_id"`
	ProviderResponseID       string  `json:"provider_response_id"`
	ProviderModel            string  `json:"provider_model"`
	ProviderInstanceID       string  `json:"provider_instance_id,omitempty"`
	ProviderEncryptionKey    string  `json:"provider_encryption_key_sha256,omitempty"`
	ProviderMeasurement      string  `json:"provider_measurement_sha256,omitempty"`
	FinishReason             string  `json:"finish_reason"`
	Byok                     *string `json:"byok"`
	// AccountOptions are the options of the credential's provider account that changed the facts
	// of the call.
	AccountOptions []HeldOption `json:"account_options,omitempty"`
}

// RequestPerformance records the request's own times on the request clock.
// Provider attempts hold the provider calls' starts and durations.
type RequestPerformance struct {
	TotalMS uint32 `json:"total_ms"`
	// RateLimitWaitMS is how long the platform request rate held the first
	// provider call, which starts when the wait ends.
	RateLimitWaitMS uint32  `json:"rate_limit_wait_ms"`
	FirstOutputMS   *uint32 `json:"first_output_ms"`
	TTFTMS          *uint32 `json:"ttft_ms"`
	// ToolCalls are the response's first tool calls in output order, and AnsweredCalls hash
	// the calls that the request's input answers after the latest model turn. A later
	// request's AnsweredCalls name the calls of this one that its client ran.
	ToolCalls     []ToolCall `json:"tool_calls,omitempty"`
	AnsweredCalls []string   `json:"answered_calls,omitempty"`
}

type EventError struct {
	Code   string `json:"code"`
	Status int    `json:"status"`
	RefusedLimit
}

const RequestLogSchemaVersion uint8 = 1

type RequestEvent struct {
	SchemaVersion  uint8       `json:"schema_version"`
	RequestID      string      `json:"request_id"`
	CreatedAt      string      `json:"created_at"`
	LastRequestAt  string      `json:"last_request_at"`
	RequestCount   uint32      `json:"request_count"`
	GatewayError   *EventError `json:"gateway_error"`
	APIKeyID       string      `json:"api_key_id"`
	GrantID        *string     `json:"grant_id"`
	MemberID       string      `json:"member_id"`
	OrganizationID string      `json:"organization_id"`
	// Interface is the API that the client called, spelled as route.interfaces and
	// policies spell it.
	Interface string `json:"interface"`
	// Stream is true when the request body asked for a stream.
	Stream           bool              `json:"stream"`
	RequestSettings  RequestSettings   `json:"request_settings"`
	SessionID        string            `json:"session_id"`
	TraceID          string            `json:"trace_id"`
	EncryptionKeyIDs []string          `json:"encryption_key_ids"`
	Metadata         map[string]string `json:"metadata"`
	// AppTitle and AppURL name the application that sent the request, as its attribution
	// headers give it; each is empty when absent.
	AppTitle string `json:"app_title"`
	AppURL   string `json:"app_url"`
	// AgentID names the agent of the session that sent the request, empty for the main
	// conversation; ParentAgentID names the agent that started it, empty for the main
	// conversation; AgentName is the agent's kind or name, empty when the client sends none.
	AgentID          string                `json:"agent_id"`
	ParentAgentID    string                `json:"parent_agent_id"`
	AgentName        string                `json:"agent_name"`
	Transport        string                `json:"transport"`
	ClientStopMS     *uint32               `json:"client_stop_ms"`
	CatalogVersion   *uint64               `json:"catalog_version"`
	PolicyVersions   *LoggedPolicyVersions `json:"policy_versions"`
	ProviderAttempts []ProviderAttempt     `json:"provider_attempts"`
	NodeID           string                `json:"node_id"`
	Performance      RequestPerformance    `json:"performance"`
	Usage            RequestUsage          `json:"usage"`
	Plugins          plugins.Metrics       `json:"plugins,omitzero"`
	GatewayVersion   string                `json:"gateway_version"`
	// LogBatch names the signed batch that holds this row and the row's leaf in it, or
	// is null when no boot key signs the gateway's rows.
	LogBatch *LogPosition `json:"log_batch"`
	// ReceiptCommitments are those of the receipt that answered the request, when the
	// caller asked for one. They match the receipt in the response's Stogas metadata.
	ReceiptCommitments *ReceiptCommitments `json:"receipt_commitments"`
}

// Outcome is how the request ended, as Analytics groups requests: the
// gateway_request_hours rollup in ClickHouse derives the same value from the
// same fields.
func (e *RequestEvent) Outcome() string {
	status := ""
	if n := len(e.ProviderAttempts); n > 0 {
		status = e.ProviderAttempts[n-1].Status
	}
	failed := e.GatewayError != nil && e.GatewayError.Code != ""
	switch {
	case failed && len(e.ProviderAttempts) == 0:
		return "rejected"
	case failed:
		return "failed"
	case e.ClientStopMS != nil:
		return "cancelled"
	case status == "" || status == "unknown":
		return "unknown"
	case status == "success":
		return "success"
	}
	return "failed"
}

// LogPosition is a row's place in its boot's signed log batches.
type LogPosition struct {
	Sequence uint32 `json:"sequence"`
	Index    uint32 `json:"index"`
}

// ReceiptCommitments are the lowercase hex commitments that a receipt signs.
type ReceiptCommitments struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

// RequestSettings records the settings that control what the model generates,
// as the gateway prepared them for the provider. It never holds content, tool
// definitions, identifiers or metadata. The request type records streaming, the
// deployment chain records service tier, speed, region and reasoning mode, and
// usage records caching. Clients choose these values, so the log leaves out a
// value that is long, not printable ASCII, or an integer JavaScript would round.
type RequestSettings struct {
	MaxOutputTokens    *int     `json:"max_output_tokens,omitempty"`
	ReasoningEnabled   *bool    `json:"reasoning_enabled,omitempty"`
	ReasoningEffort    string   `json:"reasoning_effort,omitempty"`
	ReasoningMaxTokens *int     `json:"reasoning_max_tokens,omitempty"`
	ReasoningSummary   string   `json:"reasoning_summary,omitempty"`
	ReasoningDisplay   string   `json:"reasoning_display,omitempty"`
	TaskBudgetTokens   *int     `json:"task_budget_tokens,omitempty"`
	Temperature        *float64 `json:"temperature,omitempty"`
	TopP               *float64 `json:"top_p,omitempty"`
	TopK               *int     `json:"top_k,omitempty"`
	FrequencyPenalty   *float64 `json:"frequency_penalty,omitempty"`
	PresencePenalty    *float64 `json:"presence_penalty,omitempty"`
	RepetitionPenalty  *float64 `json:"repetition_penalty,omitempty"`
	Seed               *int     `json:"seed,omitempty"`
	Logprobs           *bool    `json:"logprobs,omitempty"`
	TopLogprobs        *int     `json:"top_logprobs,omitempty"`
	Verbosity          string   `json:"verbosity,omitempty"`
	ResponseFormat     string   `json:"response_format,omitempty"`
	Include            []string `json:"include,omitempty"`
	ToolChoice         string   `json:"tool_choice,omitempty"`
	ParallelToolCalls  *bool    `json:"parallel_tool_calls,omitempty"`
	MaxToolCalls       *int     `json:"max_tool_calls,omitempty"`
	Truncation         string   `json:"truncation,omitempty"`
	// The OpenAI cyber access program that the gateway sent.
	CyberAccessProgram string `json:"cyber_access_program,omitempty"`
	// HostedTools are the hosted tools that the request let the model call, whose data
	// handling joined the deployment's.
	HostedTools []string `json:"hosted_tools,omitempty"`
	// PromptCaching is the lifetime of the cache entries that the gateway's cache marks asked
	// for, because the request marked nothing to cache.
	PromptCaching string `json:"prompt_caching,omitempty"`
	// ProviderState names the fields that kept or read state in the customer's provider account:
	// store when the provider got store: true, previous_response_id, conversation,
	// vector_store_ids when a file search read vector stores, container when the request let code
	// interpreter or a hosted shell run in one, and image_generation_call when the input sent back
	// a generated image by its ID.
	ProviderState []string `json:"provider_state,omitempty"`
}

// A request's metadata follows OpenAI's: up to 16 pairs, with keys up to 64
// bytes and values up to 512 bytes. A session ID follows OpenRouter's limit of
// 256 characters, counted in bytes.
const (
	MaxMetadataEntries    = 16
	MaxMetadataKeyBytes   = 64
	MaxMetadataValueBytes = 512
	MaxSessionIDBytes     = 256
)

const (
	// Provider settings are short words, and an include list names a few
	// response parts, so these bounds keep the settings far below the log limit.
	maxSettingBytes  = 64
	maxSettingValues = 16
	// maxExactJSONInteger is the largest integer that JavaScript reads exactly.
	maxExactJSONInteger = 1<<53 - 1
)

func ChatRequestSettings(params *schemas.ChatParameters) RequestSettings {
	if params == nil {
		return RequestSettings{}
	}
	settings := RequestSettings{
		MaxOutputTokens:   settingInt(params.MaxCompletionTokens),
		Temperature:       settingValue(params.Temperature),
		TopP:              settingValue(params.TopP),
		TopK:              settingInt(params.TopK),
		FrequencyPenalty:  settingValue(params.FrequencyPenalty),
		PresencePenalty:   settingValue(params.PresencePenalty),
		Seed:              settingInt(params.Seed),
		Logprobs:          settingValue(params.LogProbs),
		TopLogprobs:       settingInt(params.TopLogProbs),
		Verbosity:         settingText(derefString(params.Verbosity)),
		ParallelToolCalls: settingValue(params.ParallelToolCalls),
	}
	if reasoning := params.Reasoning; reasoning != nil {
		settings.ReasoningEnabled = settingValue(reasoning.Enabled)
		settings.ReasoningEffort = settingText(derefString(reasoning.Effort))
		settings.ReasoningMaxTokens = settingInt(reasoning.MaxTokens)
		settings.ReasoningDisplay = settingText(derefString(reasoning.Display))
	}
	if params.TaskBudget != nil {
		settings.TaskBudgetTokens = settingInt(&params.TaskBudget.Total)
	}
	if params.ResponseFormat != nil {
		format, _ := (*params.ResponseFormat).(map[string]any)
		formatType, _ := format["type"].(string)
		settings.ResponseFormat = settingText(formatType)
	}
	if choice := params.ToolChoice; choice != nil {
		if choice.ChatToolChoiceStruct != nil {
			settings.ToolChoice = settingText(string(choice.ChatToolChoiceStruct.Type))
		} else {
			settings.ToolChoice = settingText(derefString(choice.ChatToolChoiceStr))
		}
	}
	addExtraSettings(&settings, params.ExtraParams)
	return settings
}

func ResponsesRequestSettings(params *schemas.ResponsesParameters) RequestSettings {
	if params == nil {
		return RequestSettings{}
	}
	settings := RequestSettings{
		MaxOutputTokens:   settingInt(params.MaxOutputTokens),
		Temperature:       settingValue(params.Temperature),
		TopP:              settingValue(params.TopP),
		FrequencyPenalty:  settingValue(params.FrequencyPenalty),
		PresencePenalty:   settingValue(params.PresencePenalty),
		TopLogprobs:       settingInt(params.TopLogProbs),
		Include:           settingTexts(params.Include),
		ParallelToolCalls: settingValue(params.ParallelToolCalls),
		MaxToolCalls:      settingInt(params.MaxToolCalls),
		Truncation:        settingText(derefString(params.Truncation)),
	}
	if reasoning := params.Reasoning; reasoning != nil {
		settings.ReasoningEffort = settingText(derefString(reasoning.Effort))
		settings.ReasoningMaxTokens = settingInt(reasoning.MaxTokens)
		settings.ReasoningSummary = settingText(derefString(reasoning.Summary))
	}
	if text := params.Text; text != nil {
		settings.Verbosity = settingText(derefString(text.Verbosity))
		if text.Format != nil {
			settings.ResponseFormat = settingText(text.Format.Type)
		}
	}
	if choice := params.ToolChoice; choice != nil {
		if choice.ResponsesToolChoiceStruct != nil {
			settings.ToolChoice = settingText(string(choice.ResponsesToolChoiceStruct.Type))
		} else {
			settings.ToolChoice = settingText(derefString(choice.ResponsesToolChoiceStr))
		}
	}
	addExtraSettings(&settings, params.ExtraParams)
	return settings
}

// addExtraSettings reads the settings that Bifrost keeps as extra parameters:
// top_k and task_budget on Responses, and the reasoning and repetition penalty
// that the gateway sends to Chutes in its own fields.
func addExtraSettings(settings *RequestSettings, extra map[string]any) {
	if effort, ok := extra["reasoning_effort"].(string); ok {
		settings.ReasoningEffort = settingText(effort)
	}
	if template, ok := extra["chat_template_kwargs"].(map[string]any); ok {
		if thinking, ok := template["enable_thinking"].(bool); ok {
			settings.ReasoningEnabled = &thinking
		}
	}
	if budget, ok := extra["task_budget"].(map[string]any); ok {
		settings.TaskBudgetTokens = extraInt(budget["total"])
	}
	if topK := extraInt(extra["top_k"]); topK != nil {
		settings.TopK = topK
	}
	if penalty, ok := extra["repetition_penalty"].(float64); ok {
		settings.RepetitionPenalty = &penalty
	}
}

// extraInt reads an integer extra parameter: decoded JSON holds float64, and
// values the gateway sets hold int.
func extraInt(value any) *int {
	switch value := value.(type) {
	case float64:
		if value != math.Trunc(value) || math.Abs(value) > maxExactJSONInteger {
			return nil
		}
		number := int(value)
		return &number
	case int:
		return settingInt(&value)
	}
	return nil
}

// settingValue copies a setting, so later changes to the request never reach
// the log.
func settingValue[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func settingInt(value *int) *int {
	if value == nil || *value > maxExactJSONInteger || *value < -maxExactJSONInteger {
		return nil
	}
	return settingValue(value)
}

func settingText(value string) string {
	return boundedTelemetryValue(value, maxSettingBytes)
}

func settingTexts(values []string) []string {
	if len(values) > maxSettingValues {
		return nil
	}
	for _, value := range values {
		if value == "" || settingText(value) != value {
			return nil
		}
	}
	return slices.Clone(values)
}

type RequestUsage struct {
	UpstreamCostUSD       string      `json:"upstream_cost_usd"`
	BilledCostUSD         string      `json:"billed_cost_usd"`
	CacheReadSavingsUSD   *string     `json:"cache_read_savings_usd,omitempty"`
	CacheWriteOverheadUSD *string     `json:"cache_write_overhead_usd,omitempty"`
	Meters                EventMeters `json:"meters"`
}

type EventMeter struct {
	Quantity string  `json:"quantity"`
	RateKey  *string `json:"rateKey,omitempty"`
	RateUSD  *string `json:"rateUsd,omitempty"`
	USD      *string `json:"usd,omitempty"`
}

type EventMeters map[string]EventMeter

// The largest log the contract allows is about 80 KiB. Postgres checks its text,
// with the hold binding, against 128 KiB. That text adds a space after each
// colon and comma, which can make it half as long again, and writes a number
// in exponent notation in full, up to 327 bytes for each decimal setting, so
// 84 KiB is the most that stays within the check.
const requestLogMaxEventBytes = 84 * 1024

// encodeRequestRow encodes a row as analytics stores it. It writes missing meters into the
// event as the empty object that the row holds, so an export of the event matches the row.
func encodeRequestRow(event *RequestEvent) (string, error) {
	if event.SchemaVersion != RequestLogSchemaVersion {
		return "", fmt.Errorf("unsupported request log schema version: %d", event.SchemaVersion)
	}
	if event.Usage.Meters == nil {
		event.Usage.Meters = EventMeters{}
	}
	// HTML escaping would write <, > and & in client metadata as six bytes.
	var encoded strings.Builder
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(event); err != nil {
		return "", fmt.Errorf("marshal request log: %w", err)
	}
	row := strings.TrimSuffix(encoded.String(), "\n")
	if len(row) > requestLogMaxEventBytes {
		return "", fmt.Errorf("request log is %d bytes, limit is %d", len(row), requestLogMaxEventBytes)
	}
	return row, nil
}

// withHoldParamsHash adds the hold binding to an encoded row. Settlement checks and removes
// it before the row reaches customer history, so the row that analytics stores is the one
// whose leaf its batch signs.
func withHoldParamsHash(row string, holdParamsHash string) string {
	hash, _ := json.Marshal(holdParamsHash)
	return row[:len(row)-1] + `,"hold_params_hash":` + string(hash) + "}"
}
