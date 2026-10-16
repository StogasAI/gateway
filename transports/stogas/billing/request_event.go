package billing

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

type ProviderAttempt struct {
	CatalogChainHash         string  `json:"catalog_chain_hash"`
	ResolvedCatalogChainHash string  `json:"resolved_catalog_chain_hash,omitempty"`
	Provider                 string  `json:"provider"`
	Status                   string  `json:"status"`
	StatusCode               *int    `json:"status_code"`
	StartMS                  uint32  `json:"start_ms"`
	LatencyMS                uint32  `json:"latency_ms"`
	OutputObserved           bool    `json:"output_observed"`
	ProviderRequestID        string  `json:"provider_request_id"`
	FinishReason             string  `json:"finish_reason"`
	Byok                     *string `json:"byok"`
}

// RequestPerformance records elapsed request and provider time.
// Provider attempts retain their own durations and outcomes.
type RequestPerformance struct {
	TotalMS         uint32  `json:"total_ms"`
	ProviderMS      uint32  `json:"provider_ms"`
	ProviderStartMS *uint32 `json:"provider_start_ms"`
	FirstOutputMS   *uint32 `json:"first_output_ms"`
	TTFTMS          *uint32 `json:"ttft_ms"`
}

type EventError struct {
	Code   string `json:"code"`
	Status int    `json:"status"`
}

const RequestLogSchemaVersion uint8 = 1

// How the client reached the gateway: ordinary TLS, TLS with the gateway's
// attestation evidence, or an end-to-end encrypted session.
const (
	TransportHTTPS       = "https"
	TransportAttestedTLS = "attested_tls"
	TransportE2EE        = "e2ee"
)

type RequestEvent struct {
	SchemaVersion        uint8              `json:"schema_version"`
	RequestID            string             `json:"request_id"`
	CreatedAt            string             `json:"created_at"`
	LastRequestAt        string             `json:"last_request_at"`
	RequestCount         uint32             `json:"request_count"`
	GatewayError         *EventError        `json:"gateway_error"`
	StogasAPIKeyID       string             `json:"stogas_api_key_id"`
	StogasGrantID        *string            `json:"stogas_grant_id"`
	StogasUserID         string             `json:"stogas_user_id"`
	StogasOrganizationID string             `json:"stogas_organization_id"`
	RequestType          string             `json:"request_type"`
	RequestSettings      RequestSettings    `json:"request_settings"`
	Metadata             map[string]string  `json:"metadata"`
	Transport            string             `json:"transport"`
	Cancelled            bool               `json:"cancelled"`
	ClientStopMS         *uint32            `json:"client_stop_ms"`
	CatalogVersion       *uint64            `json:"catalog_version"`
	PolicyVersions       *PolicyVersions    `json:"policy_versions"`
	ProviderAttempts     []ProviderAttempt  `json:"provider_attempts"`
	NodeID               string             `json:"node_id"`
	Performance          RequestPerformance `json:"performance"`
	Usage                RequestUsage       `json:"usage"`
	Plugins              plugins.Metrics    `json:"plugins,omitzero"`
	GatewayVersion       string             `json:"gateway_version"`
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
}

// A request's metadata follows OpenAI's: up to 16 pairs, with keys up to 64
// bytes and values up to 512 bytes.
const (
	MaxMetadataEntries    = 16
	MaxMetadataKeyBytes   = 64
	MaxMetadataValueBytes = 512
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
		summary := reasoning.Summary
		if summary == nil {
			summary = reasoning.GenerateSummary
		}
		settings.ReasoningSummary = settingText(derefString(summary))
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
// top_k and task_budget on Responses, and the output limit, reasoning and
// repetition penalty that the gateway sends to Chutes in its own fields.
func addExtraSettings(settings *RequestSettings, extra map[string]any) {
	if limit := extraInt(extra["max_tokens"]); limit != nil {
		settings.MaxOutputTokens = limit
	}
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
	UpstreamCostUSD       string             `json:"upstream_cost_usd"`
	BilledCostUSD         string             `json:"billed_cost_usd"`
	CacheReadSavingsUSD   *string            `json:"cache_read_savings_usd,omitempty"`
	CacheWriteOverheadUSD *string            `json:"cache_write_overhead_usd,omitempty"`
	Meters                EventMeters        `json:"meters"`
	StandardTextTokens    StandardTextTokens `json:"standard_text_tokens"`
}

// StandardTextTokens counts four visible UTF-8 bytes per unit. Unknown material,
// including opaque reasoning, is omitted; observed empty text is exactly zero.
type StandardTextTokens struct {
	Input     *string `json:"input,omitempty"`
	Reasoning *string `json:"reasoning,omitempty"`
	Output    *string `json:"output,omitempty"`
}

func standardTextTokens(meters EventMeters) StandardTextTokens {
	tokens := func(key string) *string {
		meter, known := meters[key]
		if !known {
			return nil
		}
		bytes, err := strconv.ParseUint(meter.Quantity, 10, 64)
		if err != nil {
			return nil
		}
		value := strconv.FormatUint(bytes/4, 10) + [4]string{"", ".25", ".5", ".75"}[bytes%4]
		return &value
	}
	return StandardTextTokens{Input: tokens(MeterInputTextBytes), Reasoning: tokens(MeterReasoningTextBytes), Output: tokens(MeterOutputTextBytes)}
}

type EventMeter struct {
	Quantity string  `json:"quantity"`
	RateKey  *string `json:"rateKey,omitempty"`
	RateUSD  *string `json:"rateUsd,omitempty"`
	USD      *string `json:"usd,omitempty"`
}

type EventMeters map[string]EventMeter

const requestLogMaxEventBytes = 64 * 1024

// settlementLog carries the hold binding, which settlement checks and removes
// before the log reaches customer history.
type settlementLog struct {
	RequestEvent
	HoldParamsHash string `json:"hold_params_hash"`
}

// encodeRequestLog encodes a request's log for settlement. Rejections have no
// hold and pass an empty hash.
func encodeRequestLog(event RequestEvent, holdParamsHash string) (string, error) {
	if event.SchemaVersion != RequestLogSchemaVersion {
		return "", fmt.Errorf("unsupported request log schema version: %d", event.SchemaVersion)
	}
	if event.Usage.Meters == nil {
		event.Usage.Meters = EventMeters{}
	}
	var log any = event
	if holdParamsHash != "" {
		log = settlementLog{event, holdParamsHash}
	}
	// HTML escaping would write <, > and & in client metadata as six bytes.
	var encoded strings.Builder
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(log); err != nil {
		return "", fmt.Errorf("marshal request log: %w", err)
	}
	payload := strings.TrimSuffix(encoded.String(), "\n")
	if len(payload) > requestLogMaxEventBytes {
		return "", fmt.Errorf("request log is %d bytes, limit is %d", len(payload), requestLogMaxEventBytes)
	}
	return payload, nil
}
