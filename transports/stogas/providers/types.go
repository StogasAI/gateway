package providers

import (
	"encoding/json"
	"errors"

	"github.com/maximhq/bifrost/core/schemas"
)

const (
	RouteChat      Route = "chat-completions"
	RouteResponses Route = "responses"

	MeterInputTokens       = "input_tokens"
	MeterCachedInputTokens = "cached_input_tokens"
	MeterOutputTokens      = "output_tokens"

	RatePerMillionTokens         = "per_mill_tokens"
	RatePerMillionContextLTE272K = "per_mill_context_lte_272k"
	RatePerMillionContextGT272K  = "per_mill_context_gt_272k"
	RatePerThousandCalls         = "per_1k_calls"

	LongContextThresholdTokens = 272000
	MillionTokens              = 1000000
	ThousandCalls              = 1000
)

var (
	ErrUnsupportedTool         = errors.New("unsupported provider tool")
	ErrUnsupportedParameter    = errors.New("unsupported provider parameter")
	ErrUnsupportedInput        = errors.New("unsupported provider input")
	ErrOutputTokenLimitTooLow  = errors.New("output token limit is below provider minimum")
	ErrProviderContainers      = errors.New("provider containers are not supported")
	ErrInvalidProviderToolSpec = errors.New("invalid provider tool specification")
)

type Route string

type Pricing map[string]map[string]string

type ProfileDescription struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Denies  []string `json:"denies,omitempty"`
	Allows  []string `json:"allows,omitempty"`
}

type Profile struct {
	Description ProfileDescription
}

type Parameter struct {
	Alias             string       `json:"alias"`
	DeleteAttribute   bool         `json:"deleteAttribute"`
	ImplyValue        any          `json:"implyValue"`
	Max               *float64     `json:"max"`
	Min               *float64     `json:"min"`
	OverrideAttribute bool         `json:"overrideAttribute"`
	Reject            []RejectRule `json:"reject"`
	RejectConflict    bool         `json:"rejectConflict"`
	RejectUnsupported string       `json:"rejectUnsupported"`
	Type              string       `json:"type"`
	Values            []string     `json:"values"`
}

type RejectRule struct {
	AllowedKeys  []string `json:"allowedKeys"`
	Exists       bool     `json:"exists"`
	Missing      bool     `json:"missing"`
	Path         string   `json:"path"`
	Prefixes     []string `json:"prefixes"`
	RequiredKeys []string `json:"requiredKeys"`
	Values       []any    `json:"values"`
	ValuesExcept []any    `json:"valuesExcept"`
}

type Deployment struct {
	Model               string
	ContextWindowTokens int
	Pricing             Pricing
	ReasoningSupported  bool
}

type RequestContext struct {
	Route               Route
	Model               string
	Deployment          Deployment
	OutputTokenLimit    int
	HasWebSearchOptions bool
	SearchContextSize   string
	ToolsParseFailed    bool
	RawBody             map[string]json.RawMessage
	ToolTypes           []string
	RawTools            []map[string]json.RawMessage
}

type HeaderContext struct {
	Provider schemas.ModelProvider
	Model    string
	Route    Route
	Header   string
}

type MeterEstimate struct {
	MeterKey       string
	RateKey        string
	Quantity       string
	AmountUSDAtoms string
	HoldRequired   bool
}

type Adapter interface {
	ValidateRequest(RequestContext) error
	ExtraHoldMeters(RequestContext, int, int) []MeterEstimate
	ExtraSettlementMeters(RequestContext) []MeterEstimate
	AllowUpstreamRequestHeader(HeaderContext) bool
	FilterProviderResponseHeaders(HeaderContext, map[string]string) map[string]string
}
