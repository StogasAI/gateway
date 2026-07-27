package stogas

import (
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

type contextKey string

const stateContextKey contextKey = "stogas.state"

// GatewayVersion is populated by release builds. Development builds remain
// explicit rather than pretending to be a published release.
var GatewayVersion = "dev"

type State struct {
	Resolution            *catalog.ResolvedRequest
	Adapter               Adapter
	Signals               Signals
	Hold                  HoldEstimate
	RawAPIKey             string
	APIKeyClaims          *billing.APIKeyClaims
	Authorization         *billing.Authorization
	BillingFinalized      bool
	SingleUseRequestID    bool
	RequestLifetime       time.Duration
	RequestID             string
	StartedAt             time.Time
	RequestType           string
	Model                 string
	Response              *schemas.BifrostResponse
	BifrostError          *schemas.BifrostError
	FinalCostUSDAtoms     string
	FinalMeters           []catalog.MeterEstimate
	ProviderStartedAt     time.Time
	ProviderCompletedAt   time.Time
	ProviderFirstOutputMS *uint32
	Cancelled             bool
	GatewayVersion        string
	GatewayNodeID         string

	ProviderResponseHeaders map[string]string
}

type HoldEstimate struct {
	MaxUSDAtoms string
	ProductKey  string
	ProviderKey string
	Meters      []catalog.MeterEstimate
}

func NewState(resolution *catalog.ResolvedRequest, rawAPIKey string, claims *billing.APIKeyClaims, adapter Adapter) *State {
	return &State{
		Resolution:     resolution,
		Adapter:        adapter,
		RawAPIKey:      rawAPIKey,
		APIKeyClaims:   claims,
		GatewayVersion: GatewayVersion,
	}
}

func (s *State) MarkProviderStarted() {
	if s == nil || !s.ProviderStartedAt.IsZero() {
		return
	}
	s.ProviderStartedAt = time.Now()
}

func (s *State) MarkProviderCompleted() {
	if s == nil || !s.ProviderCompletedAt.IsZero() {
		return
	}
	s.ProviderCompletedAt = time.Now()
}

// ObserveProviderFirstOutput records the gateway-observed elapsed provider call
// time until Bifrost yields the first usable output. Provider latency metadata
// is only a fallback for paths that predate the outer provider clock.
func (s *State) ObserveProviderFirstOutput(latencyMS int64) {
	if s == nil || s.ProviderFirstOutputMS != nil {
		return
	}
	if !s.ProviderStartedAt.IsZero() {
		latencyMS = time.Since(s.ProviderStartedAt).Milliseconds()
	}
	if latencyMS < 0 {
		return
	}
	value := uint32(latencyMS)
	if latencyMS > int64(^uint32(0)) {
		value = ^uint32(0)
	}
	s.ProviderFirstOutputMS = &value
}

func (s *State) ObserveChatProviderOutput(response *schemas.BifrostChatResponse) {
	if !chatResponseHasOutput(response) {
		return
	}
	s.ObserveProviderFirstOutput(response.ExtraFields.Latency)
}

func (s *State) ObserveResponsesProviderOutput(response *schemas.BifrostResponsesStreamResponse) {
	if !responsesEventHasOutput(response) {
		return
	}
	s.ObserveProviderFirstOutput(response.ExtraFields.Latency)
}

func chatResponseHasOutput(response *schemas.BifrostChatResponse) bool {
	if response == nil {
		return false
	}
	for _, choice := range response.Choices {
		if choice.FinishReason != nil {
			return true
		}
		stream := choice.ChatStreamResponseChoice
		if stream == nil || stream.Delta == nil {
			continue
		}
		delta := stream.Delta
		if nonEmptyString(delta.Content) ||
			nonEmptyString(delta.Refusal) ||
			nonEmptyString(delta.Reasoning) ||
			delta.Audio != nil ||
			len(delta.ReasoningDetails) > 0 ||
			len(delta.ToolCalls) > 0 {
			return true
		}
	}
	return false
}

func responsesEventHasOutput(response *schemas.BifrostResponsesStreamResponse) bool {
	if response == nil {
		return false
	}
	switch response.Type {
	case schemas.ResponsesStreamResponseTypePing,
		schemas.ResponsesStreamResponseTypeCreated,
		schemas.ResponsesStreamResponseTypeInProgress,
		schemas.ResponsesStreamResponseTypeQueued:
		return false
	default:
		return true
	}
}

func nonEmptyString(value *string) bool {
	return value != nil && *value != ""
}

func SetState(ctx *schemas.BifrostContext, state *State) {
	if ctx == nil || state == nil {
		return
	}
	ctx.SetValue(stateContextKey, state)
}

func StateFrom(ctx *schemas.BifrostContext) (*State, bool) {
	if ctx == nil {
		return nil, false
	}
	state, ok := ctx.Value(stateContextKey).(*State)
	return state, ok && state != nil
}
