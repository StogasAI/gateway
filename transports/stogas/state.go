package stogas

import (
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

type contextKey string

const stateContextKey contextKey = "stogas.state"
const localDevReleaseMeasurement = "0000000000000000000000000000000000000000000000000000000000000000"

type State struct {
	Resolution        *catalog.ResolvedRequest
	Adapter           Adapter
	Signals           Signals
	Hold              HoldEstimate
	RawAPIKey         string
	APIKeyClaims      *billing.APIKeyClaims
	Authorization     *billing.Authorization
	BillingFinalized  bool
	RequestLifetime   time.Duration
	StartedAt         time.Time
	RequestType       string
	Model             string
	Response          *schemas.BifrostResponse
	BifrostError      *schemas.BifrostError
	FinalCostUSDAtoms string
	FinalMeters       []catalog.MeterEstimate
	FirstByteAt       time.Time
	ProviderTTFBMS    *uint32
	ReleaseMeasurement string

	ProviderResponseHeaders map[string]string
	ProcessedRequestJSON    []byte
}

type HoldEstimate struct {
	MaxUSDAtoms string
	ProductKey  string
	ProviderKey string
	Meters      []catalog.MeterEstimate
}

func NewState(resolution *catalog.ResolvedRequest, rawAPIKey string, claims *billing.APIKeyClaims, adapter Adapter) *State {
	return &State{
		Resolution:   resolution,
		Adapter:      adapter,
		RawAPIKey:    rawAPIKey,
		APIKeyClaims: claims,
		ReleaseMeasurement: localDevReleaseMeasurement,
	}
}

func ReleaseMeasurementForLog(measurement string) string {
	normalized := strings.ToLower(strings.TrimSpace(measurement))
	if normalized == "" {
		return localDevReleaseMeasurement
	}
	return normalized
}

func (s *State) MarkFirstByte() {
	if s == nil || !s.FirstByteAt.IsZero() {
		return
	}
	s.FirstByteAt = time.Now().UTC()
}

func (s *State) ObserveProviderTTFB(latencyMS int64) {
	if s == nil || s.ProviderTTFBMS != nil || latencyMS <= 0 {
		return
	}
	value := uint32(latencyMS)
	if latencyMS > int64(^uint32(0)) {
		value = ^uint32(0)
	}
	s.ProviderTTFBMS = &value
}

func (s *State) ObserveUnaryProviderLatency(extra schemas.BifrostResponseExtraFields) {
	s.ObserveProviderTTFB(extra.Latency)
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
