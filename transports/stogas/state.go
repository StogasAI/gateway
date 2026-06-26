package stogas

import (
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

type contextKey string

const stateContextKey contextKey = "stogas.state"

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

	ClientRequestHeaders    map[string][]string
	UpstreamRequestHeaders  map[string][]string
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
		Resolution:   resolution,
		Adapter:      adapter,
		RawAPIKey:    rawAPIKey,
		APIKeyClaims: claims,
	}
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
