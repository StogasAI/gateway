package stogas

import (
	"bytes"
	"sync"
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
	Resolution              *catalog.ResolvedRequest
	Adapter                 Adapter
	Signals                 Signals
	Hold                    HoldEstimate
	RawAPIKey               string
	APIKeyClaims            *billing.APIKeyClaims
	DashboardCredential     *billing.DashboardCredential
	PassthroughByokSecret   string
	Authorization           *billing.Authorization
	BillingFinalized        bool
	SingleUseRequestID      bool
	RequestLifetime         time.Duration
	RequestID               string
	StartedAt               time.Time
	RequestType             string
	Model                   string
	Response                *schemas.BifrostResponse
	BifrostError            *schemas.BifrostError
	FinalEvent              *billing.RequestEvent
	FinalCostUSDAtoms       string
	FinalMeters             []catalog.MeterEstimate
	ProviderStartedAt       time.Time
	ProviderCompletedAt     time.Time
	ProviderFirstOutputMS   *uint32
	ClientStoppedAt         time.Time
	Cancelled               bool
	GatewayVersion          string
	NodeID                  string
	ActualServiceTier       *schemas.BifrostServiceTier
	ActualSpeed             string
	ActualInferenceGeo      string
	ActualModel             string
	providerStreamBytes     int
	chatStreamObserved      bool
	chatStreamRoleSeen      bool
	chatStreamFinished      bool
	chatStreamUsageEnded    bool
	responsesStreamSeen     bool
	responsesStreamEnded    bool
	responsesInProgressSeen bool
	responsesOutputStarted  bool
	responsesNextSequence   int
	chatToolCalls           map[uint16]providerChatToolCall
	chatToolCallIDs         map[string]uint16
	responsesToolCallIDs    map[string]string
	responsesToolCalls      int
	responsesDeclaredCalls  int
	responsesHostedCalls    int
	responsesClientCalls    int
	responsesItems          map[int]providerResponsesItem

	ProviderResponseHeaders map[string]string

	providerAttemptsMu sync.Mutex
	providerAttempts   []providerAttemptObservation
}

type providerChatToolCall struct {
	id        string
	name      string
	arguments *bytes.Buffer
}

type providerResponsesItem struct {
	id                string
	callID            string
	itemType          schemas.ResponsesMessageType
	name              string
	atomicPayload     string
	toolCallerPayload string
	toolActionPayload string
	toolKind          string
	parts             map[int]*providerResponsesPart
	reasoningParts    map[int]*providerResponsesPart
	value             *bytes.Buffer
	valueDone         bool
	code              *bytes.Buffer
	codeDone          bool
	completedPayload  string
	stage             int
	done              bool
}

type providerResponsesPart struct {
	blockType   schemas.ResponsesMessageContentBlockType
	value       bytes.Buffer
	signature   *string
	annotations map[int]providerResponsesAnnotation
	valueDone   bool
	done        bool
}

type providerResponsesAnnotation struct {
	value string
	done  bool
}

type providerAttemptObservation struct {
	Provider              string
	StartedAt             time.Time
	CompletedAt           time.Time
	ProviderFirstOutputMS *uint32
	Response              *schemas.BifrostResponse
	Error                 *schemas.BifrostError
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

func (s *State) SetDashboardCredential(credential *billing.DashboardCredential) {
	s.DashboardCredential = credential
}

func (s *State) MarkProviderStarted() {
	if s == nil || !s.ProviderStartedAt.IsZero() {
		return
	}
	s.ProviderStartedAt = time.Now()
}

func (s *State) MarkProviderCompleted() {
	if s == nil {
		return
	}
	completedAt := time.Now()
	if s.ProviderCompletedAt.IsZero() {
		s.ProviderCompletedAt = completedAt
	} else {
		completedAt = s.ProviderCompletedAt
	}
	s.completeLatestProviderAttempt(completedAt)
}

func (s *State) MarkClientStopped() {
	if s == nil || !s.ClientStoppedAt.IsZero() {
		return
	}
	s.ClientStoppedAt = time.Now()
}

// observeProviderFirstOutput records the gateway-observed elapsed provider call
// time until Bifrost yields the first usable output.
func (s *State) observeProviderFirstOutput() {
	if s == nil || s.ProviderFirstOutputMS != nil || s.ProviderStartedAt.IsZero() {
		return
	}
	observedAt := time.Now()
	latencyMS := observedAt.Sub(s.ProviderStartedAt).Milliseconds()
	if latencyMS < 0 {
		return
	}
	value := uint32(latencyMS)
	if latencyMS > int64(^uint32(0)) {
		value = ^uint32(0)
	}
	s.ProviderFirstOutputMS = &value
	s.observeCurrentProviderAttemptFirstOutput(observedAt, latencyMS)
}

func (s *State) beginProviderAttempt(startedAt time.Time) int {
	if s == nil {
		return -1
	}
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	s.providerAttemptsMu.Lock()
	defer s.providerAttemptsMu.Unlock()
	if count := len(s.providerAttempts); count > 0 {
		previous := &s.providerAttempts[count-1]
		if previous.CompletedAt.IsZero() {
			previous.CompletedAt = maxProviderAttemptTime(startedAt, previous.StartedAt)
		}
	}
	s.providerAttempts = append(s.providerAttempts, providerAttemptObservation{StartedAt: startedAt})
	return len(s.providerAttempts) - 1
}

func (s *State) setProviderAttemptProvider(index int, provider string) {
	if s == nil || index < 0 {
		return
	}
	s.providerAttemptsMu.Lock()
	defer s.providerAttemptsMu.Unlock()
	if index < len(s.providerAttempts) {
		s.providerAttempts[index].Provider = provider
	}
}

func (s *State) finishProviderAttempt(index int, completedAt time.Time, response *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) {
	if s == nil || index < 0 {
		return
	}
	s.providerAttemptsMu.Lock()
	defer s.providerAttemptsMu.Unlock()
	if index >= len(s.providerAttempts) {
		return
	}
	attempt := &s.providerAttempts[index]
	if attempt.CompletedAt.IsZero() {
		attempt.CompletedAt = maxProviderAttemptTime(completedAt, attempt.StartedAt)
	}
	attempt.Response = response
	attempt.Error = bifrostErr
}

func (s *State) completeLatestProviderAttempt(completedAt time.Time) {
	s.providerAttemptsMu.Lock()
	defer s.providerAttemptsMu.Unlock()
	if len(s.providerAttempts) == 0 {
		return
	}
	attempt := &s.providerAttempts[len(s.providerAttempts)-1]
	if attempt.CompletedAt.IsZero() {
		attempt.CompletedAt = maxProviderAttemptTime(completedAt, attempt.StartedAt)
	}
}

func (s *State) observeCurrentProviderAttemptFirstOutput(observedAt time.Time, fallbackLatencyMS int64) {
	s.providerAttemptsMu.Lock()
	defer s.providerAttemptsMu.Unlock()
	if len(s.providerAttempts) == 0 {
		return
	}
	attempt := &s.providerAttempts[len(s.providerAttempts)-1]
	if attempt.ProviderFirstOutputMS != nil {
		return
	}
	latencyMS := fallbackLatencyMS
	if !attempt.StartedAt.IsZero() {
		latencyMS = observedAt.Sub(attempt.StartedAt).Milliseconds()
	}
	if latencyMS < 0 {
		return
	}
	value := uint32(latencyMS)
	if latencyMS > int64(^uint32(0)) {
		value = ^uint32(0)
	}
	attempt.ProviderFirstOutputMS = &value
}

func (s *State) providerAttemptInputs() []billing.ProviderAttemptInput {
	if s == nil {
		return nil
	}
	s.providerAttemptsMu.Lock()
	defer s.providerAttemptsMu.Unlock()
	// Keep the existing outer provider clock for the common one-attempt path.
	if len(s.providerAttempts) < 2 {
		return nil
	}
	attempts := make([]billing.ProviderAttemptInput, len(s.providerAttempts))
	for index, attempt := range s.providerAttempts {
		attempts[index] = billing.ProviderAttemptInput{
			Provider:              attempt.Provider,
			StartedAt:             attempt.StartedAt,
			CompletedAt:           attempt.CompletedAt,
			ProviderFirstOutputMS: cloneUint32(attempt.ProviderFirstOutputMS),
			Response:              attempt.Response,
			Error:                 attempt.Error,
		}
	}
	finalAttempt := &attempts[len(attempts)-1]
	if finalAttempt.CompletedAt.IsZero() {
		finalAttempt.CompletedAt = maxProviderAttemptTime(s.ProviderCompletedAt, finalAttempt.StartedAt)
	}
	if s.Response != nil {
		finalAttempt.Response = s.Response
	}
	if s.BifrostError != nil && !providerAttemptErrorBeforeFinal(attempts, s.BifrostError) {
		finalAttempt.Error = s.BifrostError
	}
	return attempts
}

func providerAttemptErrorBeforeFinal(attempts []billing.ProviderAttemptInput, target *schemas.BifrostError) bool {
	// When every fallback fails, Bifrost returns the primary error. Keep that
	// error on its original attempt instead of replacing the last fallback's
	// independently observed error.
	for _, attempt := range attempts[:len(attempts)-1] {
		if attempt.Error == target {
			return true
		}
	}
	return false
}

func maxProviderAttemptTime(value time.Time, minimum time.Time) time.Time {
	if value.IsZero() || value.Before(minimum) {
		return minimum
	}
	return value
}

func cloneUint32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func (s *State) ObserveChatProviderOutput(response *schemas.BifrostChatResponse) {
	if !chatResponseHasOutput(response) {
		return
	}
	s.observeProviderFirstOutput()
}

func (s *State) ObserveResponsesProviderOutput(response *schemas.BifrostResponsesStreamResponse) {
	if !responsesEventHasOutput(response) {
		return
	}
	s.observeProviderFirstOutput()
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
