package stogas

import (
	"bytes"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter"
)

type contextKey string

const stateContextKey contextKey = "stogas.state"

// GatewayVersion is populated by release builds. Development builds remain
// explicit rather than pretending to be a published release.
var GatewayVersion = "dev"

// Pair holds what belongs to one deployment and credential pair. A fallback
// binds the next pair as a whole; the request's own facts stay on State.
type Pair struct {
	Export             *exporter.Capture
	Resolution         *catalog.ResolvedRequest
	Adapter            Adapter
	Hold               HoldEstimate
	PreparedCredential *billing.PreparedCredential
	PolicyVersions     *billing.PolicyVersions
	Authorization      *billing.Authorization
	RequestSettings    billing.RequestSettings
	Model              string
	PluginMetrics      plugins.Metrics
}

type State struct {
	Pair
	observedUsage           *StandardSignals
	Signals                 Signals
	RawAPIKey               string
	APIKeyClaims            *billing.APIKeyClaims
	DashboardCredential     *billing.DashboardCredential
	BillingFinalized        bool
	RequestLifetime         time.Duration
	RequestID               string
	StartedAt               time.Time
	RequestType             string
	SessionID               string
	Metadata                map[string]string
	Transport               string
	Response                *schemas.BifrostResponse
	BifrostError            *schemas.BifrostError
	ProcessingError         *schemas.BifrostError
	FinalEvent              *billing.RequestEvent
	UpstreamCostUSD         string
	FinalMeters             []catalog.MeterEstimate
	ProviderStartedAt       time.Time
	ProviderCompletedAt     time.Time
	RateLimitWait           time.Duration
	TTFTMS                  *uint32
	FirstOutputAt           time.Time
	LastOutputAt            time.Time
	ProviderOutputObserved  bool
	providerOutputEmitted   bool
	ClientStoppedAt         time.Time
	Cancelled               bool
	clientStateMu           sync.RWMutex
	GatewayVersion          string
	NodeID                  string
	ActualTier              string
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
	providerToolSet         *providerToolSet
	responsesToolCallIDs    map[string]string
	responsesToolCalls      int
	responsesDeclaredCalls  int
	responsesHostedCalls    int
	responsesClientCalls    int
	responsesItems          map[int]providerResponsesItem
	textMaterial            textMaterial
	textMaterialObserved    bool
	responsesTextMaterial   map[int]textMaterial

	providerAttemptsMu sync.Mutex
	providerAttempts   []providerAttemptObservation
}

// ResponseError preserves an upstream failure when final Stogas processing also
// fails. Processing errors never become evidence about the provider's outcome.
func (s *State) ResponseError() *schemas.BifrostError {
	if s == nil {
		return nil
	}
	if s.BifrostError != nil {
		return s.BifrostError
	}
	return s.ProcessingError
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
	compactionPayload string
	toolCallerPayload string
	toolActionPayload string
	parts             map[int]*providerResponsesPart
	reasoningParts    map[int]*providerResponsesPart
	value             *bytes.Buffer
	valueDone         bool
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
	CatalogChainHash string
	Provider         string
	Byok             string
	StartedAt        time.Time
	CompletedAt      time.Time
	Response         *schemas.BifrostResponse
	Error            *schemas.BifrostError
}

type HoldEstimate struct {
	EstimatedUpstreamCostUSD string
	ReservedTokens           int64
	ProductKey               string
	ProviderKey              string
	Meters                   []catalog.MeterEstimate
}

func NewState(resolution *catalog.ResolvedRequest, rawAPIKey string, claims *billing.APIKeyClaims, adapter Adapter) *State {
	return &State{
		Pair:           NewPair(resolution, adapter),
		RawAPIKey:      rawAPIKey,
		APIKeyClaims:   claims,
		GatewayVersion: GatewayVersion,
	}
}

func NewPair(resolution *catalog.ResolvedRequest, adapter Adapter) Pair {
	pair := Pair{Resolution: resolution, Adapter: adapter}
	if summary := resolution.StructuredPIIRedactionSummary(); summary != nil {
		pair.PluginMetrics.StogasStructuredPIIRedaction = &plugins.StogasStructuredPIIRedactionMetrics{
			ItemsRedacted: summary.ItemsRedacted,
			DurationUS:    summary.DurationUS,
		}
	}
	return pair
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

// MarkProviderNotSent removes the last provider call after its transport
// proved that nothing reached the provider. A request without another call
// settles like any other failure before dispatch: no provider time and no tokens.
func (s *State) MarkProviderNotSent() {
	if s == nil {
		return
	}
	s.providerAttemptsMu.Lock()
	defer s.providerAttemptsMu.Unlock()
	if count := len(s.providerAttempts); count > 0 {
		s.providerAttempts = s.providerAttempts[:count-1]
	}
	if len(s.providerAttempts) == 0 {
		s.ProviderStartedAt, s.ProviderCompletedAt = time.Time{}, time.Time{}
	}
}

// ProviderAttemptCount reports how many provider calls the log will show.
func (s *State) ProviderAttemptCount() int {
	if s == nil {
		return 0
	}
	s.providerAttemptsMu.Lock()
	defer s.providerAttemptsMu.Unlock()
	return len(s.providerAttempts)
}

func (s *State) MarkClientStopped() {
	if s == nil {
		return
	}
	s.clientStateMu.Lock()
	defer s.clientStateMu.Unlock()
	s.Cancelled = true
	if s.ClientStoppedAt.IsZero() {
		s.ClientStoppedAt = time.Now()
	}
}

func (s *State) ClientStatus() (cancelled bool, stoppedAt time.Time) {
	if s == nil {
		return false, time.Time{}
	}
	s.clientStateMu.RLock()
	defer s.clientStateMu.RUnlock()
	return s.Cancelled, s.ClientStoppedAt
}

// observeTTFT records request start through the first generated token-bearing
// payload accepted by the downstream stream. This includes all gateway work,
// retries, provider time, and any backpressure before that payload.
func (s *State) observeTTFT() {
	if s == nil || s.TTFTMS != nil || s.StartedAt.IsZero() {
		return
	}
	latencyMS := time.Since(s.StartedAt).Milliseconds()
	if latencyMS < 0 {
		return
	}
	value := uint32(latencyMS)
	if latencyMS > int64(^uint32(0)) {
		value = ^uint32(0)
	}
	s.TTFTMS = &value
}

// Output reaches the request only from its last provider call.
func (s *State) observeProviderOutput() {
	if s != nil {
		s.ProviderOutputObserved = true
	}
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
	// The request's owner binds another pair only between provider calls.
	attempt := providerAttemptObservation{StartedAt: startedAt}
	if s.Resolution != nil {
		attempt.CatalogChainHash = s.Resolution.Deployment.ChainHash
	}
	if s.Authorization != nil {
		attempt.Byok = s.Authorization.UpstreamByok
	}
	s.providerAttempts = append(s.providerAttempts, attempt)
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

func (s *State) providerAttemptInputs() []billing.ProviderAttemptInput {
	if s == nil {
		return nil
	}
	s.providerAttemptsMu.Lock()
	defer s.providerAttemptsMu.Unlock()
	if len(s.providerAttempts) == 0 {
		return nil
	}
	attempts := make([]billing.ProviderAttemptInput, len(s.providerAttempts))
	for index, attempt := range s.providerAttempts {
		attempts[index] = billing.ProviderAttemptInput{
			Provider:                 attempt.Provider,
			Byok:                     attempt.Byok,
			CatalogChainHash:         attempt.CatalogChainHash,
			ResolvedCatalogChainHash: attempt.CatalogChainHash,
			StartedAt:                attempt.StartedAt,
			CompletedAt:              attempt.CompletedAt,
			Response:                 attempt.Response,
			Error:                    attempt.Error,
		}
	}
	// The final outcome belongs to the last call, which ran on the bound pair.
	finalAttempt := &attempts[len(attempts)-1]
	if s.Resolution != nil && finalAttempt.CatalogChainHash == s.Resolution.Deployment.ChainHash {
		finalAttempt.CatalogChainHash = ExecutionDeployment(s).ChainHash
	}
	if finalAttempt.CompletedAt.IsZero() {
		finalAttempt.CompletedAt = maxProviderAttemptTime(s.ProviderCompletedAt, finalAttempt.StartedAt)
	}
	finalAttempt.OutputObserved = s.ProviderOutputObserved
	if s.Response != nil {
		finalAttempt.Response = s.Response
	}
	if s.BifrostError != nil {
		finalAttempt.Error = s.BifrostError
	}
	return attempts
}

func maxProviderAttemptTime(value time.Time, minimum time.Time) time.Time {
	if value.IsZero() || value.Before(minimum) {
		return minimum
	}
	return value
}

func (s *State) ObserveChatStreamOutput(response *schemas.BifrostChatResponse) {
	if chatResponseHasOutput(response) {
		s.observeProviderOutput()
	}
	if chatResponseHasToken(response) {
		s.observeTTFT()
	}
}

func (s *State) observeChatProviderOutputEmitted(response *schemas.BifrostChatResponse) {
	if s != nil && chatResponseHasProviderOutput(response) {
		s.providerOutputEmitted = true
		s.observeFirstProviderOutput()
	}
}

func (s *State) observeResponsesProviderOutputEmitted(response *schemas.BifrostResponsesStreamResponse) {
	if s != nil && responsesEventHasOutput(response) {
		s.providerOutputEmitted = true
		s.observeFirstProviderOutput()
	}
}

func (s *State) observeProviderResponseOutputEmitted(response *schemas.BifrostResponse) {
	if s != nil && providerResponseHasOutput(response) {
		s.providerOutputEmitted = true
		s.observeFirstProviderOutput()
		// A buffered response is observed as one complete provider result. Record
		// the output fact without creating TTFT, which only exists for streams.
		s.observeProviderOutput()
	}
}

func (s *State) observeFirstProviderOutput() {
	s.LastOutputAt = time.Now()
	if !s.FirstOutputAt.IsZero() {
		return
	}
	s.FirstOutputAt = s.LastOutputAt
	// Unary arrival is recorded before validated content is inspected.
	if !s.ProviderCompletedAt.IsZero() && s.ProviderCompletedAt.Before(s.FirstOutputAt) {
		s.FirstOutputAt = s.ProviderCompletedAt
	}
}

func (s *State) ObserveResponsesStreamOutput(response *schemas.BifrostResponsesStreamResponse) {
	if responsesEventHasOutput(response) {
		s.observeProviderOutput()
	}
	if responsesEventHasToken(response) {
		s.observeTTFT()
	}
}

func chatResponseHasToken(response *schemas.BifrostChatResponse) bool {
	if response == nil {
		return false
	}
	for _, choice := range response.Choices {
		stream := choice.ChatStreamResponseChoice
		if stream != nil && stream.Delta != nil {
			delta := stream.Delta
			if nonEmptyString(delta.Content) ||
				nonEmptyString(delta.Refusal) ||
				nonEmptyString(delta.Reasoning) ||
				chatAudioHasOutput(delta.Audio) ||
				chatReasoningDetailsHaveToken(delta.ReasoningDetails) ||
				chatToolCallsHaveToken(delta.ToolCalls) {
				return true
			}
		}
		if nonStream := choice.ChatNonStreamResponseChoice; nonStream != nil && chatMessageHasToken(nonStream.Message) {
			return true
		}
	}
	return false
}

func chatResponseHasOutput(response *schemas.BifrostChatResponse) bool {
	if response == nil {
		return false
	}
	for _, choice := range response.Choices {
		stream := choice.ChatStreamResponseChoice
		if stream != nil && stream.Delta != nil {
			delta := stream.Delta
			if nonEmptyString(delta.Content) ||
				nonEmptyString(delta.Refusal) ||
				nonEmptyString(delta.Reasoning) ||
				chatAudioHasOutput(delta.Audio) ||
				chatReasoningDetailsHaveOutput(delta.ReasoningDetails) ||
				chatToolCallsHaveOutput(delta.ToolCalls) ||
				chatAnnotationsHaveOutput(delta.Annotations) {
				return true
			}
		}
		if nonStream := choice.ChatNonStreamResponseChoice; nonStream != nil && chatMessageHasOutput(nonStream.Message) {
			return true
		}
	}
	return false
}

func chatResponseHasProviderOutput(response *schemas.BifrostChatResponse) bool {
	if chatResponseHasOutput(response) {
		return true
	}
	if response == nil {
		return false
	}
	for _, choice := range response.Choices {
		if stream := choice.ChatStreamResponseChoice; stream != nil && stream.Delta != nil &&
			chatReasoningDetailsHaveSignature(stream.Delta.ReasoningDetails) {
			return true
		}
		if nonStream := choice.ChatNonStreamResponseChoice; nonStream != nil && chatMessageHasOutput(nonStream.Message) {
			return true
		}
	}
	return false
}

func chatMessageHasOutput(message *schemas.ChatMessage) bool {
	if message == nil {
		return false
	}
	if message.Content != nil {
		if nonEmptyString(message.Content.ContentStr) {
			return true
		}
		for index := range message.Content.ContentBlocks {
			block := &message.Content.ContentBlocks[index]
			if nonEmptyString(block.Text) || nonEmptyString(block.Refusal) ||
				block.ImageURLStruct != nil && (block.ImageURLStruct.URL != "" || nonEmptyString(block.ImageURLStruct.FileID)) ||
				block.InputAudio != nil && block.InputAudio.Data != "" ||
				block.File != nil && (nonEmptyString(block.File.FileData) || nonEmptyString(block.File.FileURL) || nonEmptyString(block.File.FileID)) {
				return true
			}
		}
	}
	assistant := message.ChatAssistantMessage
	return assistant != nil && (nonEmptyString(assistant.Refusal) ||
		nonEmptyString(assistant.Reasoning) ||
		chatAudioHasOutput(assistant.Audio) ||
		chatReasoningDetailsHaveOutput(assistant.ReasoningDetails) ||
		chatReasoningDetailsHaveSignature(assistant.ReasoningDetails) ||
		chatToolCallsHaveOutput(assistant.ToolCalls) ||
		chatAnnotationsHaveOutput(assistant.Annotations))
}

func chatMessageHasToken(message *schemas.ChatMessage) bool {
	if message == nil {
		return false
	}
	if message.Content != nil {
		if nonEmptyString(message.Content.ContentStr) {
			return true
		}
		for index := range message.Content.ContentBlocks {
			block := &message.Content.ContentBlocks[index]
			if nonEmptyString(block.Text) || nonEmptyString(block.Refusal) {
				return true
			}
		}
	}
	assistant := message.ChatAssistantMessage
	return assistant != nil && (nonEmptyString(assistant.Refusal) ||
		nonEmptyString(assistant.Reasoning) ||
		chatAudioHasOutput(assistant.Audio) ||
		chatReasoningDetailsHaveToken(assistant.ReasoningDetails) ||
		chatToolCallsHaveToken(assistant.ToolCalls))
}

func chatAudioHasOutput(audio *schemas.ChatAudioMessageAudio) bool {
	return audio != nil && (audio.Data != "" || audio.Transcript != "")
}

func chatReasoningDetailsHaveOutput(details []schemas.ChatReasoningDetails) bool {
	for _, detail := range details {
		if nonEmptyString(detail.Summary) || nonEmptyString(detail.Text) || nonEmptyString(detail.Data) {
			return true
		}
	}
	return false
}

func chatReasoningDetailsHaveToken(details []schemas.ChatReasoningDetails) bool {
	for _, detail := range details {
		if nonEmptyString(detail.Summary) || nonEmptyString(detail.Text) {
			return true
		}
	}
	return false
}

func chatReasoningDetailsHaveSignature(details []schemas.ChatReasoningDetails) bool {
	for _, detail := range details {
		if nonEmptyString(detail.Signature) {
			return true
		}
	}
	return false
}

func chatToolCallsHaveOutput(calls []schemas.ChatAssistantMessageToolCall) bool {
	for _, call := range calls {
		if nonEmptyString(call.ID) || nonEmptyString(call.Function.Name) || call.Function.Arguments != "" {
			return true
		}
	}
	return false
}

func chatToolCallsHaveToken(calls []schemas.ChatAssistantMessageToolCall) bool {
	for _, call := range calls {
		if nonEmptyString(call.Function.Name) || call.Function.Arguments != "" {
			return true
		}
	}
	return false
}

func chatAnnotationsHaveOutput(annotations []schemas.ChatAssistantMessageAnnotation) bool {
	for _, annotation := range annotations {
		citation := annotation.URLCitation
		if nonEmptyString(citation.URL) || nonEmptyString(citation.Text) || citation.Title != "" {
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
	case schemas.ResponsesStreamResponseTypeOutputTextDelta,
		schemas.ResponsesStreamResponseTypeRefusalDelta,
		schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		schemas.ResponsesStreamResponseTypeMCPCallArgumentsDelta,
		schemas.ResponsesStreamResponseTypeCustomToolCallInputDelta:
		return nonEmptyString(response.Delta)
	case schemas.ResponsesStreamResponseTypeOutputTextDone,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone:
		return nonEmptyString(response.Text)
	case schemas.ResponsesStreamResponseTypeRefusalDone:
		return nonEmptyString(response.Refusal)
	case schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone,
		schemas.ResponsesStreamResponseTypeMCPCallArgumentsDone:
		return nonEmptyString(response.Arguments)
	case schemas.ResponsesStreamResponseTypeCustomToolCallInputDone:
		return nonEmptyString(response.Input)
	case schemas.ResponsesStreamResponseTypeImageGenerationCallPartialImage:
		return nonEmptyString(response.PartialImageB64)
	case schemas.ResponsesStreamResponseTypeContentPartAdded,
		schemas.ResponsesStreamResponseTypeContentPartDone,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartDone:
		return responsesContentBlockHasOutput(response.Part)
	case schemas.ResponsesStreamResponseTypeOutputItemAdded,
		schemas.ResponsesStreamResponseTypeOutputItemDone:
		return responsesMessageHasOutput(response.Item)
	case schemas.ResponsesStreamResponseTypeCompleted,
		schemas.ResponsesStreamResponseTypeIncomplete:
		return responsesResponseHasOutput(response.Response)
	case schemas.ResponsesStreamResponseTypeFileSearchCallResultsAdded,
		schemas.ResponsesStreamResponseTypeFileSearchCallResultsCompleted,
		schemas.ResponsesStreamResponseTypeWebSearchCallResultsAdded,
		schemas.ResponsesStreamResponseTypeWebSearchCallResultsCompleted:
		return len(response.SearchResults) > 0 || len(response.Videos) > 0 || len(response.Citations) > 0
	default:
		// Unknown and lifecycle-only events are not evidence that usable output
		// reached the caller. New event types must opt in with a payload check.
		return false
	}
}

func responsesEventHasToken(response *schemas.BifrostResponsesStreamResponse) bool {
	if response == nil {
		return false
	}
	switch response.Type {
	case schemas.ResponsesStreamResponseTypeOutputTextDelta,
		schemas.ResponsesStreamResponseTypeRefusalDelta,
		schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		schemas.ResponsesStreamResponseTypeMCPCallArgumentsDelta,
		schemas.ResponsesStreamResponseTypeCustomToolCallInputDelta:
		return nonEmptyString(response.Delta)
	case schemas.ResponsesStreamResponseTypeOutputTextDone,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone:
		return nonEmptyString(response.Text)
	case schemas.ResponsesStreamResponseTypeRefusalDone:
		return nonEmptyString(response.Refusal)
	case schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone,
		schemas.ResponsesStreamResponseTypeMCPCallArgumentsDone:
		return nonEmptyString(response.Arguments)
	case schemas.ResponsesStreamResponseTypeCustomToolCallInputDone:
		return nonEmptyString(response.Input)
	case schemas.ResponsesStreamResponseTypeContentPartAdded,
		schemas.ResponsesStreamResponseTypeContentPartDone,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartDone:
		return responsesContentBlockHasToken(response.Part)
	case schemas.ResponsesStreamResponseTypeOutputItemAdded,
		schemas.ResponsesStreamResponseTypeOutputItemDone:
		return responsesMessageHasToken(response.Item)
	case schemas.ResponsesStreamResponseTypeCompleted,
		schemas.ResponsesStreamResponseTypeIncomplete:
		return responsesResponseHasToken(response.Response)
	default:
		return false
	}
}

func responsesMessageHasOutput(message *schemas.ResponsesMessage) bool {
	if message == nil {
		return false
	}
	if message.Content != nil {
		if nonEmptyString(message.Content.ContentStr) {
			return true
		}
		for index := range message.Content.ContentBlocks {
			if responsesContentBlockHasOutput(&message.Content.ContentBlocks[index]) {
				return true
			}
		}
	}
	if message.ResponsesReasoning != nil {
		if nonEmptyString(message.ResponsesReasoning.EncryptedContent) {
			return true
		}
		for _, summary := range message.ResponsesReasoning.Summary {
			if summary.Text != "" {
				return true
			}
		}
	}
	tool := message.ResponsesToolMessage
	if tool == nil {
		return false
	}
	if nonEmptyString(tool.Name) || nonEmptyString(tool.Arguments) || responsesToolActionHasOutput(tool.Action) {
		return true
	}
	if tool.Output != nil {
		if nonEmptyString(tool.Output.ResponsesToolCallOutputStr) || responsesComputerOutputHasOutput(tool.Output.ResponsesComputerToolCallOutput) {
			return true
		}
		for index := range tool.Output.ResponsesFunctionToolCallOutputBlocks {
			if responsesContentBlockHasOutput(&tool.Output.ResponsesFunctionToolCallOutputBlocks[index]) {
				return true
			}
		}
	}
	return tool.ResponsesImageGenerationCall != nil && tool.ResponsesImageGenerationCall.Result != "" ||
		tool.ResponsesCustomToolCall != nil && tool.ResponsesCustomToolCall.Input != "" ||
		tool.ResponsesFileSearchToolCall != nil &&
			(len(tool.ResponsesFileSearchToolCall.Queries) > 0 || len(tool.ResponsesFileSearchToolCall.Results) > 0) ||
		tool.ResponsesAdvisorCall != nil &&
			(nonEmptyString(tool.ResponsesAdvisorCall.Text) || nonEmptyString(tool.ResponsesAdvisorCall.EncryptedContent)) ||
		tool.ResponsesWebFetchCall != nil &&
			(nonEmptyString(tool.ResponsesWebFetchCall.URL) ||
				tool.ResponsesWebFetchCall.Document != nil && nonEmptyString(tool.ResponsesWebFetchCall.Document.Text))
}

func providerResponseHasOutput(response *schemas.BifrostResponse) bool {
	if response == nil {
		return false
	}
	switch {
	case response.ChatResponse != nil:
		return chatResponseHasProviderOutput(response.ChatResponse)
	case response.ResponsesResponse != nil:
		return responsesResponseHasOutput(response.ResponsesResponse)
	case response.ResponsesStreamResponse != nil:
		return responsesEventHasOutput(response.ResponsesStreamResponse)
	default:
		return false
	}
}

func responsesResponseHasOutput(response *schemas.BifrostResponsesResponse) bool {
	if response == nil {
		return false
	}
	for index := range response.Output {
		if responsesMessageHasOutput(&response.Output[index]) {
			return true
		}
	}
	return len(response.SearchResults) > 0 || len(response.Videos) > 0 || len(response.Citations) > 0
}

func responsesResponseHasToken(response *schemas.BifrostResponsesResponse) bool {
	if response == nil {
		return false
	}
	for index := range response.Output {
		if responsesMessageHasToken(&response.Output[index]) {
			return true
		}
	}
	return false
}

func responsesMessageHasToken(message *schemas.ResponsesMessage) bool {
	if message == nil {
		return false
	}
	if message.Content != nil {
		if nonEmptyString(message.Content.ContentStr) {
			return true
		}
		for index := range message.Content.ContentBlocks {
			if responsesContentBlockHasToken(&message.Content.ContentBlocks[index]) {
				return true
			}
		}
	}
	if message.ResponsesReasoning != nil {
		for _, summary := range message.ResponsesReasoning.Summary {
			if summary.Text != "" {
				return true
			}
		}
	}
	tool := message.ResponsesToolMessage
	if tool == nil {
		return false
	}
	if nonEmptyString(tool.Name) || nonEmptyString(tool.Arguments) || responsesToolActionHasToken(tool.Action) {
		return true
	}
	return tool.ResponsesCustomToolCall != nil && tool.ResponsesCustomToolCall.Input != "" ||
		tool.ResponsesFileSearchToolCall != nil && len(tool.ResponsesFileSearchToolCall.Queries) > 0
}

func responsesToolActionHasToken(action *schemas.ResponsesToolMessageActionStruct) bool {
	if action == nil {
		return false
	}
	if computer := action.ResponsesComputerToolCallAction; computer != nil &&
		(computer.Type != "" || computer.X != nil || computer.Y != nil || computer.Button != nil || len(computer.Path) > 0 ||
			len(computer.Keys) > 0 || computer.ScrollX != nil || computer.ScrollY != nil ||
			computer.Text != nil || len(computer.Region) > 0) {
		return true
	}
	if search := action.ResponsesWebSearchToolCallAction; search != nil &&
		(search.Type != "" || nonEmptyString(search.URL) || nonEmptyString(search.Query) || len(search.Queries) > 0 ||
			len(search.Sources) > 0 || nonEmptyString(search.Pattern) || len(search.ImageQueries) > 0) {
		return true
	}
	if fetch := action.ResponsesWebFetchToolCallAction; fetch != nil && (fetch.Type != "" || fetch.URL != "") {
		return true
	}
	if shell := action.ResponsesLocalShellToolCallAction; shell != nil &&
		(shell.Type != "" || len(shell.Command) > 0 || len(shell.Env) > 0 || shell.TimeoutMS != nil ||
			shell.User != nil || shell.WorkingDirectory != nil) {
		return true
	}
	if approval := action.ResponsesMCPApprovalRequestAction; approval != nil {
		return approval.Name != "" || approval.ServerLabel != "" || approval.Arguments != ""
	}
	return false
}

func responsesToolActionHasOutput(action *schemas.ResponsesToolMessageActionStruct) bool {
	if action == nil {
		return false
	}
	if computer := action.ResponsesComputerToolCallAction; computer != nil &&
		(computer.Type != "" || computer.X != nil || computer.Y != nil || computer.Button != nil ||
			len(computer.Path) > 0 || len(computer.Keys) > 0 || computer.ScrollX != nil ||
			computer.ScrollY != nil || computer.Text != nil || len(computer.Region) > 0) {
		return true
	}
	if search := action.ResponsesWebSearchToolCallAction; search != nil &&
		(search.Type != "" || nonEmptyString(search.URL) || nonEmptyString(search.Query) ||
			len(search.Queries) > 0 || len(search.Sources) > 0 || nonEmptyString(search.Pattern) ||
			len(search.ImageQueries) > 0) {
		return true
	}
	if fetch := action.ResponsesWebFetchToolCallAction; fetch != nil && (fetch.Type != "" || fetch.URL != "") {
		return true
	}
	if shell := action.ResponsesLocalShellToolCallAction; shell != nil &&
		(shell.Type != "" || len(shell.Command) > 0 || len(shell.Env) > 0 || shell.TimeoutMS != nil ||
			shell.User != nil || shell.WorkingDirectory != nil) {
		return true
	}
	if approval := action.ResponsesMCPApprovalRequestAction; approval != nil {
		return approval.ID != "" || approval.Type != "" || approval.Name != "" ||
			approval.ServerLabel != "" || approval.Arguments != ""
	}
	return false
}

func responsesComputerOutputHasOutput(output *schemas.ResponsesComputerToolCallOutputData) bool {
	return output != nil && (output.Type != "" || nonEmptyString(output.FileID) || nonEmptyString(output.ImageURL))
}

func responsesContentBlockHasOutput(block *schemas.ResponsesMessageContentBlock) bool {
	if block == nil {
		return false
	}
	if nonEmptyString(block.Text) || nonEmptyString(block.EncryptedContent) {
		return true
	}
	if block.ResponsesOutputMessageContentRefusal != nil && block.ResponsesOutputMessageContentRefusal.Refusal != "" {
		return true
	}
	if block.ResponsesOutputMessageContentRenderedContent != nil && block.ResponsesOutputMessageContentRenderedContent.RenderedContent != "" {
		return true
	}
	return block.ResponsesOutputMessageContentCompaction != nil && block.ResponsesOutputMessageContentCompaction.Summary != ""
}

func responsesContentBlockHasToken(block *schemas.ResponsesMessageContentBlock) bool {
	if block == nil {
		return false
	}
	if nonEmptyString(block.Text) {
		return true
	}
	if block.ResponsesOutputMessageContentRefusal != nil && block.ResponsesOutputMessageContentRefusal.Refusal != "" {
		return true
	}
	return block.ResponsesOutputMessageContentCompaction != nil && block.ResponsesOutputMessageContentCompaction.Summary != ""
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
