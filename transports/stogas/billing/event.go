package billing

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/money"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

const (
	maxProviderNameBytes   = 64
	maxProviderReasonBytes = 128
	// Providers' IDs are UUIDs or prefixed random strings of up to about 60 characters, and
	// their model names are shorter still.
	maxProviderRequestIDBytes  = 128
	maxProviderResponseIDBytes = 256
	maxProviderModelBytes      = 128
	maxProviderInstanceIDBytes = 64
)

type EventInput struct {
	PolicyVersions        *LoggedPolicyVersions
	UpstreamCostUSD       string
	Authorization         *Authorization
	Cancelled             bool
	ClientStoppedAt       time.Time
	CatalogVersion        uint64
	Meters                EventMeters
	Plugins               plugins.Metrics
	ProviderAttempts      []ProviderAttemptInput
	RateLimitWait         time.Duration
	TTFTMS                *uint32
	FirstOutputAt         time.Time
	CacheReadSavingsUSD   *string
	CacheWriteOverheadUSD *string
	NodeID                string
	GatewayVersion        string
	RequestType           string
	RequestSettings       RequestSettings
	SessionID             string
	TraceID               string
	EncryptionKeyIDs      []string
	Metadata              map[string]string
	AppTitle              string
	AppURL                string
	Transport             string
	StartedAt             time.Time
	ToolCalls             []ToolCallInput
	// AnsweredCallIDs are the IDs that the input's results name after the latest model turn.
	AnsweredCallIDs []string
}

type ProviderAttemptInput struct {
	CatalogChainHash         string
	ResolvedCatalogChainHash string
	Provider                 string
	Byok                     string
	StartedAt                time.Time
	CompletedAt              time.Time
	OutputObserved           bool
	// Refusal is set when the reply carries refusal content, which its finish reason need not
	// show.
	Refusal  bool
	Response *schemas.BifrostResponse
	Error    *schemas.BifrostError
	Upstream UpstreamRecord
}

// UpstreamRecord is what a provider said about one call, as far as it says it: the request ID
// that its support uses to find the call, the model that served it and, where the provider names
// one, the instance that ran it.
type UpstreamRecord struct {
	RequestID  string
	Model      string
	InstanceID string
}

func NewRequestEvent(input EventInput) (RequestEvent, error) {
	authorization := input.Authorization
	if authorization == nil {
		authorization = &Authorization{}
	}
	startedAt := input.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	// Keep monotonic clocks for elapsed time. Convert only persisted wall
	// timestamps to UTC; UTC() here would make NTP adjustments affect latency.
	finishedAt := time.Now()
	createdAt := startedAt
	if !authorization.CreatedAt.IsZero() {
		createdAt = authorization.CreatedAt
	}
	totalTimeMS := uint32Duration(finishedAt.Sub(startedAt))
	var clientStopMS *uint32
	if !input.ClientStoppedAt.IsZero() && !input.ClientStoppedAt.Before(startedAt) {
		value := uint32Duration(input.ClientStoppedAt.Sub(startedAt))
		if value > totalTimeMS {
			value = totalTimeMS
		}
		clientStopMS = &value
	}
	upstreamCostRaw := input.UpstreamCostUSD
	if upstreamCostRaw == "" {
		upstreamCostRaw = ZeroChargeUSD
	}
	upstreamCostUSD, err := ParseUSD(upstreamCostRaw)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("invalid upstream cost: %w", err)
	}
	ttftMS := cloneUint32Pointer(input.TTFTMS)
	requestInterface, stream := RequestShape(input.RequestType)
	if !stream {
		ttftMS = nil
	} else if ttftMS != nil && *ttftMS > totalTimeMS {
		*ttftMS = totalTimeMS
	}
	pricing, err := ValidateMeters(input.Meters)
	if err != nil {
		return RequestEvent{}, err
	}
	billedCostUSD := calculateBilledCostUSD(authorization, upstreamCostUSD)
	cacheReadSavingsUSD, err := requestOptionalUSD(
		input.CacheReadSavingsUSD,
		"cache read savings",
	)
	if err != nil {
		return RequestEvent{}, err
	}
	cacheWriteOverheadUSD, err := requestOptionalUSD(
		input.CacheWriteOverheadUSD,
		"cache write overhead",
	)
	if err != nil {
		return RequestEvent{}, err
	}
	providerAttempts := requestProviderAttempts(input, startedAt, totalTimeMS)
	if len(providerAttempts) == 0 {
		// A request that reached no provider has no usage. Settlement rejects
		// meters without an attempt, including request-side counts.
		pricing = EventMeters{}
	}
	return RequestEvent{
		SchemaVersion:    RequestLogSchemaVersion,
		PolicyVersions:   input.PolicyVersions,
		RequestID:        authorization.RequestID,
		CreatedAt:        createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		LastRequestAt:    createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		RequestCount:     1,
		APIKeyID:         authorization.KeyID,
		GrantID:          authorization.GrantID,
		MemberID:         authorization.UserID,
		OrganizationID:   authorization.OrganizationID,
		Interface:        requestInterface,
		Stream:           stream,
		RequestSettings:  input.RequestSettings,
		SessionID:        input.SessionID,
		TraceID:          input.TraceID,
		EncryptionKeyIDs: encryptionKeyIDs(input.EncryptionKeyIDs),
		Metadata:         requestMetadata(input.Metadata),
		AppTitle:         input.AppTitle,
		AppURL:           input.AppURL,
		Transport:        input.Transport,
		Cancelled:        input.Cancelled,
		ClientStopMS:     clientStopMS,
		CatalogVersion:   catalogVersion(input.CatalogVersion),
		ProviderAttempts: providerAttempts,
		NodeID:           strings.ToLower(strings.TrimSpace(input.NodeID)),
		Performance: RequestPerformance{
			TotalMS:         totalTimeMS,
			RateLimitWaitMS: requestRateLimitWait(input.RateLimitWait, providerAttempts, totalTimeMS),
			FirstOutputMS:   requestFirstOutput(input, startedAt, providerAttempts),
			TTFTMS:          ttftMS,
			ToolCalls:       requestToolCalls(input.ToolCalls, startedAt, totalTimeMS),
			AnsweredCalls:   requestAnsweredCalls(input.AnsweredCallIDs),
		},
		Usage: RequestUsage{
			UpstreamCostUSD:       upstreamCostUSD.String(),
			BilledCostUSD:         billedCostUSD.String(),
			CacheReadSavingsUSD:   cacheReadSavingsUSD,
			CacheWriteOverheadUSD: cacheWriteOverheadUSD,
			Meters:                pricing,
			StandardTextTokens:    standardTextTokens(pricing),
		},
		Plugins:        input.Plugins,
		GatewayVersion: strings.TrimSpace(input.GatewayVersion),
	}, nil
}

// requestMetadata keeps metadata an object in every record, including exports.
func requestMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return map[string]string{}
	}
	return metadata
}

// encryptionKeyIDs keeps a log's roots a list, which JSON writes as [] when
// the request needs none.
func encryptionKeyIDs(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}

// requestFirstOutput places the provider's first output on the request clock, within the provider
// calls.
func requestFirstOutput(input EventInput, startedAt time.Time, attempts []ProviderAttempt) *uint32 {
	if input.FirstOutputAt.IsZero() || len(attempts) == 0 || input.FirstOutputAt.Before(input.ProviderAttempts[0].StartedAt) {
		return nil
	}
	last := attempts[len(attempts)-1]
	value := min(uint32Duration(input.FirstOutputAt.Sub(startedAt)), last.StartMS+last.LatencyMS)
	return &value
}

// ProviderMS is the time from the start of the first provider call to the end of the last, so it
// includes the waits between calls. It is 0 without a call.
func (event *RequestEvent) ProviderMS() uint32 {
	attempts := event.ProviderAttempts
	if len(attempts) == 0 {
		return 0
	}
	last := attempts[len(attempts)-1]
	return last.StartMS + last.LatencyMS - attempts[0].StartMS
}

// requestRateLimitWait ends by the start of the first provider call, which the wait held.
func requestRateLimitWait(wait time.Duration, attempts []ProviderAttempt, totalTimeMS uint32) uint32 {
	if len(attempts) > 0 {
		totalTimeMS = attempts[0].StartMS
	}
	return min(uint32Duration(wait), totalTimeMS)
}

func catalogVersion(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	return &value
}

func requestProviderAttempts(input EventInput, startedAt time.Time, totalTimeMS uint32) []ProviderAttempt {
	attempts := make([]ProviderAttempt, len(input.ProviderAttempts))
	// Calls follow each other, so a start never precedes the previous call's start.
	var previousStartMS uint32
	for index, observed := range input.ProviderAttempts {
		startMS := max(min(uint32Duration(observed.StartedAt.Sub(startedAt)), totalTimeMS), previousStartMS)
		previousStartMS = startMS
		attempts[index] = ProviderAttempt{
			Provider:                 boundedTelemetryValue(observed.Provider, maxProviderNameBytes),
			CatalogChainHash:         observed.CatalogChainHash,
			ResolvedCatalogChainHash: changedCatalogResolution(observed.ResolvedCatalogChainHash, observed.CatalogChainHash),
			Status:                   providerAttemptStatus(observed.Error, observed.Response, observed.Refusal),
			StatusCode:               providerStatusCode(observed.Error),
			ErrorCode:                providerErrorCode(observed.Error),
			StartMS:                  startMS,
			LatencyMS:                min(uint32Duration(observed.CompletedAt.Sub(observed.StartedAt)), totalTimeMS-startMS),
			OutputObserved:           observed.OutputObserved,
			ProviderRequestID:        boundedTelemetryValue(observed.Upstream.RequestID, maxProviderRequestIDBytes),
			ProviderResponseID:       providerResponseID(observed.Response),
			ProviderModel:            boundedTelemetryValue(observed.Upstream.Model, maxProviderModelBytes),
			ProviderInstanceID:       boundedTelemetryValue(observed.Upstream.InstanceID, maxProviderInstanceIDBytes),
			FinishReason:             finishReason(observed.Response),
			Byok:                     loggedCredentialID(observed.Byok),
		}
	}
	return attempts
}

func changedCatalogResolution(resolved, settled string) string {
	if resolved == settled {
		return ""
	}
	return resolved
}

// providerAttemptStatus is content_filter for a reply that stopped for a content filter and for
// one that carries a refusal, which OpenAI ends with an ordinary finish reason.
func providerAttemptStatus(bifrostErr *schemas.BifrostError, response *schemas.BifrostResponse, refusal bool) string {
	if bifrostErr != nil {
		return NormalizeUpstreamStatus(bifrostErr)
	}
	if refusal || providerResponseContentFiltered(response) {
		return "content_filter"
	}
	return "success"
}

func providerResponseContentFiltered(response *schemas.BifrostResponse) bool {
	switch finishReason(response) {
	case "content_filter", "refusal":
		return true
	}
	var incomplete *schemas.ResponsesResponseIncompleteDetails
	switch {
	case response == nil:
		return false
	case response.ResponsesResponse != nil:
		incomplete = response.ResponsesResponse.IncompleteDetails
	case response.ResponsesStreamResponse != nil && response.ResponsesStreamResponse.Response != nil:
		incomplete = response.ResponsesStreamResponse.Response.IncompleteDetails
	}
	return incomplete != nil && incomplete.Reason == schemas.ResponsesResponseIncompleteReasonContentFilter
}

func requestOptionalUSD(raw *string, name string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := ParseUSD(*raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", name, err)
	}
	normalized := value.String()
	return &normalized, nil
}

func cloneUint32Pointer(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

// loggedCredentialID returns the customer's credential ID, or nil for ours.
func loggedCredentialID(upstreamByok string) *string {
	id := strings.TrimSpace(upstreamByok)
	if id == "" || id == ManagedUpstreamByok {
		return nil
	}
	return &id
}

func calculateBilledCostUSD(authorization *Authorization, upstreamCostUSD *money.USD) *money.USD {
	if loggedCredentialID(authorization.UpstreamByok) == nil {
		return new(money.USD).Set(upstreamCostUSD)
	}
	return new(money.USD).MulRatioCeil(upstreamCostUSD, big.NewInt(2), 100)
}

// RequestShape reads a client request type as the interface that route.interfaces and
// policies spell, and whether the body asked for a stream. Only the Chat Completions and
// Responses paths reach inference, so a type that is not a Chat Completions one is a
// Responses one.
func RequestShape(requestType string) (string, bool) {
	switch schemas.RequestType(requestType) {
	case schemas.ChatCompletionRequest:
		return "chat_completions", false
	case schemas.ChatCompletionStreamRequest:
		return "chat_completions", true
	case schemas.ResponsesStreamRequest:
		return "responses", true
	}
	return "responses", false
}

func providerStatusCode(bifrostErr *schemas.BifrostError) *int {
	if bifrostErr == nil {
		status := 200
		return &status
	}
	if bifrostErr.StatusCode == nil {
		return nil
	}
	status := *bifrostErr.StatusCode
	return &status
}

func NormalizeUpstreamStatus(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil {
		return "success"
	}

	statusCode := 0
	if bifrostErr.StatusCode != nil {
		statusCode = *bifrostErr.StatusCode
	}
	identifiers := upstreamErrorIdentifiers(bifrostErr)

	switch {
	case identifiers.has(schemas.RequestCancelled) || statusCode == 499:
		return "cancelled"
	case identifiers.has(schemas.RequestTimedOut, "timeout", "timeout_error", "vector_store_timeout"):
		return "timeout"
	case identifiers.has(schemas.ProviderConnectionFailed):
		return "connection_error"
	case identifiers.has("context_length_exceeded", "max_tokens_exceeded", "token_limit_exceeded"):
		return "context_length_exceeded"
	case identifiers.has("request_too_large", "payload_too_large"):
		return "request_too_large"
	// OpenAI's Responses API names each image problem with a code of its own.
	case identifiers.has("invalid_image", "image_too_large", "image_too_small", "unsupported_image_format", "image_not_found", "image_download_failed",
		"invalid_image_format", "invalid_base64_image", "invalid_image_url", "image_parse_error", "invalid_image_mode", "image_file_too_large",
		"unsupported_image_media_type", "empty_image_file", "failed_to_download_image", "image_file_not_found"):
		return "invalid_image"
	case identifiers.has("overloaded_error", "provider_overloaded", "server_overloaded"):
		return "provider_overloaded"
	case identifiers.has("upstream_response_invalid", "upstream_execution_invalid", "upstream_protocol_error", "upstream_response_too_large"):
		return "invalid_response"
	// AWS sends UnrecognizedClientException, as a 403, for an access key that no longer exists, and
	// ExpiredTokenException for temporary credentials past their expiry.
	case identifiers.has("authentication_error", "invalid_api_key", "unauthorized", "upstream_authentication_failed",
		"unrecognizedclientexception", "expiredtokenexception"):
		return "authentication_error"
	// OpenAI sends missing_scope, as a 401, for a restricted key that lacks a permission. Google
	// sends FAILED_PRECONDITION, as a 400, for a model that needs allowlisting or that an
	// organization policy disallows (https://docs.cloud.google.com/vertex-ai/generative-ai/docs/model-reference/api-errors).
	case identifiers.has("permission_error", "permission_denied", "forbidden", "upstream_access_denied", "missing_scope",
		"failed_precondition"):
		return "permission_error"
	case identifiers.has("billing_error", "insufficient_quota", "over_budget", "upstream_quota_exceeded", "payment_required",
		// Anthropic's monthly spend cap, a 429 that retries cannot pass until the next month.
		"enforced_spend_limit_reached",
		// OpenAI's account limits, which its API reference lists among its error codes.
		"billing_not_active", "credit_balance_exhausted", "usage_limit_exceeded", "project_spend_limit_exceeded",
		"organization_spend_limit_exceeded", "organization_usage_limit_exceeded"):
		return "over_budget"
	case messageRefusal(bifrostErr) != "":
		return messageRefusal(bifrostErr)
	// Bedrock sends ServiceQuotaExceededException, as a 400, for an account quota that a later
	// request can pass.
	case identifiers.has("rate_limit_error", "rate_limited", "too_many_requests", "upstream_rate_limit_error", "rate_limit_exceeded",
		"servicequotaexceededexception"):
		return "rate_limited"
	case identifiers.has("content_filter", "content_filter_error", "safety_error", "content_policy_violation", "refusal", "cyber_policy",
		"bio_policy", "misalignment_policy_violation", "image_content_policy_violation"),
		flaggedPrompt(bifrostErr, identifiers):
		return "content_filter"
	case identifiers.has("model_decommissioned", "servicemodeldeprecating"):
		// The provider retired the model, whatever status it sends: Groq and Azure
		// send a retirement as 400.
		return "model_retired"
	case identifiers.has("unsupported_country_region_territory", "data_residency_mismatch"):
		// The provider does not serve the model to our region, or to the project's.
		return "model_unavailable"
	case statusCode == 401:
		return "authentication_error"
	case statusCode == 403:
		return "permission_error"
	case statusCode == 402:
		return "over_budget"
	case statusCode == 429:
		return "rate_limited"
	case statusCode == 408 || statusCode == 504:
		return "timeout"
	case statusCode == 503 || identifiers.has("provider_unavailable"):
		return "provider_unavailable"
	case statusCode == 529:
		return "provider_overloaded"
	case statusCode == 413:
		return "request_too_large"
	case statusCode >= 500:
		return "provider_error"
	case statusCode == 404:
		// The catalog already resolved a known upstream model. A provider 404
		// therefore means that the selected deployment is unavailable or drifted.
		return "model_unavailable"
	case statusCode == 410:
		// Azure answers a retired deployment with 410 Gone.
		return "model_retired"
	case statusCode == 400 || statusCode == 409 || statusCode == 415 || statusCode == 422:
		return "invalid_request"
	case identifiers.has("invalid_request", "invalid_request_error", "bad_request_error", "invalid_prompt"):
		// A generic invalid-request type is useful when status is absent. It must
		// not hide a more reliable 404, 429, or 5xx status.
		return "invalid_request"
	default:
		return "provider_error"
	}
}

// messageRefusal reads the refusals that only their message tells apart from a refused request.
// Another pair can serve them:
//   - The account behind the key refuses, rather than the request: Anthropic's spend cap and the
//     spend limits that an account's owner sets
//     (https://platform.claude.com/docs/en/api/rate-limits#setting-your-own-spend-limit), a
//     credit balance too low to start, and an inference_geo that the key's workspace does not
//     allow (400 "inference_geo 'global' is not allowed for this workspace. Allowed values:
//     ['us']"). They read as the account's quota and access errors.
//   - The prompt is longer than the deployment's context window, which another deployment of the
//     model can have larger: Anthropic's 400 "prompt is too long: 215000 tokens > 200000
//     maximum", also on Bedrock and Vertex, Bedrock's "Input is too long for requested model.",
//     vLLM's "This model's maximum context length is 32768 tokens. However, you requested ..."
//     and SGLang's "The input (40000 tokens) is longer than the model's context length (32768
//     tokens)." on Chutes.
func messageRefusal(bifrostErr *schemas.BifrostError) string {
	if bifrostErr.Error == nil || len(bifrostErr.Error.Message) > maxMessageRefusalBytes {
		return ""
	}
	message := strings.ToLower(strings.TrimSpace(bifrostErr.Error.Message))
	switch {
	case strings.HasPrefix(message, "you have reached your ") && strings.Contains(message, "api usage limits"),
		strings.HasPrefix(message, "your credit balance is too low"):
		return "over_budget"
	case strings.HasPrefix(message, "inference_geo ") && strings.Contains(message, " is not allowed for this workspace"),
		// OpenAI's restricted key that lacks a permission, as a 401, sometimes without missing_scope.
		strings.HasPrefix(message, "you have insufficient permissions for this operation"):
		return "permission_error"
	// AWS quarantines an access key found in public, and its denial names the policy.
	case strings.Contains(message, "awscompromisedkeyquarantine"):
		return "authentication_error"
	case strings.HasPrefix(message, "prompt is too long: "),
		strings.HasPrefix(message, "input is too long for requested model"),
		strings.HasPrefix(message, "this model's maximum context length is "),
		strings.HasPrefix(message, "the input (") && strings.Contains(message, " is longer than the model's context length"):
		return "context_length_exceeded"
	// Claude's filter of its own output answers with a generic 400 invalid_request_error.
	case strings.HasPrefix(message, "output blocked by content filtering policy"):
		return "content_filter"
	}
	return ""
}

// maxMessageRefusalBytes bounds the messages that messageRefusal and flaggedPrompt read; those
// they know are under 500 bytes.
const maxMessageRefusalBytes = 1024

// flaggedPrompt reports OpenAI's invalid_prompt for a prompt that its safety checks flagged:
// "Invalid prompt: your prompt was flagged as potentially violating our usage policy." and
// "Invalid prompt: we've limited access to this content for safety reasons." OpenAI sends the
// same 400 code for other prompts that it refuses, such as "Sorry! We've encountered an issue
// with repetitive patterns in your prompt.", which stay invalid requests, so the refusal rate
// counts only what a safety check refused. The attempt's error_code keeps invalid_prompt either way.
func flaggedPrompt(bifrostErr *schemas.BifrostError, identifiers errorIdentifierSet) bool {
	if !identifiers.has("invalid_prompt") || bifrostErr.Error == nil || len(bifrostErr.Error.Message) > maxMessageRefusalBytes {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(bifrostErr.Error.Message))
	return strings.HasPrefix(message, "invalid prompt: ") &&
		(strings.Contains(message, "usage polic") || strings.Contains(message, "safety reasons"))
}

// maxErrorCodeBytes bounds an attempt's error_code. The longest that providers send are under 40
// bytes, such as unsupported_country_region_territory and ServiceQuotaExceededException.
const maxErrorCodeBytes = 48

// providerErrorCode is the most specific identifier in a provider's error reply: its code, else
// its type, such as OpenAI's invalid_prompt, Anthropic's overloaded_error or Bedrock's
// ValidationException. The status says what the failure means to us; the code keeps what the
// provider said, which the status may generalize. A value that is not a short identifier, or
// that only repeats an HTTP status, names nothing. Errors that the gateway or core raised
// themselves, such as a lost connection, have no provider code.
func providerErrorCode(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil || bifrostErr.IsBifrostError {
		return ""
	}
	candidates := []*string{bifrostErr.Type}
	if bifrostErr.Error != nil {
		candidates = []*string{bifrostErr.Error.Code, bifrostErr.Error.Type, bifrostErr.Type}
	}
	for _, value := range candidates {
		if value != nil {
			if code := strings.TrimSpace(*value); errorCodeText(code) {
				return code
			}
		}
	}
	return ""
}

func errorCodeText(code string) bool {
	if code == "" || len(code) > maxErrorCodeBytes || !isASCIILetter(code[0]) {
		return false
	}
	for index := 1; index < len(code); index++ {
		character := code[index]
		if !isASCIILetter(character) && (character < '0' || character > '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func isASCIILetter(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
}

type errorIdentifierSet map[string]struct{}

func upstreamErrorIdentifiers(bifrostErr *schemas.BifrostError) errorIdentifierSet {
	identifiers := errorIdentifierSet{}
	if bifrostErr == nil {
		return identifiers
	}
	add := func(value *string) {
		if value == nil {
			return
		}
		if len(*value) > maxProviderReasonBytes {
			return
		}
		identifier := strings.ToLower(strings.TrimSpace(*value))
		if identifier != "" {
			identifiers[identifier] = struct{}{}
		}
	}
	add(bifrostErr.Type)
	if bifrostErr.Error != nil {
		add(bifrostErr.Error.Type)
		add(bifrostErr.Error.Code)
	}
	return identifiers
}

func (identifiers errorIdentifierSet) has(values ...string) bool {
	for _, value := range values {
		if _, ok := identifiers[strings.ToLower(value)]; ok {
			return true
		}
	}
	return false
}

func finishReason(resp *schemas.BifrostResponse) string {
	if resp == nil {
		return ""
	}
	choices := []schemas.BifrostResponseChoice{}
	if resp.ChatResponse != nil {
		choices = resp.ChatResponse.Choices
	} else if resp.TextCompletionResponse != nil {
		choices = resp.TextCompletionResponse.Choices
	}
	for _, choice := range choices {
		if choice.FinishReason != nil {
			return boundedTelemetryValue(*choice.FinishReason, maxProviderReasonBytes)
		}
	}
	responses := resp.ResponsesResponse
	if responses == nil && resp.ResponsesStreamResponse != nil {
		responses = resp.ResponsesStreamResponse.Response
	}
	switch {
	case responses == nil:
		return ""
	case responses.StopReason != nil:
		return boundedTelemetryValue(*responses.StopReason, maxProviderReasonBytes)
	case responses.IncompleteDetails != nil:
		// OpenAI's Responses API says why a response stopped early, such as max_output_tokens,
		// only in its incomplete details.
		return boundedTelemetryValue(responses.IncompleteDetails.Reason, maxProviderReasonBytes)
	}
	return ""
}

func providerResponseID(resp *schemas.BifrostResponse) string {
	if resp == nil {
		return ""
	}
	if resp.ChatResponse != nil {
		return boundedTelemetryValue(resp.ChatResponse.ID, maxProviderResponseIDBytes)
	}
	if resp.TextCompletionResponse != nil {
		return boundedTelemetryValue(resp.TextCompletionResponse.ID, maxProviderResponseIDBytes)
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.ID != nil {
		return boundedTelemetryValue(*resp.ResponsesResponse.ID, maxProviderResponseIDBytes)
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.ID != nil {
		return boundedTelemetryValue(*resp.ResponsesStreamResponse.Response.ID, maxProviderResponseIDBytes)
	}
	return ""
}

// Provider names, reasons and request IDs are short printable ASCII. Other
// values are dropped, which also keeps out NUL, which PostgreSQL JSON rejects.
func boundedTelemetryValue(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) > maximum {
		return ""
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return ""
		}
	}
	return value
}

// PricedMeter records the quantity used in the charge, including a known free rate.
func PricedMeter(quantity, rateKey, rateUSD, usd string) EventMeter {
	return EventMeter{Quantity: quantity, RateKey: &rateKey, RateUSD: &rateUSD, USD: &usd}
}

// IsInformationalMeter identifies quantities that never carry prices.
func IsInformationalMeter(key string) bool {
	switch key {
	case MeterInputTextBytes, MeterInputFileCount, MeterInputFileURLCount, MeterInputInlineFileBytes, MeterOutputTextBytes, MeterReasoningTextBytes,
		MeterClientStopOutputTextBytes, MeterClientStopReasoningTextBytes, MeterEstimatedInputTokens, MeterTotalInputTokens, MeterTotalOutputTokens, MeterTotalTokens, MeterTotalCacheWriteTokens, MeterHostedToolCalls, MeterClientToolCalls,
		MeterCheckedClientToolCalls, MeterInvalidClientToolCalls, MeterCheckedStructuredOutputs, MeterInvalidStructuredOutputs:
		return true
	default:
		return false
	}
}

func ValidateMeters(pricing EventMeters) (EventMeters, error) {
	cloned := make(EventMeters, len(pricing))
	for key, meter := range pricing {
		if key == "" || strings.TrimSpace(key) != key {
			return nil, fmt.Errorf("invalid meter identity")
		}
		quantity, err := ParseNonnegativeInteger(meter.Quantity)
		if err != nil || !quantity.IsUint64() {
			return nil, fmt.Errorf("invalid meter quantity for %s", key)
		}
		if meter.RateKey == nil && meter.RateUSD == nil && meter.USD == nil {
			// A count without a price is not evidence of a free rate.
		} else {
			if IsInformationalMeter(key) {
				return nil, fmt.Errorf("informational meter cannot be priced: %s", key)
			}
			if meter.RateKey == nil || meter.RateUSD == nil || meter.USD == nil ||
				*meter.RateKey == "" || strings.TrimSpace(*meter.RateKey) != *meter.RateKey {
				return nil, fmt.Errorf("incomplete meter pricing for %s", key)
			}
			rate, rateErr := ParseUSD(*meter.RateUSD)
			amount, amountErr := ParseUSD(*meter.USD)
			if rateErr != nil || amountErr != nil ||
				(quantity.Sign() == 0 && amount.Sign() != 0) ||
				(quantity.Sign() > 0 && (rate.Sign() == 0) != (amount.Sign() == 0)) {
				return nil, fmt.Errorf("invalid meter amount for %s", key)
			}
		}
		cloned[key] = meter
	}
	return cloned, nil
}

func uint32Duration(value time.Duration) uint32 {
	if value <= 0 {
		return 0
	}
	return uint32FromInt64(value.Milliseconds())
}

func uint32FromInt64(value int64) uint32 {
	if value <= 0 {
		return 0
	}
	if value > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}
