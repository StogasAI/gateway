package billing

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

type EventInput struct {
	UpstreamCostUSDAtoms       string
	Authorization              *Authorization
	Cancelled                  bool
	ClientStoppedAt            time.Time
	CatalogDigest              string
	Error                      *schemas.BifrostError
	Pricing                    EventPricing
	Plugins                    plugins.Metrics
	ProviderAttempts           []ProviderAttemptInput
	ProviderCompletedAt        time.Time
	ProviderStartedAt          time.Time
	TTFTMS                     *uint32
	ProviderOutputObserved     bool
	CacheReadSavingsUSDAtoms   *string
	CacheWriteOverheadUSDAtoms *string
	NodeID                     string
	GatewayVersion             string
	RequestType                string
	CatalogNodeIDs             []string
	Response                   *schemas.BifrostResponse
	StartedAt                  time.Time
}

type ProviderAttemptInput struct {
	Provider       string
	StartedAt      time.Time
	CompletedAt    time.Time
	OutputObserved bool
	Response       *schemas.BifrostResponse
	Error          *schemas.BifrostError
}

func NewRequestEvent(input EventInput) (RequestEvent, error) {
	authorization := input.Authorization
	if authorization == nil {
		authorization = &Authorization{}
	}
	startedAt := input.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	finishedAt := time.Now().UTC()
	createdAt := startedAt
	if !authorization.CreatedAt.IsZero() {
		createdAt = authorization.CreatedAt
	}
	totalTimeMS := uint32Duration(finishedAt.Sub(startedAt))
	upstreamTimeMS := totalTimeMS
	if !input.ProviderStartedAt.IsZero() && !input.ProviderStartedAt.Before(startedAt) {
		providerCompletedAt := input.ProviderCompletedAt
		if providerCompletedAt.IsZero() || providerCompletedAt.Before(input.ProviderStartedAt) {
			providerCompletedAt = finishedAt
		}
		upstreamTimeMS = uint32Duration(providerCompletedAt.Sub(input.ProviderStartedAt))
	} else if extra := responseExtraFields(input.Response); extra != nil && extra.Latency > 0 {
		upstreamTimeMS = uint32FromInt64(extra.Latency)
	}
	if upstreamTimeMS > totalTimeMS {
		upstreamTimeMS = totalTimeMS
	}
	var clientStopMS *uint32
	if !input.ClientStoppedAt.IsZero() && !input.ClientStoppedAt.Before(startedAt) {
		value := uint32Duration(input.ClientStoppedAt.Sub(startedAt))
		if value > totalTimeMS {
			value = totalTimeMS
		}
		clientStopMS = &value
	}
	upstreamCostRaw := input.UpstreamCostUSDAtoms
	if upstreamCostRaw == "" {
		upstreamCostRaw = ZeroChargeUSDAtoms
	}
	upstreamCostUSDAtoms, err := ParseUSDAtoms(upstreamCostRaw)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("invalid upstream cost: %w", err)
	}
	ttftMS := cloneUint32Pointer(input.TTFTMS)
	if !isStreamingRequest(input.RequestType) {
		ttftMS = nil
	} else if ttftMS != nil && *ttftMS > totalTimeMS {
		*ttftMS = totalTimeMS
	}
	pricing, analyticsQuantities, err := validateEventPricing(input.Pricing)
	if err != nil {
		return RequestEvent{}, err
	}
	billedCostUSDAtoms := calculateBilledCostUSDAtoms(authorization, upstreamCostUSDAtoms)
	cacheReadSavingsUSDAtoms, err := requestOptionalUSDAtoms(
		input.CacheReadSavingsUSDAtoms,
		"cache read savings",
	)
	if err != nil {
		return RequestEvent{}, err
	}
	cacheWriteOverheadUSDAtoms, err := requestOptionalUSDAtoms(
		input.CacheWriteOverheadUSDAtoms,
		"cache write overhead",
	)
	if err != nil {
		return RequestEvent{}, err
	}
	providerAttempts := requestProviderAttempts(input, authorization, upstreamTimeMS)

	return RequestEvent{
		RequestID:                  authorization.RequestID,
		CreatedAt:                  createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		StogasAPIKeyID:             authorization.KeyID,
		StogasGrantID:              authorization.GrantID,
		StogasUserID:               authorization.UserID,
		StogasOrganizationID:       authorization.OrganizationID,
		StogasWorkspaceID:          authorization.WorkspaceID,
		RequestType:                normalizeRequestType(input.RequestType),
		Cancelled:                  input.Cancelled,
		ClientStopMS:               clientStopMS,
		CatalogDigest:              strings.TrimSpace(input.CatalogDigest),
		ProviderAttempts:           providerAttempts,
		StogasProcessingSuccess:    true,
		StogasBillingStatus:        calculateSettlementStatus(authorization.AuthorizedBilledCostUSDAtoms, authorization.AvailableBalanceUSDAtoms, billedCostUSDAtoms),
		NodeID:                     strings.ToLower(strings.TrimSpace(input.NodeID)),
		TotalTimeMS:                totalTimeMS,
		Timings:                    requestTimings(input, startedAt, finishedAt, totalTimeMS),
		TTFTMS:                     ttftMS,
		UpstreamCostUSDAtoms:       upstreamCostUSDAtoms.String(),
		BilledCostUSDAtoms:         billedCostUSDAtoms.String(),
		CacheReadSavingsUSDAtoms:   cacheReadSavingsUSDAtoms,
		CacheWriteOverheadUSDAtoms: cacheWriteOverheadUSDAtoms,
		Pricing:                    pricing,
		Plugins:                    input.Plugins,
		GatewayVersion:             strings.TrimSpace(input.GatewayVersion),
		CatalogNodeIDs:             append([]string(nil), input.CatalogNodeIDs...),
		analyticsQuantities:        analyticsQuantities,
	}, nil
}

func requestTimings(input EventInput, startedAt time.Time, finishedAt time.Time, totalTimeMS uint32) RequestTimings {
	if input.ProviderStartedAt.IsZero() || input.ProviderStartedAt.Before(startedAt) {
		return RequestTimings{AdmissionMS: totalTimeMS}
	}

	admissionMS := min(uint32Duration(input.ProviderStartedAt.Sub(startedAt)), totalTimeMS)
	providerCompletedAt := input.ProviderCompletedAt
	if providerCompletedAt.IsZero() || providerCompletedAt.Before(input.ProviderStartedAt) {
		providerCompletedAt = finishedAt
	}
	providerMS := min(
		uint32Duration(providerCompletedAt.Sub(input.ProviderStartedAt)),
		totalTimeMS-admissionMS,
	)
	return RequestTimings{
		AdmissionMS: admissionMS,
		ProviderMS:  providerMS,
		ResponseMS:  totalTimeMS - admissionMS - providerMS,
	}
}

func requestProviderAttempts(input EventInput, authorization *Authorization, fallbackLatencyMS uint32) []ProviderAttempt {
	if len(input.ProviderAttempts) == 0 {
		if input.ProviderStartedAt.IsZero() {
			return []ProviderAttempt{}
		}
		return []ProviderAttempt{{
			Provider:          authorization.ProviderKey,
			Status:            providerAttemptStatus(input.Error, input.Response),
			StatusCode:        providerStatusCode(input.Error),
			LatencyMS:         fallbackLatencyMS,
			OutputObserved:    input.ProviderOutputObserved,
			ProviderRequestID: upstreamRequestID(input.Response),
			FinishReason:      finishReason(input.Response),
			UpstreamByok:      normalizedUpstreamByok(authorization),
		}}
	}

	attempts := make([]ProviderAttempt, len(input.ProviderAttempts))
	for index, observed := range input.ProviderAttempts {
		provider := strings.TrimSpace(observed.Provider)
		if provider == "" {
			provider = authorization.ProviderKey
		}
		attempts[index] = ProviderAttempt{
			Provider:          provider,
			Status:            providerAttemptStatus(observed.Error, observed.Response),
			StatusCode:        providerStatusCode(observed.Error),
			LatencyMS:         uint32Duration(observed.CompletedAt.Sub(observed.StartedAt)),
			OutputObserved:    observed.OutputObserved,
			ProviderRequestID: upstreamRequestID(observed.Response),
			FinishReason:      finishReason(observed.Response),
			UpstreamByok:      normalizedUpstreamByok(authorization),
		}
	}
	return attempts
}

func providerAttemptStatus(bifrostErr *schemas.BifrostError, response *schemas.BifrostResponse) string {
	if bifrostErr != nil {
		return NormalizeUpstreamStatus(bifrostErr)
	}
	if providerResponseContentFiltered(response) {
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

func requestOptionalUSDAtoms(raw *string, name string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := ParseUSDAtoms(*raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", name, err)
	}
	normalized := value.String()
	return &normalized, nil
}

func (event RequestEvent) FinalProviderAttempt() (ProviderAttempt, bool) {
	if len(event.ProviderAttempts) == 0 {
		return ProviderAttempt{}, false
	}
	return event.ProviderAttempts[len(event.ProviderAttempts)-1], true
}

func (event RequestEvent) ProviderDurationMS() uint32 {
	var providerDurationMS uint64
	for _, attempt := range event.ProviderAttempts {
		providerDurationMS += uint64(attempt.LatencyMS)
	}
	return saturatingUint32(providerDurationMS)
}

func cloneUint32Pointer(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func normalizedUpstreamByok(authorization *Authorization) string {
	if authorization == nil || strings.TrimSpace(authorization.UpstreamByok) == "" {
		return "stogas"
	}
	return strings.TrimSpace(authorization.UpstreamByok)
}

func calculateBilledCostUSDAtoms(authorization *Authorization, upstreamCostUSDAtoms *big.Int) *big.Int {
	if normalizedUpstreamByok(authorization) == "stogas" {
		return new(big.Int).Set(upstreamCostUSDAtoms)
	}
	numerator := new(big.Int).Mul(upstreamCostUSDAtoms, big.NewInt(2))
	numerator.Add(numerator, big.NewInt(99))
	return numerator.Quo(numerator, big.NewInt(100))
}

func isStreamingRequest(requestType string) bool {
	switch requestType {
	case string(schemas.ChatCompletionStreamRequest), string(schemas.ResponsesStreamRequest):
		return true
	default:
		return false
	}
}

func responseExtraFields(resp *schemas.BifrostResponse) *schemas.BifrostResponseExtraFields {
	if resp == nil {
		return nil
	}
	return resp.GetExtraFields()
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
	case identifiers.has(schemas.RequestTimedOut, schemas.ProviderConnectionFailed):
		// Bifrost uses 502 for a provider connection failure. Match its stable
		// type before HTTP status so transport failures keep their meaning.
		return "network_error"
	case identifiers.has("authentication_error", "invalid_api_key", "unauthorized", "upstream_authentication_failed"):
		return "authentication_error"
	case identifiers.has("permission_error", "permission_denied", "forbidden", "upstream_access_denied"):
		return "permission_error"
	case identifiers.has("billing_error", "insufficient_quota", "over_budget", "upstream_quota_exceeded"):
		return "over_budget"
	case identifiers.has("rate_limit_error", "rate_limited", "too_many_requests", "upstream_rate_limit_error"):
		return "rate_limited"
	case identifiers.has("content_filter", "content_filter_error", "safety_error"):
		return "content_filter"
	case statusCode == 401:
		return "authentication_error"
	case statusCode == 403:
		return "permission_error"
	case statusCode == 402:
		return "over_budget"
	case statusCode == 429:
		return "rate_limited"
	case statusCode == 408 || statusCode == 504:
		return "network_error"
	case statusCode >= 500:
		return "provider_error"
	case statusCode == 404:
		// The catalog already resolved a known upstream model. A provider 404
		// therefore means that the selected deployment is unavailable or drifted.
		return "provider_error"
	case statusCode == 400 || statusCode == 409 || statusCode == 413 || statusCode == 415 || statusCode == 422:
		return "invalid_request"
	case identifiers.has("invalid_request", "invalid_request_error", "bad_request_error", "request_too_large"):
		// A generic invalid-request type is useful when status is absent. It must
		// not hide a more reliable 404, 429, or 5xx status.
		return "invalid_request"
	default:
		return "provider_error"
	}
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

func normalizeRequestType(requestType string) string {
	switch requestType {
	case string(schemas.ChatCompletionRequest):
		return "chat_completion_request"
	case string(schemas.ResponsesRequest):
		return "responses_request"
	default:
		return requestType
	}
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
			return *choice.FinishReason
		}
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.StopReason != nil {
		return *resp.ResponsesResponse.StopReason
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.StopReason != nil {
		return *resp.ResponsesStreamResponse.Response.StopReason
	}
	return ""
}

func upstreamRequestID(resp *schemas.BifrostResponse) string {
	if resp == nil {
		return ""
	}
	if resp.ChatResponse != nil {
		return resp.ChatResponse.ID
	}
	if resp.TextCompletionResponse != nil {
		return resp.TextCompletionResponse.ID
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.ID != nil {
		return *resp.ResponsesResponse.ID
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.ID != nil {
		return *resp.ResponsesStreamResponse.Response.ID
	}
	return ""
}

func validateEventPricing(pricing EventPricing) (EventPricing, map[string]uint64, error) {
	cloned := make(EventPricing, len(pricing))
	quantities := make(map[string]uint64, len(pricing))
	for key, meter := range pricing {
		if key == "" || strings.TrimSpace(key) != key || meter.RateKey == "" || strings.TrimSpace(meter.RateKey) != meter.RateKey {
			return nil, nil, fmt.Errorf("invalid pricing meter identity")
		}
		quantity, err := ParseNonnegativeInteger(meter.Quantity)
		if err != nil || quantity.Sign() <= 0 || !quantity.IsUint64() {
			return nil, nil, fmt.Errorf("invalid pricing meter quantity for %s", key)
		}
		rate, rateErr := ParseUSDAtoms(meter.RateUSDAtoms)
		amount, amountErr := ParseUSDAtoms(meter.USDAtoms)
		if rateErr != nil || amountErr != nil || rate.Sign() <= 0 || amount.Sign() <= 0 {
			return nil, nil, fmt.Errorf("invalid pricing meter amount for %s", key)
		}
		cloned[key] = meter
		quantities[key] = quantity.Uint64()
	}
	return cloned, quantities, nil
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
