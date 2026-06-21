package catalog

import (
	"errors"
	"net/http"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/providers"
	openaiadapter "github.com/maximhq/bifrost/transports/stogas/providers/openai"
)

var providerAdapters = map[schemas.ModelProvider]providers.Adapter{
	schemas.OpenAI: openaiadapter.Adapter{},
}

var ErrProviderContainersUnsupported = APIError{
	StatusCode: http.StatusBadRequest,
	Type:       ErrorTypeInvalidRequest,
	Message:    "Provider-hosted containers are not supported by Stogas",
}

func validateProviderRequest(modelProvider schemas.ModelProvider, route Route, deployment Deployment, outputTokenLimit int, pricing requestPricingContext) error {
	adapter, ok := providerAdapters[modelProvider]
	if !ok {
		return nil
	}
	return providerPolicyError(adapter.ValidateRequest(providerRequestContext(route, deployment, outputTokenLimit, pricing)))
}

func appendProviderExtraHoldMeterCosts(meters []MeterEstimate, modelProvider schemas.ModelProvider, deployment Deployment, outputTokenLimit int, inputTokenLimit int, pricingContext requestPricingContext) []MeterEstimate {
	adapter, ok := providerAdapters[modelProvider]
	if !ok {
		return meters
	}
	return append(meters, adapter.ExtraHoldMeters(providerRequestContext(pricingContext.Route, deployment, outputTokenLimit, pricingContext), outputTokenLimit, inputTokenLimit)...)
}

func appendProviderExtraSettlementMeterCosts(meters []MeterEstimate, resolution *ResolvedRequest) []MeterEstimate {
	if resolution == nil {
		return meters
	}
	adapter, ok := providerAdapters[resolution.Provider]
	if !ok {
		return meters
	}
	return append(meters, adapter.ExtraSettlementMeters(providerRequestContext(resolution.Route, resolution.Deployment, 0, resolution.pricing))...)
}

func AllowsUpstreamRequestHeader(modelProvider schemas.ModelProvider, model string, route Route, header string) bool {
	adapter, ok := providerAdapters[modelProvider]
	if !ok {
		return false
	}
	return adapter.AllowUpstreamRequestHeader(providers.HeaderContext{
		Provider: modelProvider,
		Model:    model,
		Route:    providers.Route(route),
		Header:   strings.ToLower(strings.TrimSpace(header)),
	})
}

func FilterProviderResponseHeaders(modelProvider schemas.ModelProvider, model string, headers map[string]string) map[string]string {
	adapter, ok := providerAdapters[modelProvider]
	if !ok {
		return nil
	}
	return adapter.FilterProviderResponseHeaders(providers.HeaderContext{
		Provider: modelProvider,
		Model:    model,
		Header:   "",
	}, headers)
}

func providerRequestContext(route Route, deployment Deployment, outputTokenLimit int, pricing requestPricingContext) providers.RequestContext {
	return providers.RequestContext{
		Route: providers.Route(route),
		Model: deployment.Model,
		Deployment: providers.Deployment{
			Model:               deployment.Model,
			ContextWindowTokens: deployment.ContextWindowTokens,
			Pricing:             providers.Pricing(deployment.Pricing),
			ReasoningSupported:  deployment.ReasoningSupported,
		},
		OutputTokenLimit:    outputTokenLimit,
		HasWebSearchOptions: pricing.HasWebSearchOptions,
		SearchContextSize:   pricing.SearchContextSize,
		ToolsParseFailed:    pricing.ToolsParseFailed,
		RawBody:             pricing.RawBody,
		ToolTypes:           pricing.ToolTypes,
		RawTools:            pricing.RawTools,
	}
}

func providerPolicyError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, providers.ErrProviderContainers):
		return ErrProviderContainersUnsupported
	case errors.Is(err, providers.ErrUnsupportedTool), errors.Is(err, providers.ErrInvalidProviderToolSpec):
		return ErrUnsupportedTool
	case errors.Is(err, providers.ErrUnsupportedParameter):
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Parameter is not supported by Stogas provider policy"}
	case errors.Is(err, providers.ErrUnsupportedInput):
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Input modality is not supported by Stogas billing policy"}
	case errors.Is(err, providers.ErrOutputTokenLimitTooLow):
		return ErrParameterTooLarge
	default:
		return err
	}
}
