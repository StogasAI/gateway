package stogas

import (
	"strconv"
	"strings"

	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// PrepareProviderRequest applies the final provider-owned body policy, runs the
// provider's complete local converter and serializer, and installs those bytes
// for dispatch. It has no client or transport dependency and cannot perform
// network I/O. A later operation that can change the wire body must invalidate
// the prepared descriptor so Bifrost performs its normal conversion.
func PrepareProviderRequest(ctx *schemas.BifrostContext, state *State, request *schemas.BifrostRequest) error {
	if ctx == nil || request == nil {
		return catalog.ErrUnsupportedRequest
	}
	ctx.ClearValue(schemas.BifrostContextKeyPreparedRequestBody)
	ctx.ClearValue(schemas.BifrostContextKeyUseRawRequestBody)
	ctx.ClearValue(schemas.BifrostContextKeyRequestModelInfo)
	request.SetRawRequestBody(nil)

	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	resolution := state.Resolution
	if request.RequestType != resolution.RequestType {
		return catalog.ErrUnsupportedRequest
	}
	trustedRequestType, ok := ctx.Value(schemas.BifrostContextKeyHTTPRequestType).(schemas.RequestType)
	if !ok || trustedRequestType != request.RequestType {
		return catalog.ErrUnsupportedRequest
	}
	if !schemas.SetRequestModelInfo(ctx, schemas.RequestModelInfo{
		Provider:        resolution.Provider,
		WireModel:       resolution.Model,
		CanonicalModel:  resolution.Deployment.ModelID,
		MaxOutputTokens: resolvedOutputLimit(resolution),
	}) {
		return catalog.ErrUnsupportedRequest
	}
	prepared := false
	defer func() {
		if !prepared {
			ctx.ClearValue(schemas.BifrostContextKeyRequestModelInfo)
		}
	}()

	var (
		body       []byte
		bifrostErr *schemas.BifrostError
	)
	switch {
	case request.ChatRequest != nil && request.ResponsesRequest == nil:
		chat := request.ChatRequest
		if !isChatRequestType(request.RequestType) || chat.Provider != resolution.Provider || chat.Model != resolution.Model {
			return catalog.ErrUnsupportedRequest
		}
		sanitizeChatProviderFields(ctx, chat)
		applyRequiredChatOutputLimit(ctx, resolution, chat)
		body, bifrostErr = prepareChatProviderBody(ctx, chat, request.RequestType == schemas.ChatCompletionStreamRequest)
	case request.ResponsesRequest != nil && request.ChatRequest == nil:
		responses := request.ResponsesRequest
		if !isResponsesRequestType(request.RequestType) || responses.Provider != resolution.Provider || responses.Model != resolution.Model {
			return catalog.ErrUnsupportedRequest
		}
		sanitizeResponsesProviderFields(ctx, responses)
		applyRequiredResponsesOutputLimit(ctx, resolution, responses)
		body, bifrostErr = prepareResponsesProviderBody(ctx, responses, request.RequestType == schemas.ResponsesStreamRequest)
	default:
		return catalog.ErrUnsupportedRequest
	}
	if bifrostErr != nil || len(body) == 0 {
		return invalidRequest("Invalid request for selected provider")
	}

	if !providerutils.SetPreparedRequestBody(ctx, request.RequestType, resolution.Provider, resolution.Model, body) {
		return catalog.ErrUnsupportedRequest
	}
	prepared = true
	return nil
}

func resolvedOutputLimit(resolution *catalog.ResolvedRequest) int {
	if resolution == nil {
		return 0
	}
	if limit := resolution.OutputTokenLimit(); limit > 0 {
		return limit
	}
	return resolution.Deployment.MaxOutputTokens
}

func applyRequiredChatOutputLimit(ctx *schemas.BifrostContext, resolution *catalog.ResolvedRequest, request *schemas.BifrostChatRequest) {
	if request == nil || !usesAnthropicWireFormat(ctx, request.Provider, request.Model) {
		return
	}
	if request.Params == nil {
		request.Params = &schemas.ChatParameters{}
	}
	if request.Params.MaxCompletionTokens != nil {
		return
	}
	if limit := resolvedOutputLimit(resolution); limit > 0 {
		request.Params.MaxCompletionTokens = schemas.Ptr(limit)
	}
}

func applyRequiredResponsesOutputLimit(ctx *schemas.BifrostContext, resolution *catalog.ResolvedRequest, request *schemas.BifrostResponsesRequest) {
	if request == nil || !usesAnthropicWireFormat(ctx, request.Provider, request.Model) {
		return
	}
	if request.Params == nil {
		request.Params = &schemas.ResponsesParameters{}
	}
	if request.Params.MaxOutputTokens != nil {
		return
	}
	if limit := resolvedOutputLimit(resolution); limit > 0 {
		request.Params.MaxOutputTokens = schemas.Ptr(limit)
	}
}

func isChatRequestType(requestType schemas.RequestType) bool {
	return requestType == schemas.ChatCompletionRequest || requestType == schemas.ChatCompletionStreamRequest
}

func isResponsesRequestType(requestType schemas.RequestType) bool {
	return requestType == schemas.ResponsesRequest || requestType == schemas.ResponsesStreamRequest
}

func sanitizeChatProviderFields(ctx *schemas.BifrostContext, request *schemas.BifrostChatRequest) {
	if request.Params == nil {
		request.Params = &schemas.ChatParameters{}
	}
	request.Params.Metadata = nil
	request.Params.SafetyIdentifier = nil
	request.Params.User = nil
	request.Params.Store = nil
	if request.Provider == schemas.OpenAI || (request.Provider == schemas.Azure && !schemas.IsAnthropicModelFamily(ctx, request.Model)) {
		request.Params.Store = schemas.Ptr(false)
	}
}

func sanitizeResponsesProviderFields(ctx *schemas.BifrostContext, request *schemas.BifrostResponsesRequest) {
	if request.Params == nil {
		request.Params = &schemas.ResponsesParameters{}
	}
	request.Params.Metadata = nil
	request.Params.SafetyIdentifier = nil
	request.Params.User = nil
	request.Params.Store = nil
	if request.Provider == schemas.OpenAI || (request.Provider == schemas.Azure && !schemas.IsAnthropicModelFamily(ctx, request.Model)) {
		request.Params.Store = schemas.Ptr(false)
	}
}

func prepareChatProviderBody(ctx *schemas.BifrostContext, request *schemas.BifrostChatRequest, streaming bool) ([]byte, *schemas.BifrostError) {
	switch request.Provider {
	case schemas.OpenAI:
		return prepareOpenAIChatBody(ctx, request, streaming)
	case schemas.Azure:
		if schemas.IsAnthropicModelFamily(ctx, request.Model) {
			return anthropicprovider.BuildAnthropicChatRequestBody(ctx, request, anthropicprovider.AnthropicRequestBuildConfig{
				Provider:    schemas.Azure,
				Model:       request.Model,
				IsStreaming: streaming,
			})
		}
		return prepareOpenAIChatBody(ctx, request, streaming)
	case schemas.Anthropic:
		return anthropicprovider.BuildAnthropicChatRequestBody(ctx, request, anthropicprovider.AnthropicRequestBuildConfig{
			Provider:    schemas.Anthropic,
			IsStreaming: streaming,
		})
	case catalog.ProviderChutes:
		return prepareChutesChatBody(ctx, request, streaming)
	default:
		return nil, providerutils.NewUnsupportedOperationError(requestTypeForChat(streaming), request.Provider)
	}
}

func prepareResponsesProviderBody(ctx *schemas.BifrostContext, request *schemas.BifrostResponsesRequest, streaming bool) ([]byte, *schemas.BifrostError) {
	switch request.Provider {
	case schemas.OpenAI:
		return prepareOpenAIResponsesBody(ctx, request, streaming)
	case schemas.Azure:
		if schemas.IsAnthropicModelFamily(ctx, request.Model) {
			return prepareAnthropicResponsesBody(ctx, request, anthropicprovider.AnthropicRequestBuildConfig{
				Provider:      schemas.Azure,
				Model:         request.Model,
				IsStreaming:   streaming,
				ValidateTools: true,
			})
		}
		return prepareOpenAIResponsesBody(ctx, request, streaming)
	case schemas.Anthropic:
		return prepareAnthropicResponsesBody(ctx, request, anthropicprovider.AnthropicRequestBuildConfig{
			Provider:    schemas.Anthropic,
			IsStreaming: streaming,
		})
	default:
		return nil, providerutils.NewUnsupportedOperationError(requestTypeForResponses(streaming), request.Provider)
	}
}

// prepareAnthropicResponsesBody sends web search and web fetch at their basic
// versions. Core picks newer versions for recent Claude models; those filter
// results with code execution, which keeps container data for up to 30 days,
// and Azure-hosted Claude rejects them.
func prepareAnthropicResponsesBody(ctx *schemas.BifrostContext, request *schemas.BifrostResponsesRequest, config anthropicprovider.AnthropicRequestBuildConfig) ([]byte, *schemas.BifrostError) {
	body, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(ctx, request, config)
	if bifrostErr != nil {
		return nil, bifrostErr
	}
	for index, tool := range providerutils.GetJSONField(body, "tools").Array() {
		toolType := tool.Get("type").String()
		basic := toolType
		switch {
		case strings.HasPrefix(toolType, "web_search_"):
			basic = string(anthropicprovider.AnthropicToolTypeWebSearch20250305)
		case strings.HasPrefix(toolType, "web_fetch_"):
			basic = string(anthropicprovider.AnthropicToolTypeWebFetch20250910)
		}
		if basic == toolType {
			continue
		}
		var err error
		if body, err = providerutils.SetJSONField(body, "tools."+strconv.Itoa(index)+".type", basic); err != nil {
			return nil, providerutils.NewBifrostOperationError(schemas.ErrProviderRequestMarshal, err)
		}
	}
	return body, nil
}

func usesAnthropicWireFormat(ctx *schemas.BifrostContext, provider schemas.ModelProvider, model string) bool {
	return provider == schemas.Anthropic || (provider == schemas.Azure && schemas.IsAnthropicModelFamily(ctx, model))
}

func prepareOpenAIChatBody(ctx *schemas.BifrostContext, request *schemas.BifrostChatRequest, streaming bool) ([]byte, *schemas.BifrostError) {
	return providerutils.CheckContextAndGetRequestBody(ctx, request, func() (providerutils.RequestBodyWithExtraParams, error) {
		wire := openaiprovider.ToOpenAIChatRequest(ctx, request)
		if wire != nil && streaming {
			wire.Stream = schemas.Ptr(true)
			wire.StreamOptions = &schemas.ChatStreamOptions{IncludeUsage: schemas.Ptr(true)}
		}
		return wire, nil
	})
}

func prepareOpenAIResponsesBody(ctx *schemas.BifrostContext, request *schemas.BifrostResponsesRequest, streaming bool) ([]byte, *schemas.BifrostError) {
	return providerutils.CheckContextAndGetRequestBody(ctx, request, func() (providerutils.RequestBodyWithExtraParams, error) {
		wire := openaiprovider.ToOpenAIResponsesRequest(ctx, request)
		if wire != nil && streaming {
			wire.Stream = schemas.Ptr(true)
		}
		return wire, nil
	})
}

func requestTypeForChat(streaming bool) schemas.RequestType {
	if streaming {
		return schemas.ChatCompletionStreamRequest
	}
	return schemas.ChatCompletionRequest
}

func requestTypeForResponses(streaming bool) schemas.RequestType {
	if streaming {
		return schemas.ResponsesStreamRequest
	}
	return schemas.ResponsesRequest
}
