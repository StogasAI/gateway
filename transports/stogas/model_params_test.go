package stogas

import (
	"context"
	"testing"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestSeedBifrostModelParamsSetsResolvedMaxOutputTokens(t *testing.T) {
	model := "stogas-test-model-cache-set"
	defer providerUtils.DeleteModelParams(model)

	SeedBifrostModelParams(&catalog.ResolvedRequest{
		Model:      model,
		Deployment: catalog.Deployment{MaxOutputTokens: 12345},
	})

	maxOutputTokens, ok := providerUtils.GetMaxOutputTokens(model)
	if !ok || maxOutputTokens != 12345 {
		t.Fatalf("expected max output tokens 12345, got %d ok=%v", maxOutputTokens, ok)
	}
}

func TestSeedBifrostModelParamsPreservesExistingModelParams(t *testing.T) {
	model := "stogas-test-model-cache-merge"
	defer providerUtils.DeleteModelParams(model)

	multiRegionOnly := true
	providerUtils.SetModelParams(model, providerUtils.ModelParams{IsVertexMultiRegionOnly: &multiRegionOnly})

	SeedBifrostModelParams(&catalog.ResolvedRequest{
		Model:      model,
		Deployment: catalog.Deployment{MaxOutputTokens: 6789},
	})

	params, ok := providerUtils.GetModelParams(model)
	if !ok {
		t.Fatalf("expected seeded model params")
	}
	if params.MaxOutputTokens == nil || *params.MaxOutputTokens != 6789 {
		t.Fatalf("expected max output tokens 6789, got %#v", params.MaxOutputTokens)
	}
	if params.IsVertexMultiRegionOnly == nil || !*params.IsVertexMultiRegionOnly {
		t.Fatalf("expected existing vertex multi-region flag to be preserved")
	}
}

func TestPreLLMHookSeedsBifrostModelParams(t *testing.T) {
	model := "stogas-test-plugin-model-cache"
	defer providerUtils.DeleteModelParams(model)

	resolution := &catalog.ResolvedRequest{
		RequestType: schemas.ChatCompletionRequest,
		Provider:    schemas.OpenAI,
		Model:       model,
		Deployment:  catalog.Deployment{MaxOutputTokens: 4567},
		Hold:        catalog.HoldEstimate{ProviderKey: "openai", ProductKey: model, MaxUSDAtoms: "1000"},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, "11111111-1111-1111-1111-111111111111")
	SetAPIKey(ctx, "sk-test", nil)
	SetCatalogResolution(ctx, resolution)

	plugin := &Plugin{billing: &fakeBillingAuthorizer{
		results: []*BillingAuthorization{{HoldID: "hold-1"}},
	}}
	req := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.OpenAI,
			Model:    model,
		},
	}

	returnedReq, shortCircuit, err := plugin.PreLLMHook(ctx, req)
	if err != nil {
		t.Fatalf("PreLLMHook returned error: %v", err)
	}
	if shortCircuit != nil {
		t.Fatalf("PreLLMHook returned short circuit: %#v", shortCircuit)
	}
	if returnedReq != req {
		t.Fatalf("expected original request pointer")
	}

	maxOutputTokens, ok := providerUtils.GetMaxOutputTokens(model)
	if !ok || maxOutputTokens != 4567 {
		t.Fatalf("expected max output tokens 4567, got %d ok=%v", maxOutputTokens, ok)
	}
}
