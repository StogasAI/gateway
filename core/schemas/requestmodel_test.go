package schemas

import (
	"context"
	"testing"
)

func TestRequestModelInfoIsBoundToProviderAndWireModel(t *testing.T) {
	ctx := NewBifrostContext(context.Background(), NoDeadline)
	if SetRequestModelInfo(ctx, RequestModelInfo{Provider: OpenAI}) {
		t.Fatal("incomplete request model identity was accepted")
	}
	if !SetRequestModelInfo(ctx, RequestModelInfo{
		Provider:        OpenAI,
		WireModel:       "opaque-deployment",
		CanonicalModel:  "gpt-5.6-terra",
		MaxOutputTokens: 128000,
	}) {
		t.Fatal("valid request model info was rejected")
	}

	info, ok := GetRequestModelInfo(ctx, OpenAI, "opaque-deployment")
	if !ok || info.CanonicalModel != "gpt-5.6-terra" || info.MaxOutputTokens != 128000 {
		t.Fatalf("request model info = %#v ok=%v", info, ok)
	}
	if _, ok := GetRequestModelInfo(ctx, Azure, "opaque-deployment"); ok {
		t.Fatal("request model info matched another provider")
	}
	if _, ok := GetRequestModelInfo(ctx, OpenAI, "other-deployment"); ok {
		t.Fatal("request model info matched another wire model")
	}
	if got := ResolveCanonicalModelForProvider(ctx, OpenAI, "opaque-deployment"); got != "gpt-5.6-terra" {
		t.Fatalf("canonical model = %q", got)
	}
	if got := ResolveCanonicalModelForProvider(ctx, Azure, "opaque-deployment"); got != "opaque-deployment" {
		t.Fatalf("mismatched provider canonical model = %q", got)
	}
}

func TestRequestModelInfoDefaultsCanonicalModelToWireModel(t *testing.T) {
	ctx := NewBifrostContext(context.Background(), NoDeadline)
	if !SetRequestModelInfo(ctx, RequestModelInfo{Provider: Anthropic, WireModel: "claude-sonnet-4-6"}) {
		t.Fatal("valid request model info was rejected")
	}
	info, ok := GetRequestModelInfo(ctx, Anthropic, "claude-sonnet-4-6")
	if !ok || info.CanonicalModel != "claude-sonnet-4-6" {
		t.Fatalf("request model info = %#v ok=%v", info, ok)
	}
}
