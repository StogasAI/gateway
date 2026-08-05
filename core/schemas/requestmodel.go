package schemas

// RequestModelInfo is immutable model metadata for one resolved provider
// request. WireModel binds the metadata to the exact model sent upstream so it
// cannot affect a fallback or a later mutation that selects another model.
type RequestModelInfo struct {
	Provider        ModelProvider
	WireModel       string
	CanonicalModel  string
	MaxOutputTokens int
}

// SetRequestModelInfo installs request-scoped model metadata for provider
// conversion. It returns false for an incomplete identity.
func SetRequestModelInfo(ctx *BifrostContext, info RequestModelInfo) bool {
	if ctx == nil || info.Provider == "" || info.WireModel == "" || info.MaxOutputTokens < 0 {
		return false
	}
	if info.CanonicalModel == "" {
		info.CanonicalModel = info.WireModel
	}
	ctx.SetValue(BifrostContextKeyRequestModelInfo, info)
	return true
}

// GetRequestModelInfo returns metadata only when both provider and wire model
// still match the resolved request identity.
func GetRequestModelInfo(ctx *BifrostContext, provider ModelProvider, wireModel string) (RequestModelInfo, bool) {
	if ctx == nil || provider == "" || wireModel == "" {
		return RequestModelInfo{}, false
	}
	info, ok := ctx.Value(BifrostContextKeyRequestModelInfo).(RequestModelInfo)
	if !ok || info.Provider != provider || info.WireModel != wireModel {
		return RequestModelInfo{}, false
	}
	return info, true
}

// ResolveCanonicalModelForProvider uses exact request-scoped catalog metadata
// before the ordinary Bifrost alias resolution path.
func ResolveCanonicalModelForProvider(ctx *BifrostContext, provider ModelProvider, fallbackModel string) string {
	if info, ok := GetRequestModelInfo(ctx, provider, fallbackModel); ok && info.CanonicalModel != "" {
		return info.CanonicalModel
	}
	return ResolveCanonicalModel(ctx, fallbackModel)
}
