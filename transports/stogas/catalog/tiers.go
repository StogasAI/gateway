package catalog

import (
	"slices"

	"github.com/maximhq/bifrost/core/schemas"
)

// Tiers are provider neutral. Each deployment runs at exactly one.
const (
	TierStandard  = "standard"
	TierFlex      = "flex"
	TierFast      = "fast"
	TierUltrafast = "ultrafast"
)

var tierOrder = []string{TierStandard, TierFlex, TierFast, TierUltrafast}

// serviceTierNames maps the service_tier spellings that clients send and providers report to
// tiers. OpenAI renamed Priority to Fast and accepts both names.
var serviceTierNames = map[schemas.BifrostServiceTier]string{
	"default":   TierStandard,
	"standard":  TierStandard,
	"flex":      TierFlex,
	"fast":      TierFast,
	"priority":  TierFast,
	"ultrafast": TierUltrafast,
}

// providerServiceTiers maps each tier a provider offers to the service_tier value sent for it.
// Azure documents only the Priority name for Fast. Claude takes Fast as the speed field, and core
// sends default as standard_only, which keeps Claude off Priority Tier capacity.
var providerServiceTiers = map[schemas.ModelProvider]map[string]schemas.BifrostServiceTier{
	schemas.OpenAI:    {TierStandard: "default", TierFlex: "flex", TierFast: "fast", TierUltrafast: "ultrafast"},
	schemas.Azure:     {TierStandard: "default", TierFlex: "flex", TierFast: "priority"},
	schemas.Anthropic: {TierStandard: "default", TierFast: "default"},
}

// standardOnly serves providers, and Azure models other than OpenAI's, that take no service_tier.
var standardOnly = map[string]schemas.BifrostServiceTier{TierStandard: ""}

func offeredTiers(provider schemas.ModelProvider, modelFormat string) map[string]schemas.BifrostServiceTier {
	if tiers, ok := providerServiceTiers[provider]; ok && (provider != schemas.Azure || modelFormat == "OpenAI") {
		return tiers
	}
	return standardOnly
}

// requestedTier parses a client service_tier. An omitted value and auto leave the tier to the
// model selector.
func requestedTier(value *schemas.BifrostServiceTier) (string, error) {
	if value == nil || *value == schemas.BifrostServiceTierAuto {
		return "", nil
	}
	if tier, ok := serviceTierNames[*value]; ok {
		return tier, nil
	}
	return "", ErrUnsupportedServiceTier
}

// ReportedTier returns the tier that a provider response reports, or "" when it reports none.
// Claude reports Fast mode in speed; its service_tier describes Priority Tier capacity instead.
// Providers without tiers can report nothing that Stogas bills.
func ReportedTier(provider schemas.ModelProvider, serviceTier *schemas.BifrostServiceTier, speed *string) string {
	if provider == schemas.Anthropic {
		serviceTier = (*schemas.BifrostServiceTier)(speed)
	}
	if _, tiered := providerServiceTiers[provider]; !tiered || serviceTier == nil {
		return ""
	}
	return serviceTierNames[*serviceTier]
}

func upstreamServiceTier(provider schemas.ModelProvider, upstream Upstream) *schemas.BifrostServiceTier {
	value := offeredTiers(provider, upstream.ModelFormat)[upstream.ServiceTier]
	if value == "" {
		return nil
	}
	return &value
}

func tierRank(tier string) int {
	return slices.Index(tierOrder, tier)
}
