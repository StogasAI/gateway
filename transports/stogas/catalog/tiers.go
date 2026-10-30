package catalog

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/bytedance/sonic"
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

// standardOnly serves providers, and Azure models other than OpenAI's and Claude, that take no
// service_tier.
var standardOnly = map[string]schemas.BifrostServiceTier{TierStandard: ""}

// claudeOnAzure sends no tier either: Azure sells Claude Fast as its own model, which runs every
// request at Fast, and rejects speed.
var claudeOnAzure = map[string]schemas.BifrostServiceTier{TierStandard: "", TierFast: ""}

func offeredTiers(provider schemas.ModelProvider, modelFormat string) map[string]schemas.BifrostServiceTier {
	if provider == schemas.Azure && modelFormat == "Anthropic" {
		return claudeOnAzure
	}
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
// Claude, on Anthropic or Azure, reports Fast mode in speed; its service_tier describes Priority
// Tier capacity instead. Providers without tiers can report nothing that Stogas bills.
func ReportedTier(provider schemas.ModelProvider, modelFormat string, serviceTier *schemas.BifrostServiceTier, speed *string) string {
	if provider == schemas.Anthropic || provider == schemas.Azure && modelFormat == "Anthropic" {
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

// Reasoning modes select deployments as tiers do. A deployment's upstream.reasoningMode is empty
// in standard mode.
const (
	ModeStandard = "standard"
	ModePro      = "pro"
)

// variant is the service tier and reasoning mode that a request selects. An empty field leaves the
// choice to the model selector: the base deployment's tier, in standard mode.
type variant struct {
	tier string
	mode string
}

// upstreamMode is the upstream.reasoningMode of the deployments that a model selector, group or
// pool selects.
func (v variant) upstreamMode() string {
	if v.mode == ModePro {
		return ModePro
	}
	return ""
}

// matches reports whether a deployment that the request names exactly runs at the variant.
func (v variant) matches(upstream compiledUpstream) bool {
	return (v.tier == "" || upstream.ServiceTier == v.tier) &&
		(v.mode == "" || upstream.ReasoningMode == v.upstreamMode())
}

// unavailable is the error for a request whose variant leaves no deployment. usable says whether
// the key can use the model at a variant. The error names a field only when the request sent it
// and another value of that field would serve. The mode applies before the tier, so a model that
// the key uses only in another mode names the mode.
func (v variant) unavailable(usable func(variant) bool) error {
	if v.tier == "" && v.mode == "" {
		return ErrModelUnavailable
	}
	inMode := func(mode string) bool {
		return slices.ContainsFunc(tierOrder, func(tier string) bool { return usable(variant{tier: tier, mode: mode}) })
	}
	other := ModePro
	if v.mode == ModePro {
		other = ModeStandard
	}
	served := inMode(v.mode)
	switch {
	case !served && v.mode != "" && inMode(other):
		return ErrReasoningModeUnavailable
	case served && v.tier != "":
		return ErrServiceTierUnavailable
	}
	return ErrModelUnavailable
}

// requestedMode parses a client reasoning.mode. An omitted value leaves the mode to the model
// selector.
func requestedMode(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return "", nil
	}
	var mode string
	if err := sonic.Unmarshal(raw, &mode); err != nil {
		return "", ErrInvalidJSON
	}
	if mode != ModeStandard && mode != ModePro {
		return "", ErrUnsupportedReasoningMode
	}
	return mode, nil
}
