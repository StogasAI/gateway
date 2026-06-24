package catalog

import (
	"encoding/json"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
)

func applyResolvedDeployment(provider schemas.ModelProvider, model *string, serviceTier **schemas.BifrostServiceTier, deployment Deployment) bool {
	if model == nil {
		return false
	}
	if !applyServiceTierPolicy(provider, serviceTier, deployment) {
		return false
	}
	*model = deployment.Model
	return true
}

func applyServiceTierPolicy(provider schemas.ModelProvider, serviceTier **schemas.BifrostServiceTier, deployment Deployment) bool {
	if serviceTier == nil {
		return true
	}
	if implied := impliedServiceTier(provider, deployment.ServiceTier); implied != nil {
		if *serviceTier == nil {
			*serviceTier = implied
			return true
		}
		if !equivalentServiceTier(provider, **serviceTier, *implied) {
			return false
		}
		*serviceTier = implied
		return true
	}
	switch deployment.ServiceTier {
	case "", "default", "standard":
		if *serviceTier == nil {
			return true
		}
		switch **serviceTier {
		case schemas.BifrostServiceTierAuto, schemas.BifrostServiceTierDefault, "":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func impliedServiceTierForDeployment(provider schemas.ModelProvider, deployment compiledDeployment) *schemas.BifrostServiceTier {
	return impliedServiceTier(provider, deployment.ServiceTier)
}

func impliedServiceTier(provider schemas.ModelProvider, tier string) *schemas.BifrostServiceTier {
	if provider == schemas.Anthropic {
		switch tier {
		case "auto":
			value := schemas.BifrostServiceTierAuto
			return &value
		case "standard_only", "standard":
			value := schemas.BifrostServiceTierDefault
			return &value
		default:
			return nil
		}
	}
	switch tier {
	case "flex", "priority":
		value := schemas.BifrostServiceTier(tier)
		return &value
	default:
		return nil
	}
}

func equivalentServiceTier(provider schemas.ModelProvider, requested, implied schemas.BifrostServiceTier) bool {
	if requested == implied {
		return true
	}
	if provider != schemas.Anthropic {
		return false
	}
	switch implied {
	case schemas.BifrostServiceTierAuto:
		return requested == schemas.BifrostServiceTierPriority
	case schemas.BifrostServiceTierDefault:
		return requested == schemas.BifrostServiceTier("standard_only")
	default:
		return false
	}
}

func rawStringField(object map[string]json.RawMessage, key string) string {
	raw, ok := object[key]
	if !ok {
		return ""
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(value))
}
