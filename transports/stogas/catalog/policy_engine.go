package catalog

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
)

const (
	schemaHeaderRefPrefix    = "schema.headers."
	schemaParameterRefPrefix = "schema.parameters."
)

func effectiveParameterPolicies(schema compiledStogasEndpointSchema, routeNode compiledProviderEndpoint, deployment Deployment) map[string]compiledParameter {
	policies := make(map[string]compiledParameter, len(schema.Parameters)+len(routeNode.ParameterPolicies)+len(deployment.ParameterPolicies))
	for name, policy := range schema.Parameters {
		policies[name] = policy
	}
	mergeParameterPolicies(policies, routeNode.ParameterPolicies)
	mergeParameterPolicies(policies, deployment.ParameterPolicies)
	return policies
}

func mergeParameterPolicies(base map[string]compiledParameter, patches map[string]compiledParameter) {
	for name, patch := range patches {
		if parameterAttributeAction(patch) == "delete" {
			delete(base, name)
			continue
		}
		base[name] = mergeParameterPolicy(base[name], patch)
	}
}

func mergeParameterPolicy(base compiledParameter, patch compiledParameter) compiledParameter {
	if rejects := patch.Reject; len(rejects) > 0 {
		base.Reject = append(base.Reject, rejects...)
	}
	if patch.Alias != "" {
		base.Alias = patch.Alias
	}
	if patch.ImplyValue != nil {
		base.ImplyValue = patch.ImplyValue
	}
	if patch.RejectConflict {
		base.RejectConflict = true
	}
	if patch.RejectUnsupported != "" {
		base.RejectUnsupported = patch.RejectUnsupported
	}
	if len(patch.Values) > 0 {
		base.Values = patch.Values
	}
	if patch.Min != nil {
		base.Min = patch.Min
	}
	if patch.Max != nil {
		base.Max = patch.Max
	}
	return base
}

func validateRequestParameterRules(body []byte, routeNode compiledProviderEndpoint, parameters map[string]compiledParameter, deployment Deployment) error {
	var rawData map[string]json.RawMessage
	if err := sonic.Unmarshal(body, &rawData); err != nil {
		return ErrInvalidJSON
	}
	for name, raw := range rawData {
		policy, ok := parameters[name]
		if !ok {
			if routeHasParameter(routeNode, name) {
				return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " is not supported by the resolved model"}
			}
			continue
		}
		if err := validateUnsupportedRule(name, policy, deployment); err != nil {
			return err
		}
		if err := validateInvalidParameterRules(name, raw, policy); err != nil {
			return err
		}
	}
	return nil
}

func routeHasParameter(routeNode compiledProviderEndpoint, name string) bool {
	if _, ok := routeNode.ParameterPolicies[name]; ok {
		return true
	}
	for _, deploymentID := range routeNode.DeploymentIDs {
		snap := active.Load()
		if snap == nil {
			return false
		}
		if deployment, ok := snap.graph.Deployments[deploymentID]; ok {
			if _, ok := deployment.ParameterPolicies[name]; ok {
				return true
			}
		}
	}
	return false
}

func validateUnsupportedRule(name string, policy compiledParameter, deployment Deployment) error {
	if policy.RejectUnsupported == "" {
		return nil
	}
	if !supportedCapability(policy.RejectUnsupported, deployment) {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " is not supported by the resolved model"}
	}
	return nil
}

func supportedCapability(source string, deployment Deployment) bool {
	switch source {
	case "model.reasoning", "deployment.reasoning":
		return deployment.ReasoningSupported
	default:
		return true
	}
}

func applyResolvedDeployment(model *string, serviceTier **schemas.BifrostServiceTier, deployment Deployment, parameters map[string]compiledParameter) bool {
	if model == nil {
		return false
	}
	if !applyServiceTierPolicy(serviceTier, deployment, parameters["service_tier"]) {
		return false
	}
	*model = deployment.Model
	return true
}

func applyServiceTierPolicy(serviceTier **schemas.BifrostServiceTier, deployment Deployment, policy compiledParameter) bool {
	if serviceTier == nil {
		return true
	}
	allowed := deployment.AllowedServiceTier
	if value, ok := singleServiceTierValue(policy.Values); ok {
		allowed = &value
	}
	if allowed != nil && *serviceTier != nil && **serviceTier != *allowed {
		if deployment.AllowedServiceTier != nil || parameterRejectsConflict(policy) {
			return false
		}
	}
	if impliedRaw, ok := parameterImpliedValue(policy); ok && *serviceTier == nil {
		implied := schemas.BifrostServiceTier(impliedRaw)
		*serviceTier = &implied
	}
	return true
}

func serviceTierPolicy(deployment compiledDeployment) (*schemas.BifrostServiceTier, *schemas.BifrostServiceTier, bool) {
	param := deployment.ParameterPolicies["service_tier"]
	values := param.Values
	if len(values) == 0 && deployment.ServiceTier != "" {
		values = []string{deployment.ServiceTier}
	}
	allowed, ok := singleServiceTierValue(values)
	if !ok {
		return nil, nil, false
	}
	var implied *schemas.BifrostServiceTier
	if impliedRaw, ok := parameterImpliedValue(param); ok {
		value := schemas.BifrostServiceTier(impliedRaw)
		implied = &value
	}
	return &allowed, implied, true
}

func singleServiceTierValue(values []string) (schemas.BifrostServiceTier, bool) {
	if len(values) != 1 {
		return "", false
	}
	return schemas.BifrostServiceTier(values[0]), true
}

func parameterAlias(policy compiledParameter) (string, bool) {
	return schemaFieldTarget(policy.Alias, schemaParameterRefPrefix)
}

func headerAlias(policy compiledParameter) (string, bool) {
	return schemaFieldTarget(policy.Alias, schemaHeaderRefPrefix)
}

func parameterImpliedValue(policy compiledParameter) (string, bool) {
	return stringRuleValue(policy.ImplyValue)
}

func parameterRejectsConflict(policy compiledParameter) bool {
	return policy.RejectConflict
}

func parameterAttributeAction(policy compiledParameter) string {
	switch {
	case policy.DeleteAttribute:
		return "delete"
	case policy.OverrideAttribute:
		return "override"
	default:
		return ""
	}
}

func parameterRejectRules(policy compiledParameter) []compiledRejectRule {
	return policy.Reject
}

func stringRuleValue(raw any) (string, bool) {
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func schemaFieldTarget(raw string, prefix string) (string, bool) {
	target := strings.TrimSpace(raw)
	if !strings.HasPrefix(target, prefix) {
		return "", false
	}
	name := strings.TrimPrefix(target, prefix)
	if name == "" {
		return "", false
	}
	return name, true
}
