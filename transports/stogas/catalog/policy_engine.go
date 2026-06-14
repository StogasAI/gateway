package catalog

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
)

const schemaParameterRefPrefix = "parameters."

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
		if parameterCompileAction(patch) == "delete" {
			delete(base, name)
			continue
		}
		base[name] = mergeParameterPolicy(base[name], patch)
	}
}

func mergeParameterPolicy(base compiledParameter, patch compiledParameter) compiledParameter {
	if directives := parameterDirectives(patch); len(directives) > 0 {
		base.Rules.Gateway.Directives = append(base.Rules.Gateway.Directives, directives...)
	}
	if patch.Rules.Gateway.Canonical != "" {
		base.Rules.Gateway.Canonical = patch.Rules.Gateway.Canonical
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
		if err := validateUnsupportedDirectives(name, policy, deployment); err != nil {
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

func validateUnsupportedDirectives(name string, policy compiledParameter, deployment Deployment) error {
	for _, directive := range parameterDirectives(policy) {
		if directive.Op != "rejectUnsupported" {
			continue
		}
		if !supportedCapability(directive.Source, deployment) {
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " is not supported by the resolved model"}
		}
	}
	return nil
}

func supportedCapability(source string, deployment Deployment) bool {
	switch source {
	case "model.reasoningSupported", "deployment.reasoningSupported":
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
	for _, directive := range parameterDirectives(policy) {
		if directive.Op == "alias" {
			return schemaParameterTarget(directive)
		}
	}
	return "", false
}

func parameterImpliedValue(policy compiledParameter) (string, bool) {
	for _, directive := range parameterDirectives(policy) {
		if directive.Op == "implyValue" {
			return stringDirectiveValue(directive)
		}
	}
	return "", false
}

func parameterRejectsConflict(policy compiledParameter) bool {
	for _, directive := range parameterDirectives(policy) {
		if directive.Op == "rejectConflict" {
			return true
		}
	}
	return false
}

func parameterCompileAction(policy compiledParameter) string {
	return policy.Rules.Compile.Action
}

func parameterDirectives(policy compiledParameter) []compiledGatewayDirective {
	return policy.Rules.Gateway.Directives
}

func parameterRejectDirectives(policy compiledParameter) []compiledGatewayDirective {
	directives := parameterDirectives(policy)
	rejects := make([]compiledGatewayDirective, 0, len(directives))
	for _, directive := range directives {
		if directive.Op == "reject" {
			rejects = append(rejects, directive)
		}
	}
	return rejects
}

func stringDirectiveValue(directive compiledGatewayDirective) (string, bool) {
	value, ok := directive.Value.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func schemaParameterTarget(directive compiledGatewayDirective) (string, bool) {
	target := strings.TrimSpace(directive.Target)
	if !strings.HasPrefix(target, schemaParameterRefPrefix) {
		return "", false
	}
	name := strings.TrimPrefix(target, schemaParameterRefPrefix)
	if name == "" {
		return "", false
	}
	return name, true
}
