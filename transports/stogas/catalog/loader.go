package catalog

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

const (
	catalogSchema    = 1
	runtimeSchema    = "stogas.catalog.runtime.v1"
	publicSchema     = "stogas.catalog.public.v1"
	runtimeSizeLimit = 16 * 1024 * 1024
	publicSizeLimit  = 64 * 1024 * 1024
)

var compiledRouteContracts = map[string]struct {
	providerID string
	interfaces []string
}{
	"anthropic-messages": {
		providerID: "anthropic",
		interfaces: []string{"chat_completions", "responses"},
	},
	"azure-chat-completions": {
		providerID: "azure",
		interfaces: []string{"chat_completions"},
	},
	"azure-responses": {
		providerID: "azure",
		interfaces: []string{"responses"},
	},
	"chutes-chat-completions": {
		providerID: "chutes",
		interfaces: []string{"chat_completions"},
	},
	"openai-chat-completions": {
		providerID: "openai",
		interfaces: []string{"chat_completions"},
	},
	"openai-responses": {
		providerID: "openai",
		interfaces: []string{"responses"},
	},
}

var canonicalUUIDPattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

const (
	meterAnthropicWebSearchCalls                          = "anthropic_web_search_calls"
	meterOpenAIChatCompletionSearchModelCalls             = "openai_chat_completion_search_model_calls"
	meterOpenAIChatCompletionSearchPreviewModelCalls      = "openai_chat_completion_search_preview_model_calls"
	meterOpenAIResponsesWebSearchCalls                    = "openai_responses_web_search_calls"
	meterOpenAIResponsesWebSearchPreviewCalls             = "openai_responses_web_search_preview_calls"
	meterOpenAIResponsesWebSearchPreviewNonReasoningCalls = "openai_responses_web_search_preview_non_reasoning_calls"
	ratePerThousandSearchContextHighCalls                 = "per_1k_search_context_high_calls"
	ratePerThousandSearchContextLowCalls                  = "per_1k_search_context_low_calls"
	ratePerThousandSearchContextMediumCalls               = "per_1k_search_context_medium_calls"
)

var tokenPricingMeters = map[string]bool{
	billing.MeterInputTokens:             true,
	billing.MeterCachedInputTokens:       true,
	billing.MeterCacheWriteInputTokens:   true,
	billing.MeterCacheWrite5mInputTokens: true,
	billing.MeterCacheWrite1hInputTokens: true,
	billing.MeterOutputTokens:            true,
	billing.MeterReasoningTokens:         true,
}

var callPricingMeters = map[string]bool{
	meterAnthropicWebSearchCalls:                          true,
	meterOpenAIChatCompletionSearchModelCalls:             true,
	meterOpenAIResponsesWebSearchCalls:                    true,
	meterOpenAIResponsesWebSearchPreviewCalls:             true,
	meterOpenAIResponsesWebSearchPreviewNonReasoningCalls: true,
}

//go:embed fallback/catalog.runtime.json
var embeddedRuntimeCatalogJSON []byte

//go:embed fallback/catalog.public.json
var embeddedPublicCatalogJSON []byte

func loadSnapshot() (*snapshot, error) {
	return snapshotFromRelease(embeddedRuntimeCatalogJSON, embeddedPublicCatalogJSON, Identity{})
}

func snapshotFromCatalogBytes(data []byte) (*snapshot, error) {
	return snapshotFromRelease(data, nil, Identity{})
}

func snapshotFromRelease(runtimeData, publicData []byte, identity Identity) (*snapshot, error) {
	if len(runtimeData) == 0 || len(runtimeData) > runtimeSizeLimit {
		return nil, fmt.Errorf("runtime catalog size is outside the accepted range")
	}
	catalog := compiledCatalog{}
	if err := json.Unmarshal(runtimeData, &catalog); err != nil {
		return nil, fmt.Errorf("decode runtime catalog: %w", err)
	}
	if catalog.Schema != runtimeSchema {
		return nil, fmt.Errorf("runtime catalog schema %q is unsupported", catalog.Schema)
	}
	if err := validateCompiledCatalog(catalog); err != nil {
		return nil, err
	}
	if len(publicData) > 0 {
		if len(publicData) > publicSizeLimit {
			return nil, fmt.Errorf("public catalog exceeds the accepted size")
		}
		var publicHeader struct {
			Schema string `json:"schema"`
			Graph  struct {
				Authors     map[string]json.RawMessage `json:"authors"`
				Deployments map[string]json.RawMessage `json:"deployments"`
				Models      map[string]json.RawMessage `json:"models"`
				Providers   map[string]json.RawMessage `json:"providers"`
				Routes      map[string]json.RawMessage `json:"routes"`
			} `json:"graph"`
		}
		if err := json.Unmarshal(publicData, &publicHeader); err != nil {
			return nil, fmt.Errorf("decode public catalog: %w", err)
		}
		if publicHeader.Schema != publicSchema ||
			!sameKeys(publicHeader.Graph.Authors, catalog.Graph.Authors) ||
			!sameKeys(publicHeader.Graph.Providers, catalog.Graph.Providers) ||
			!sameKeys(publicHeader.Graph.Routes, catalog.Graph.Routes) ||
			!sameKeys(publicHeader.Graph.Models, catalog.Graph.Models) ||
			!sameKeys(publicHeader.Graph.Deployments, catalog.Graph.Deployments) {
			return nil, fmt.Errorf("public catalog does not match the runtime graph")
		}
	}

	runtimeDigest := sha256.Sum256(runtimeData)
	digest := "sha256:" + hex.EncodeToString(runtimeDigest[:])
	if identity.Digest == "" {
		identity.Digest = digest
	} else if identity.Digest != digest {
		return nil, fmt.Errorf("runtime catalog digest does not match the signed release")
	}
	publicDigest := ""
	if len(publicData) > 0 {
		sum := sha256.Sum256(publicData)
		publicDigest = "sha256:" + hex.EncodeToString(sum[:])
	}

	routeDeployments := make(map[string][]string, len(catalog.Graph.Routes))
	deploymentSelectors := make(map[string]string)
	modelSelectors := make(map[string]string)
	for modelID, model := range catalog.Graph.Models {
		modelSelectors[modelID] = modelID
		for _, alias := range model.Aliases {
			modelSelectors[alias] = modelID
		}
	}
	for deploymentID, deployment := range catalog.Graph.Deployments {
		deploymentSelectors[deploymentID] = deploymentID
		for _, alias := range deployment.Aliases {
			deploymentSelectors[alias] = deploymentID
		}
		for _, routeID := range deployment.RouteIDs {
			routeDeployments[routeID] = append(routeDeployments[routeID], deploymentID)
		}
	}
	for routeID, route := range catalog.Graph.Routes {
		route.ID = routeID
		route.DeploymentIDs = routeDeployments[routeID]
		sortDeploymentIDs(route.DeploymentIDs, catalog.Graph.Deployments)
		catalog.Graph.Routes[routeID] = route
	}

	return &snapshot{
		deploymentSelectors: deploymentSelectors,
		graph:               catalog.Graph,
		identity:            identity,
		modelSelectors:      modelSelectors,
		publicDigest:        publicDigest,
		publicRaw:           append([]byte(nil), publicData...),
		raw:                 append([]byte(nil), runtimeData...),
		routeDeployments:    routeDeployments,
	}, nil
}

func validateCompiledCatalog(catalog compiledCatalog) error {
	graph := catalog.Graph
	if len(graph.Authors) == 0 ||
		len(graph.Models) == 0 ||
		len(graph.Providers) == 0 ||
		len(graph.Routes) == 0 ||
		len(graph.Deployments) == 0 {
		return fmt.Errorf("compiled catalog is missing required graph nodes")
	}
	authorQualifiers := make(map[string]string)
	for authorID, author := range graph.Authors {
		if err := validateQualifierAliases(authorQualifiers, "author", authorID, author.Aliases); err != nil {
			return err
		}
	}
	providerQualifiers := make(map[string]string)
	for providerID, provider := range graph.Providers {
		if err := validateQualifierAliases(providerQualifiers, "provider", providerID, provider.Aliases); err != nil {
			return err
		}
		if !validCredentialModes(provider.CredentialModes) {
			return fmt.Errorf("provider %s has invalid credential modes", providerID)
		}
	}
	selectors := make(map[string]string)
	addSelector := func(selector, owner string) error {
		if strings.TrimSpace(selector) != selector || selector == "" || strings.Contains(selector, "/") {
			return fmt.Errorf("selector %q is not canonical", selector)
		}
		if existing := selectors[selector]; existing != "" {
			return fmt.Errorf("selector %s is shared by %s and %s", selector, existing, owner)
		}
		selectors[selector] = owner
		return nil
	}
	for modelID, model := range graph.Models {
		if _, ok := graph.Authors[model.AuthorID]; !ok {
			return fmt.Errorf("model %s references unknown author %s", modelID, model.AuthorID)
		}
		if err := validateModelReasoning(modelID, model); err != nil {
			return err
		}
		if err := addSelector(modelID, "model:"+modelID); err != nil {
			return err
		}
		for _, alias := range model.Aliases {
			if err := addSelector(alias, "model:"+modelID); err != nil {
				return err
			}
		}
	}
	for routeID, route := range graph.Routes {
		contract, allowed := compiledRouteContracts[routeID]
		if !allowed ||
			route.ProviderID != contract.providerID ||
			!sameStrings(route.Interfaces, contract.interfaces) {
			return fmt.Errorf("route %s is not a compiled gateway transport contract", routeID)
		}
		if _, ok := graph.Providers[route.ProviderID]; !ok {
			return fmt.Errorf("route %s references unknown provider %s", routeID, route.ProviderID)
		}
		if firstInterfaceRoute(route) == "" {
			return fmt.Errorf("route %s has no supported interface", routeID)
		}
	}
	for deploymentID, deployment := range graph.Deployments {
		model, ok := graph.Models[deployment.ModelID]
		if !ok {
			return fmt.Errorf("deployment %s references unknown model %s", deploymentID, deployment.ModelID)
		}
		if deployment.Upstream.Model == "" ||
			deployment.ContextWindowTokens <= 0 ||
			deployment.MaxOutputTokens <= 0 ||
			deployment.MaxOutputTokens > deployment.ContextWindowTokens ||
			len(deployment.InputModalities) == 0 ||
			len(deployment.OutputModalities) == 0 {
			return fmt.Errorf("deployment %s is not executable", deploymentID)
		}
		if len(deployment.Capabilities.InputModalities) != 0 ||
			len(deployment.Capabilities.OutputModalities) != 0 ||
			!validModalities(deployment.InputModalities) ||
			!validModalities(deployment.OutputModalities) {
			return fmt.Errorf("deployment %s has invalid modalities", deploymentID)
		}
		if !validDeprecationDate(deployment.DeprecationDate) {
			return fmt.Errorf("deployment %s has invalid deprecationDate", deploymentID)
		}
		if err := addSelector(deploymentID, "deployment:"+deploymentID); err != nil {
			return err
		}
		providerID := ""
		for _, routeID := range deployment.RouteIDs {
			route, ok := graph.Routes[routeID]
			if !ok {
				return fmt.Errorf("deployment %s references unknown route %s", deploymentID, routeID)
			}
			if providerID != "" && route.ProviderID != providerID {
				return fmt.Errorf("deployment %s spans multiple providers", deploymentID)
			}
			providerID = route.ProviderID
		}
		if providerID == "" {
			return fmt.Errorf("deployment %s has no route", deploymentID)
		}
		selector := deployment.Upstream
		switch providerID {
		case "openai":
			if selector.ChuteID != "" || selector.InferenceGeo != "" || selector.Speed != "" ||
				(selector.ReasoningMode != "" && selector.ReasoningMode != "pro") ||
				(selector.ServiceTier != "default" &&
					selector.ServiceTier != "flex" &&
					selector.ServiceTier != "priority") {
				return fmt.Errorf("deployment %s has an invalid OpenAI upstream selector", deploymentID)
			}
		case "anthropic":
			if selector.ChuteID != "" || selector.ReasoningMode != "" || selector.ServiceTier != "standard_only" ||
				(selector.Speed != "" && selector.Speed != "standard" && selector.Speed != "fast") ||
				(selector.InferenceGeo != "" &&
					selector.InferenceGeo != "global" &&
					selector.InferenceGeo != "us") {
				return fmt.Errorf("deployment %s has an invalid Anthropic upstream selector", deploymentID)
			}
		case "chutes":
			if !canonicalUUIDPattern.MatchString(selector.ChuteID) ||
				selector.InferenceGeo != "" || selector.ReasoningMode != "" || selector.ServiceTier != "" || selector.Speed != "" {
				return fmt.Errorf("deployment %s has an invalid Chutes upstream selector", deploymentID)
			}
		case "azure":
			if selector.Model != deployment.ModelID ||
				selector.ChuteID != "" || selector.InferenceGeo != "" || selector.ReasoningMode != "" ||
				selector.ServiceTier != "" || selector.Speed != "" {
				return fmt.Errorf("deployment %s has an invalid Azure upstream selector", deploymentID)
			}
		default:
			return fmt.Errorf("deployment %s uses unsupported provider %s", deploymentID, providerID)
		}
		if err := validateDeploymentTEE(deploymentID, providerID, deployment.TEE); err != nil {
			return err
		}
		if err := validateDeploymentPricing(deploymentID, providerID, deployment); err != nil {
			return err
		}
		if err := validateReasoningEfforts("deployment "+deploymentID, deployment.ReasoningEfforts); err != nil {
			return err
		}
		if err := validateReasoningConfiguration(deploymentID, providerID, deployment, graph); err != nil {
			return err
		}
		if err := validateDeploymentReasoningInheritance(deploymentID, model, deployment); err != nil {
			return err
		}
		for _, alias := range deployment.Aliases {
			if err := addSelector(alias, "deployment:"+deploymentID); err != nil {
				return err
			}
		}
	}
	for routeID, deploymentIDs := range routeDeploymentsForGraph(graph) {
		route := graph.Routes[routeID]
		deploymentsByModel := make(map[string][]string)
		for _, deploymentID := range deploymentIDs {
			deployment := graph.Deployments[deploymentID]
			deploymentsByModel[deployment.ModelID] = append(
				deploymentsByModel[deployment.ModelID],
				deploymentID,
			)
		}
		for modelID, modelDeploymentIDs := range deploymentsByModel {
			if len(modelDeploymentIDs) < 2 {
				continue
			}
			baseID := route.ProviderID + "-" + modelID
			if !stringIn(modelDeploymentIDs, baseID) {
				return fmt.Errorf(
					"route %s model %s has multiple deployments but no canonical base %s",
					routeID,
					modelID,
					baseID,
				)
			}
		}
	}
	return nil
}

func validateDeploymentTEE(deploymentID, providerID string, tee *TEE) error {
	if providerID != "chutes" {
		if tee != nil {
			return fmt.Errorf("deployment %s has an unexpected TEE policy", deploymentID)
		}
		return nil
	}
	if tee == nil || tee.Mechanism != "tdx" {
		return fmt.Errorf("deployment %s has an invalid Chutes TEE policy", deploymentID)
	}
	switch tee.Status {
	case "attested", "claimed", "unverified", "unknown":
	default:
		return fmt.Errorf("deployment %s has an invalid Chutes TEE status", deploymentID)
	}
	switch tee.ExternalNetworkEgress {
	case "blocked", "allowed", "unknown":
	default:
		return fmt.Errorf("deployment %s has an invalid Chutes external network egress policy", deploymentID)
	}
	return nil
}

func validModalities(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		switch value {
		case "text", "image", "audio", "video":
		default:
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return len(seen) > 0
}

func validateDeploymentPricing(deploymentID, providerID string, deployment compiledDeployment) error {
	for _, required := range []string{
		billing.MeterInputTokens,
		billing.MeterCachedInputTokens,
		billing.MeterOutputTokens,
	} {
		if len(deployment.Pricing[required]) == 0 {
			return fmt.Errorf("deployment %s is missing required pricing meter %s", deploymentID, required)
		}
	}
	for meterKey, rates := range deployment.Pricing {
		switch {
		case tokenPricingMeters[meterKey]:
			if !validTokenRates(rates) {
				return fmt.Errorf("deployment %s has invalid token rates for %s", deploymentID, meterKey)
			}
		case callPricingMeters[meterKey]:
			if !validExactRates(rates, billing.RatePerThousandCalls) {
				return fmt.Errorf("deployment %s has invalid call rates for %s", deploymentID, meterKey)
			}
		case meterKey == meterOpenAIChatCompletionSearchPreviewModelCalls:
			if !validExactRates(
				rates,
				ratePerThousandSearchContextLowCalls,
				ratePerThousandSearchContextMediumCalls,
				ratePerThousandSearchContextHighCalls,
			) {
				return fmt.Errorf("deployment %s has invalid search-context rates for %s", deploymentID, meterKey)
			}
		default:
			return fmt.Errorf("deployment %s uses unsupported pricing meter %s", deploymentID, meterKey)
		}
	}
	hasRoute := func(routeID string) bool {
		for _, candidate := range deployment.RouteIDs {
			if candidate == routeID {
				return true
			}
		}
		return false
	}
	switch providerID {
	case "openai", "azure":
		if len(deployment.Pricing[billing.MeterCacheWrite5mInputTokens]) > 0 ||
			len(deployment.Pricing[billing.MeterCacheWrite1hInputTokens]) > 0 {
			return fmt.Errorf("deployment %s uses Anthropic cache-write meters", deploymentID)
		}
		if providerID == "openai" && hasRoute("openai-responses") {
			for _, required := range []string{
				meterOpenAIResponsesWebSearchCalls,
				meterOpenAIResponsesWebSearchPreviewCalls,
				meterOpenAIResponsesWebSearchPreviewNonReasoningCalls,
			} {
				if len(deployment.Pricing[required]) == 0 {
					return fmt.Errorf("deployment %s is missing route pricing meter %s", deploymentID, required)
				}
			}
		}
	case "anthropic":
		if len(deployment.Pricing[billing.MeterCacheWriteInputTokens]) > 0 {
			return fmt.Errorf("deployment %s uses OpenAI cache-write pricing", deploymentID)
		}
		for _, required := range []string{
			billing.MeterCacheWrite5mInputTokens,
			billing.MeterCacheWrite1hInputTokens,
			meterAnthropicWebSearchCalls,
		} {
			if len(deployment.Pricing[required]) == 0 {
				return fmt.Errorf("deployment %s is missing provider pricing meter %s", deploymentID, required)
			}
		}
	}
	return nil
}

func validTokenRates(rates map[string]string) bool {
	if validExactRates(rates, billing.RatePerMillionTokens) {
		return true
	}
	return validExactRates(
		rates,
		billing.RatePerMillionContextLTE272K,
		billing.RatePerMillionContextGT272K,
	)
}

func validExactRates(rates map[string]string, keys ...string) bool {
	if len(rates) != len(keys) {
		return false
	}
	for _, key := range keys {
		rate, ok := billing.ParseRate(rates[key])
		if !ok || rate.Sign() <= 0 {
			return false
		}
	}
	return true
}

func validateReasoningEfforts(owner string, efforts []string) error {
	previousRank := -1
	for _, effort := range efforts {
		rank := reasoningEffortIndex(effort)
		if rank < 0 {
			return fmt.Errorf("%s has unsupported reasoning effort %s", owner, effort)
		}
		if rank <= previousRank {
			return fmt.Errorf("%s reasoning efforts are not in canonical order", owner)
		}
		previousRank = rank
	}
	return nil
}

func validateModelReasoning(modelID string, model compiledModel) error {
	switch model.ReasoningAvailability {
	case "optional", "required", "unsupported":
	default:
		return fmt.Errorf("model %s has invalid reasoning availability", modelID)
	}
	if err := validateReasoningEfforts("model "+modelID, model.ReasoningEfforts); err != nil {
		return err
	}
	if model.ReasoningAvailability == "unsupported" &&
		(len(model.ReasoningEfforts) > 0 || model.ReasoningMaxTokens != nil) {
		return fmt.Errorf("model %s exposes controls for unsupported reasoning", modelID)
	}
	if budget := model.ReasoningMaxTokens; budget != nil &&
		(budget.Minimum < 1 || budget.Maximum < budget.Minimum || budget.Maximum >= model.MaxOutputTokens) {
		return fmt.Errorf("model %s has an invalid manual reasoning token limit", modelID)
	}
	return nil
}

func validateDeploymentReasoningInheritance(deploymentID string, model compiledModel, deployment compiledDeployment) error {
	if model.ReasoningAvailability == "unsupported" && deployment.ReasoningAvailability != "unsupported" {
		return fmt.Errorf("deployment %s enables model-unsupported reasoning", deploymentID)
	}
	if model.ReasoningAvailability == "required" && deployment.ReasoningAvailability != "required" {
		return fmt.Errorf("deployment %s weakens required model reasoning", deploymentID)
	}
	modelEfforts := make(map[string]struct{}, len(model.ReasoningEfforts))
	for _, effort := range model.ReasoningEfforts {
		modelEfforts[effort] = struct{}{}
	}
	for _, effort := range deployment.ReasoningEfforts {
		if _, ok := modelEfforts[effort]; !ok {
			return fmt.Errorf("deployment %s enables a model-unsupported reasoning effort", deploymentID)
		}
	}
	if deployment.ReasoningMaxTokens == nil {
		return nil
	}
	if model.ReasoningMaxTokens == nil ||
		deployment.ReasoningMaxTokens.Minimum < model.ReasoningMaxTokens.Minimum ||
		deployment.ReasoningMaxTokens.Maximum > model.ReasoningMaxTokens.Maximum {
		return fmt.Errorf("deployment %s expands the model reasoning token range", deploymentID)
	}
	return nil
}

func validateReasoningConfiguration(deploymentID, providerID string, deployment compiledDeployment, graph compiledGraph) error {
	switch deployment.ReasoningAvailability {
	case "optional", "required", "unsupported":
	default:
		return fmt.Errorf("deployment %s has invalid reasoning availability", deploymentID)
	}
	if deployment.ReasoningAvailability == "unsupported" &&
		(len(deployment.ReasoningEfforts) > 0 || deployment.ReasoningMaxTokens != nil) {
		return fmt.Errorf("deployment %s exposes controls for unsupported reasoning", deploymentID)
	}
	if budget := deployment.ReasoningMaxTokens; budget != nil {
		if providerID != "anthropic" || budget.Minimum < 1 || budget.Maximum < budget.Minimum || budget.Maximum >= deployment.MaxOutputTokens {
			return fmt.Errorf("deployment %s has an invalid manual reasoning token limit", deploymentID)
		}
	}
	if deployment.Upstream.ReasoningMode == "" {
		return nil
	}
	if providerID != "openai" || deployment.Upstream.ReasoningMode != "pro" ||
		!strings.HasPrefix(deployment.Upstream.Model, "gpt-5.6-") {
		return fmt.Errorf("deployment %s has an invalid fixed reasoning mode", deploymentID)
	}
	for _, routeID := range deployment.RouteIDs {
		route := graph.Routes[routeID]
		if len(route.Interfaces) != 1 || route.Interfaces[0] != "responses" {
			return fmt.Errorf("deployment %s fixed reasoning mode requires the Responses API", deploymentID)
		}
	}
	return nil
}

func validCredentialModes(modes []string) bool {
	if len(modes) == 0 {
		return false
	}
	seen := make(map[string]bool, len(modes))
	for _, mode := range modes {
		if (mode != "managed" && mode != "byok") || seen[mode] {
			return false
		}
		seen[mode] = true
	}
	return true
}

func validateQualifierAliases(
	owners map[string]string,
	kind string,
	id string,
	aliases []string,
) error {
	for _, qualifier := range append([]string{id}, aliases...) {
		if strings.TrimSpace(qualifier) != qualifier ||
			qualifier == "" ||
			strings.Contains(qualifier, "/") {
			return fmt.Errorf("%s qualifier %q is not canonical", kind, qualifier)
		}
		if existing := owners[qualifier]; existing != "" {
			return fmt.Errorf(
				"%s qualifier %s is shared by %s and %s",
				kind,
				qualifier,
				existing,
				id,
			)
		}
		owners[qualifier] = id
	}
	return nil
}

func validDeprecationDate(value *string) bool {
	if value == nil {
		return true
	}
	parsed, err := time.Parse(time.DateOnly, *value)
	return err == nil && parsed.Format(time.DateOnly) == *value
}

func routeDeploymentsForGraph(graph compiledGraph) map[string][]string {
	out := make(map[string][]string, len(graph.Routes))
	for deploymentID, deployment := range graph.Deployments {
		for _, routeID := range deployment.RouteIDs {
			out[routeID] = append(out[routeID], deploymentID)
		}
	}
	return out
}

func sameKeys[A, B any](left map[string]A, right map[string]B) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, ok := right[key]; !ok {
			return false
		}
	}
	return true
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortDeploymentIDs(ids []string, deployments map[string]compiledDeployment) {
	sort.SliceStable(ids, func(i, j int) bool {
		left := deployments[ids[i]]
		right := deployments[ids[j]]
		if left.ModelID != right.ModelID {
			return ids[i] < ids[j]
		}
		if left.Upstream.ServiceTier != right.Upstream.ServiceTier {
			return serviceTierRank(left.Upstream.ServiceTier) < serviceTierRank(right.Upstream.ServiceTier)
		}
		if left.Upstream.Speed != right.Upstream.Speed {
			return left.Upstream.Speed < right.Upstream.Speed
		}
		return ids[i] < ids[j]
	})
}

func serviceTierRank(tier string) int {
	switch tier {
	case "auto", "default", "standard", "standard_only", "":
		return 0
	case "flex":
		return 1
	case "priority":
		return 2
	default:
		return 9
	}
}
