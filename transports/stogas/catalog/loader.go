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
	catalogSchema     = 1
	runtimeSchema     = "stogas.catalog.runtime.v3"
	publicSchema      = "stogas.catalog.public.v3"
	runtimeSizeLimit  = 16 * 1024 * 1024
	publicSizeLimit   = 64 * 1024 * 1024
	maxAliasesPerNode = 8
)

const isoCountryCodes = "|AD|AE|AF|AG|AI|AL|AM|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|" +
	"BA|BB|BD|BE|BF|BG|BH|BI|BJ|BL|BM|BN|BO|BQ|BR|BS|BT|BV|BW|BY|BZ|" +
	"CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|" +
	"DE|DJ|DK|DM|DO|DZ|EC|EE|EG|EH|ER|ES|ET|FI|FJ|FK|FM|FO|FR|" +
	"GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|" +
	"HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|" +
	"KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|" +
	"MA|MC|MD|ME|MF|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|" +
	"NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|" +
	"QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|SS|ST|SV|SX|SY|SZ|" +
	"TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TR|TT|TV|TW|TZ|UA|UG|UM|US|UY|UZ|" +
	"VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW|"

const euCountryCodes = "|AT|BE|BG|HR|CY|CZ|DK|EE|FI|FR|DE|GR|HU|IE|IT|LV|LT|LU|MT|NL|PL|PT|RO|SK|SI|ES|SE|"

const europeCountryCodes = "|AD|AL|AT|AX|BA|BE|BG|BY|CH|CZ|DE|DK|EE|ES|FI|FO|FR|GB|GG|GI|GR|" +
	"HR|HU|IE|IM|IS|IT|JE|LI|LT|LU|LV|MC|MD|ME|MK|MT|NL|NO|PL|PT|RO|RS|RU|SE|SI|SJ|SK|SM|UA|VA|"

const apacCountryCodes = "|AF|AM|AS|AU|AZ|BD|BN|BT|CC|CK|CN|CX|FJ|FM|GE|GU|HK|ID|IN|IO|JP|KG|KH|KI|KP|KR|KZ|" +
	"LA|LK|MH|MM|MN|MO|MP|MV|MY|NC|NF|NP|NR|NU|NZ|PF|PG|PH|PK|PN|PW|SB|SG|TH|TJ|TK|TL|TM|TO|TR|TV|TW|UM|UZ|VU|WF|WS|VN|"

var compiledRouteContracts = map[string]struct {
	providerID string
	interfaces []string
}{
	"anthropic-messages": {
		providerID: "anthropic",
		interfaces: []string{"chat_completions", "responses"},
	},
	"azure-anthropic-messages": {
		providerID: "azure",
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
	if !validSHA256Digest(catalog.PublicDigest) {
		return nil, fmt.Errorf("runtime catalog public digest is invalid")
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
			!hasEveryKey(publicHeader.Graph.Models, catalog.Graph.Models) ||
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
	publicDigest := catalog.PublicDigest
	if len(publicData) > 0 {
		sum := sha256.Sum256(publicData)
		actualPublicDigest := "sha256:" + hex.EncodeToString(sum[:])
		if actualPublicDigest != catalog.PublicDigest {
			return nil, fmt.Errorf("public catalog digest does not match the runtime catalog")
		}
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

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
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
	if err := validateCompiledAuthors(graph); err != nil {
		return err
	}
	if err := validateCompiledProviders(graph); err != nil {
		return err
	}
	selectors := make(selectorRegistry)
	if err := validateCompiledModels(graph, selectors); err != nil {
		return err
	}
	if err := validateCompiledRoutes(graph); err != nil {
		return err
	}
	if err := validateCompiledDeployments(graph, selectors); err != nil {
		return err
	}
	return validateCanonicalRouteDeployments(graph)
}

type selectorRegistry map[string]string

func (selectors selectorRegistry) add(selector, owner string) error {
	if strings.TrimSpace(selector) != selector || selector == "" || strings.Contains(selector, "/") {
		return fmt.Errorf("selector %q is not canonical", selector)
	}
	if existing := selectors[selector]; existing != "" {
		return fmt.Errorf("selector %s is shared by %s and %s", selector, existing, owner)
	}
	selectors[selector] = owner
	return nil
}

func validateCompiledAuthors(graph compiledGraph) error {
	authorQualifiers := make(map[string]string)
	for authorID, author := range graph.Authors {
		if err := validateQualifierAliases(authorQualifiers, "author", authorID, author.Aliases); err != nil {
			return err
		}
	}
	return nil
}

func validateCompiledProviders(graph compiledGraph) error {
	providerQualifiers := make(map[string]string)
	for providerID, provider := range graph.Providers {
		if err := validateQualifierAliases(providerQualifiers, "provider", providerID, provider.Aliases); err != nil {
			return err
		}
		if !validCredentialModes(provider.CredentialModes) {
			return fmt.Errorf("provider %s has invalid credential modes", providerID)
		}
	}
	return nil
}

func validateCompiledModels(graph compiledGraph, selectors selectorRegistry) error {
	for modelID, model := range graph.Models {
		if len(model.Aliases) > maxAliasesPerNode {
			return fmt.Errorf("model %s has too many aliases", modelID)
		}
		if _, ok := graph.Authors[model.AuthorID]; !ok {
			return fmt.Errorf("model %s references unknown author %s", modelID, model.AuthorID)
		}
		if err := validateModelReasoning(modelID, model); err != nil {
			return err
		}
		if err := selectors.add(modelID, "model:"+modelID); err != nil {
			return err
		}
		for _, alias := range model.Aliases {
			if err := selectors.add(alias, "model:"+modelID); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCompiledRoutes(graph compiledGraph) error {
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
	return nil
}

func validateCompiledDeployments(graph compiledGraph, selectors selectorRegistry) error {
	for deploymentID, deployment := range graph.Deployments {
		if err := validateCompiledDeployment(graph, selectors, deploymentID, deployment); err != nil {
			return err
		}
	}
	return nil
}

func validateCompiledDeployment(graph compiledGraph, selectors selectorRegistry, deploymentID string, deployment compiledDeployment) error {
	if len(deployment.Aliases) > maxAliasesPerNode {
		return fmt.Errorf("deployment %s has too many aliases", deploymentID)
	}
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
	if err := selectors.add(deploymentID, "deployment:"+deploymentID); err != nil {
		return err
	}

	providerID, err := validateDeploymentRoutes(graph, deploymentID, deployment)
	if err != nil {
		return err
	}
	if err := validateDeploymentUpstreamSelector(deploymentID, providerID, model, deployment); err != nil {
		return err
	}
	if err := validateDeploymentRouteDataHandling(deploymentID, providerID, deployment); err != nil {
		return err
	}
	if err := validateDeploymentPricing(deploymentID, providerID, model.AuthorID, deployment); err != nil {
		return err
	}
	if err := validateReasoningEfforts("deployment "+deploymentID, deployment.ReasoningEfforts); err != nil {
		return err
	}
	if err := validateDeploymentRouteOverrides(deploymentID, deployment); err != nil {
		return err
	}
	if err := validateReasoningConfiguration(deploymentID, providerID, model.AuthorID, deployment, graph); err != nil {
		return err
	}
	if err := validateDeploymentReasoningInheritance(deploymentID, model, deployment); err != nil {
		return err
	}
	for _, alias := range deployment.Aliases {
		if err := selectors.add(alias, "deployment:"+deploymentID); err != nil {
			return err
		}
	}
	return nil
}

func validateDeploymentRoutes(graph compiledGraph, deploymentID string, deployment compiledDeployment) (string, error) {
	providerID := ""
	routeIDs := make(map[string]struct{}, len(deployment.RouteIDs))
	for _, routeID := range deployment.RouteIDs {
		if _, repeated := routeIDs[routeID]; repeated {
			return "", fmt.Errorf("deployment %s repeats route %s", deploymentID, routeID)
		}
		routeIDs[routeID] = struct{}{}
		route, ok := graph.Routes[routeID]
		if !ok {
			return "", fmt.Errorf("deployment %s references unknown route %s", deploymentID, routeID)
		}
		if providerID != "" && route.ProviderID != providerID {
			return "", fmt.Errorf("deployment %s spans multiple providers", deploymentID)
		}
		providerID = route.ProviderID
	}
	if providerID == "" {
		return "", fmt.Errorf("deployment %s has no route", deploymentID)
	}
	if len(deployment.DataHandlingByRoute) != len(routeIDs) {
		return "", fmt.Errorf("deployment %s does not define exact route data handling", deploymentID)
	}
	for routeID := range deployment.DataHandlingByRoute {
		if _, attached := routeIDs[routeID]; !attached {
			return "", fmt.Errorf("deployment %s defines data handling for unattached route %s", deploymentID, routeID)
		}
	}
	return providerID, nil
}

func validateDeploymentUpstreamSelector(deploymentID, providerID string, model compiledModel, deployment compiledDeployment) error {
	selector := deployment.Upstream
	switch providerID {
	case "openai":
		if selector.ChuteID != "" || selector.GPUCount != 0 || selector.InferenceGeo != "" || selector.Speed != "" ||
			selector.Hosting != "" || selector.DeploymentType != "" || selector.ModelFormat != "" || selector.ModelVersion != "" ||
			(selector.ReasoningMode != "" && selector.ReasoningMode != "pro") ||
			(selector.ServiceTier != "default" && selector.ServiceTier != "flex" && selector.ServiceTier != "priority") {
			return fmt.Errorf("deployment %s has an invalid OpenAI upstream selector", deploymentID)
		}
	case "anthropic":
		if selector.ChuteID != "" || selector.GPUCount != 0 || selector.ReasoningMode != "" || selector.ServiceTier != "" ||
			selector.Hosting != "" || selector.DeploymentType != "" || selector.ModelFormat != "" || selector.ModelVersion != "" ||
			(selector.Speed != "" && selector.Speed != "standard" && selector.Speed != "fast") ||
			(selector.InferenceGeo != "" && selector.InferenceGeo != "global" && selector.InferenceGeo != "us") {
			return fmt.Errorf("deployment %s has an invalid Anthropic upstream selector", deploymentID)
		}
	case "chutes":
		if !canonicalUUIDPattern.MatchString(selector.ChuteID) ||
			selector.GPUCount < 1 || selector.GPUCount > 8 || selector.InferenceGeo != "" ||
			selector.ReasoningMode != "" || selector.ServiceTier != "" || selector.Speed != "" ||
			selector.Hosting != "" || selector.DeploymentType != "" || selector.ModelFormat != "" || selector.ModelVersion != "" {
			return fmt.Errorf("deployment %s has an invalid Chutes upstream selector", deploymentID)
		}
	case "azure":
		return validateAzureUpstreamSelector(deploymentID, model, deployment)
	default:
		return fmt.Errorf("deployment %s uses unsupported provider %s", deploymentID, providerID)
	}
	return nil
}

func validateAzureUpstreamSelector(deploymentID string, model compiledModel, deployment compiledDeployment) error {
	selector := deployment.Upstream
	modelFormat := strings.ToLower(selector.ModelFormat)
	if selector.ChuteID != "" || selector.GPUCount != 0 || selector.InferenceGeo != "" || selector.Speed != "" ||
		strings.TrimSpace(selector.ModelFormat) == "" || strings.TrimSpace(selector.ModelVersion) == "" ||
		(selector.ReasoningMode != "" && selector.ReasoningMode != "pro") ||
		(selector.ServiceTier != "" && selector.ServiceTier != "default" && selector.ServiceTier != "priority") ||
		!stringIn([]string{"azure", "anthropic", "fireworks", "nvidia"}, selector.Hosting) ||
		!stringIn([]string{"global_standard", "data_zone_standard_us", "data_zone_standard_eu", "data_zone_standard_apac", "instant"}, selector.DeploymentType) {
		return fmt.Errorf("deployment %s has an invalid Azure upstream selector", deploymentID)
	}
	validFormatHost := (modelFormat == "anthropic" && stringIn([]string{"anthropic", "azure"}, selector.Hosting)) ||
		(modelFormat == "fireworks" && selector.Hosting == "fireworks") ||
		(stringIn([]string{"deepseek", "openai", "openai-oss"}, modelFormat) && selector.Hosting == "azure") ||
		(modelFormat == "nvidia" && selector.Hosting == "nvidia")
	if !validFormatHost {
		return fmt.Errorf("deployment %s has mismatched Azure model format and hosting", deploymentID)
	}
	usesAnthropicMessages := stringIn(deployment.RouteIDs, "azure-anthropic-messages")
	if usesAnthropicMessages != (model.AuthorID == "anthropic") {
		return fmt.Errorf("deployment %s has an invalid Azure protocol route", deploymentID)
	}
	if model.AuthorID == "anthropic" && selector.Hosting != "azure" && selector.Hosting != "anthropic" {
		return fmt.Errorf("deployment %s has an invalid Azure Claude host", deploymentID)
	}
	if selector.Hosting == "anthropic" && selector.DeploymentType != "global_standard" {
		return fmt.Errorf("deployment %s has an invalid Anthropic-hosted deployment type", deploymentID)
	}
	if selector.DeploymentType != "global_standard" && selector.Hosting != "azure" && selector.Hosting != "fireworks" {
		return fmt.Errorf("deployment %s has an invalid Data Zone host", deploymentID)
	}
	if selector.ServiceTier == "priority" &&
		(!stringIn([]string{"gpt-5.6-sol", "gpt-5.6-terra"}, selector.Model) || selector.DeploymentType != "global_standard") {
		return fmt.Errorf("deployment %s enables Azure Priority for an unsupported model", deploymentID)
	}
	if selector.DeploymentType == "instant" &&
		(selector.Hosting != "azure" ||
			modelFormat != "openai" ||
			!stringIn([]string{"gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra"}, selector.Model) ||
			selector.ServiceTier != "default") {
		return fmt.Errorf("deployment %s has an unsupported Azure Instant target", deploymentID)
	}
	if modelFormat == "fireworks" &&
		(selector.DeploymentType != "data_zone_standard_us" ||
			len(deployment.RouteIDs) != 1 || deployment.RouteIDs[0] != "azure-chat-completions") {
		return fmt.Errorf("deployment %s has an invalid Azure Fireworks target", deploymentID)
	}
	return nil
}

func validateDeploymentRouteDataHandling(deploymentID, providerID string, deployment compiledDeployment) error {
	for _, routeID := range deployment.RouteIDs {
		handling, exists := deployment.DataHandlingByRoute[routeID]
		if !exists {
			return fmt.Errorf("deployment %s has no data handling for route %s", deploymentID, routeID)
		}
		if err := validateDeploymentDataHandling(deploymentID, routeID, providerID, handling); err != nil {
			return err
		}
		if providerID == "azure" {
			if err := validateAzureDataHandling(deploymentID, routeID, deployment.Upstream, handling); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAzureDataHandling(deploymentID, routeID string, selector compiledUpstream, handling DataHandling) error {
	if selector.Hosting == "azure" {
		type locations struct {
			processing string
			storage    string
		}
		expected, constrained := map[string]locations{
			"data_zone_standard_us":   {processing: "US", storage: "US"},
			"data_zone_standard_eu":   {processing: "europe", storage: "europe"},
			"data_zone_standard_apac": {processing: "apac", storage: "apac"},
		}[selector.DeploymentType]
		if constrained &&
			(handling.ProcessingLocation != expected.processing || handling.StorageLocation != expected.storage) {
			return fmt.Errorf("deployment %s route %s has invalid Data Zone handling", deploymentID, routeID)
		}
	}
	if selector.Hosting != "" && selector.Hosting != "azure" &&
		(handling.ProcessingLocation != "unknown" || handling.StorageLocation != "unknown") {
		return fmt.Errorf("deployment %s route %s has disclosed locations for externally hosted Azure inference", deploymentID, routeID)
	}
	return nil
}

func validateCanonicalRouteDeployments(graph compiledGraph) error {
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

func validateDeploymentDataHandling(deploymentID, routeID, _ string, handling DataHandling) error {
	if !IsCanonicalDataLocation(handling.ProcessingLocation, false) ||
		!IsCanonicalDataLocation(handling.StorageLocation, true) {
		return fmt.Errorf("deployment %s route %s has an invalid data handling location", deploymentID, routeID)
	}
	if handling.TEEVerified && !handling.TEE {
		return fmt.Errorf("deployment %s route %s verifies a TEE that is not enabled", deploymentID, routeID)
	}
	return nil
}

// IsCanonicalDataLocation reports whether value uses the catalog's closed location vocabulary.
func IsCanonicalDataLocation(value string, allowNone bool) bool {
	if value == "global" || value == "apac" || value == "eu" || value == "europe" || value == "unknown" || (allowNone && value == "none") {
		return true
	}
	return len(value) == 2 && strings.Contains(isoCountryCodes, "|"+value+"|")
}

// DataLocationWithin reports whether actual is at least as geographically narrow as boundary.
func DataLocationWithin(actual, boundary string) bool {
	if !IsCanonicalDataLocation(actual, true) || !IsCanonicalDataLocation(boundary, true) {
		return false
	}
	if actual == boundary || boundary == "global" || boundary == "unknown" {
		return true
	}
	if actual == "unknown" || actual == "global" || actual == "none" || boundary == "none" {
		return false
	}
	switch boundary {
	case "eu":
		return strings.Contains(euCountryCodes, "|"+actual+"|")
	case "europe":
		return actual == "eu" || strings.Contains(europeCountryCodes, "|"+actual+"|")
	case "apac":
		return strings.Contains(apacCountryCodes, "|"+actual+"|")
	default:
		return false
	}
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

func validateDeploymentPricing(deploymentID, providerID, modelAuthorID string, deployment compiledDeployment) error {
	for _, required := range []string{
		billing.MeterInputTokens,
		billing.MeterOutputTokens,
	} {
		if len(deployment.Pricing[required]) == 0 {
			return fmt.Errorf("deployment %s is missing required pricing meter %s", deploymentID, required)
		}
	}
	if (deployment.Capabilities.ImplicitPromptCaching || deployment.Capabilities.ExplicitPromptCaching) &&
		len(deployment.Pricing[billing.MeterCachedInputTokens]) == 0 {
		return fmt.Errorf("deployment %s is missing required pricing meter %s", deploymentID, billing.MeterCachedInputTokens)
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
	usesAnthropicPricing := providerID == "anthropic" || (providerID == "azure" && modelAuthorID == "anthropic")
	if usesAnthropicPricing {
		if len(deployment.Pricing[billing.MeterCacheWriteInputTokens]) > 0 {
			return fmt.Errorf("deployment %s uses OpenAI cache-write pricing", deploymentID)
		}
		for _, required := range []string{
			billing.MeterCacheWrite5mInputTokens,
			billing.MeterCacheWrite1hInputTokens,
		} {
			if len(deployment.Pricing[required]) == 0 {
				return fmt.Errorf("deployment %s is missing provider pricing meter %s", deploymentID, required)
			}
		}
		if providerID == "anthropic" && len(deployment.Pricing[meterAnthropicWebSearchCalls]) == 0 {
			return fmt.Errorf("deployment %s is missing provider pricing meter %s", deploymentID, meterAnthropicWebSearchCalls)
		}
		if providerID == "azure" && len(deployment.Pricing[meterAnthropicWebSearchCalls]) > 0 {
			return fmt.Errorf("deployment %s uses unavailable Azure Anthropic web-search pricing", deploymentID)
		}
		return nil
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
	switch model.Reasoning {
	case "optional", "required", "unsupported":
	default:
		return fmt.Errorf("model %s has invalid reasoning availability", modelID)
	}
	if err := validateReasoningEfforts("model "+modelID, model.ReasoningEfforts); err != nil {
		return err
	}
	if model.Reasoning == "unsupported" &&
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
	if model.Reasoning == "unsupported" && deployment.Reasoning != "unsupported" {
		return fmt.Errorf("deployment %s enables model-unsupported reasoning", deploymentID)
	}
	if model.Reasoning == "required" && deployment.Reasoning != "required" {
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

func validateDeploymentRouteOverrides(deploymentID string, deployment compiledDeployment) error {
	deploymentEfforts := make(map[string]struct{}, len(deployment.ReasoningEfforts))
	for _, effort := range deployment.ReasoningEfforts {
		deploymentEfforts[effort] = struct{}{}
	}
	for routeID, override := range deployment.RouteOverrides {
		if !stringIn(deployment.RouteIDs, routeID) {
			return fmt.Errorf("deployment %s overrides unattached route %s", deploymentID, routeID)
		}
		if err := validateReasoningEfforts("deployment "+deploymentID+" route "+routeID, override.ReasoningEfforts); err != nil {
			return err
		}
		if sameStrings(override.ReasoningEfforts, deployment.ReasoningEfforts) {
			return fmt.Errorf("deployment %s route %s redundantly repeats reasoning efforts", deploymentID, routeID)
		}
		for _, effort := range override.ReasoningEfforts {
			if _, ok := deploymentEfforts[effort]; !ok {
				return fmt.Errorf("deployment %s route %s enables an unsupported reasoning effort", deploymentID, routeID)
			}
		}
	}
	return nil
}

func validateReasoningConfiguration(deploymentID, providerID, modelAuthorID string, deployment compiledDeployment, graph compiledGraph) error {
	switch deployment.Reasoning {
	case "optional", "required", "unsupported":
	default:
		return fmt.Errorf("deployment %s has invalid reasoning availability", deploymentID)
	}
	if deployment.Reasoning == "unsupported" &&
		(len(deployment.ReasoningEfforts) > 0 || deployment.ReasoningMaxTokens != nil) {
		return fmt.Errorf("deployment %s exposes controls for unsupported reasoning", deploymentID)
	}
	if budget := deployment.ReasoningMaxTokens; budget != nil {
		supportsManualBudget := providerID == "anthropic" || (providerID == "azure" && modelAuthorID == "anthropic")
		if !supportsManualBudget || budget.Minimum < 1 || budget.Maximum < budget.Minimum || budget.Maximum >= deployment.MaxOutputTokens {
			return fmt.Errorf("deployment %s has an invalid manual reasoning token limit", deploymentID)
		}
	}
	if deployment.Upstream.ReasoningMode == "" {
		return nil
	}
	if (providerID != "openai" && providerID != "azure") || deployment.Upstream.ReasoningMode != "pro" ||
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
	if len(aliases) > maxAliasesPerNode {
		return fmt.Errorf("%s %s has too many aliases", kind, id)
	}
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

// The public graph can include reviewed models that have no executable
// deployment. Every executable runtime model must still exist publicly.
func hasEveryKey[A, B any](superset map[string]A, required map[string]B) bool {
	for key := range required {
		if _, ok := superset[key]; !ok {
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
