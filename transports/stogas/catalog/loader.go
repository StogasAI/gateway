package catalog

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

const (
	runtimeSchema      = "stogas.catalog.runtime.v6"
	publicSchema       = "stogas.catalog.public.v8"
	publicPartSchema   = "stogas.catalog.public.part.v8"
	archiveIndexSchema = "stogas.catalog.archive.index.v1"
	archivePartSchema  = "stogas.catalog.archive.part.v1"
	// Evidence approves the runtime catalog and the public root by digest, and the root names
	// its parts and the archive's index and parts by digest. Each file, the root with its parts,
	// and the archive with its files have their own limits.
	runtimeSizeLimit       = 32 * 1024 * 1024
	publicSizeLimit        = 16 * 1024 * 1024
	publicPartSizeLimit    = 1024 * 1024
	archiveIndexSizeLimit  = 16 * 1024 * 1024
	publicCatalogSizeLimit = 64 * 1024 * 1024
	archiveSizeLimit       = 64 * 1024 * 1024
	maxAliasesPerNode      = 8
)

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

// The fallback embeds every file that its public root names.
//
//go:embed fallback
var fallbackFiles embed.FS

var (
	embeddedRuntimeCatalogJSON = fallbackFile("catalog.runtime.json")
	embeddedPublicCatalogJSON  = fallbackFile("catalog.public.json")
)

func fallbackFile(name string) []byte {
	data, _ := fallbackFiles.ReadFile("fallback/" + name)
	return data
}

func loadSnapshot() (*snapshot, error) {
	parts, err := embeddedPublicParts()
	if err != nil {
		return nil, err
	}
	return snapshotFromRelease(embeddedRuntimeCatalogJSON, embeddedPublicCatalogJSON, parts, Identity{})
}

// embeddedPublicParts reads every file that the embedded public root names, by SHA-256 in hex.
func embeddedPublicParts() (map[string][]byte, error) {
	files, err := PublicCatalogFiles(embeddedPublicCatalogJSON)
	if err != nil {
		return nil, err
	}
	parts := make(map[string][]byte, len(files))
	for _, file := range files {
		data, err := fallbackFiles.ReadFile("fallback/catalog.public.parts/" + file.SHA256 + ".json")
		if err != nil {
			return nil, fmt.Errorf("read embedded public catalog part: %w", err)
		}
		parts[file.SHA256] = data
	}
	return parts, nil
}

// PublicFile names a file of the public catalog by the SHA-256, in hex, and size of its bytes.
type PublicFile struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// publicListing is what a public root names: its parts, and the archive's index and parts, or
// no archive while nothing has moved there.
type publicListing struct {
	Parts   []PublicFile `json:"parts"`
	Archive *struct {
		Index PublicFile   `json:"index"`
		Parts []PublicFile `json:"parts"`
	} `json:"archive"`
}

// listPublicFiles reads what a root names, after checking each name and size and the size of
// the catalog and of the archive with all their files.
func listPublicFiles(root []byte) (publicListing, error) {
	var listing publicListing
	if err := json.Unmarshal(root, &listing); err != nil {
		return publicListing{}, fmt.Errorf("decode public catalog files: %w", err)
	}
	seen := make(map[string]bool)
	total := func(files []PublicFile, limit int64) (int64, bool) {
		var sum int64
		for _, file := range files {
			decoded, err := hex.DecodeString(file.SHA256)
			if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != file.SHA256 ||
				seen[file.SHA256] || file.Size < 1 || file.Size > limit {
				return 0, false
			}
			seen[file.SHA256] = true
			sum += file.Size
		}
		return sum, true
	}
	invalid := errors.New("public catalog names an invalid file")
	parts, ok := total(listing.Parts, publicPartSizeLimit)
	if !ok {
		return publicListing{}, invalid
	}
	if int64(len(root))+parts > publicCatalogSizeLimit {
		return publicListing{}, errors.New("public catalog exceeds the accepted size")
	}
	if archive := listing.Archive; archive != nil {
		index, indexOK := total([]PublicFile{archive.Index}, archiveIndexSizeLimit)
		parts, partsOK := total(archive.Parts, publicPartSizeLimit)
		if !indexOK || !partsOK || len(archive.Parts) == 0 {
			return publicListing{}, invalid
		}
		if index+parts > archiveSizeLimit {
			return publicListing{}, errors.New("catalog archive exceeds the accepted size")
		}
	}
	return listing, nil
}

// PublicCatalogFiles lists every file that a public root names: its parts, then the archive's
// index and parts.
func PublicCatalogFiles(root []byte) ([]PublicFile, error) {
	listing, err := listPublicFiles(root)
	if err != nil {
		return nil, err
	}
	files := slices.Clone(listing.Parts)
	if archive := listing.Archive; archive != nil {
		files = append(append(files, archive.Index), archive.Parts...)
	}
	return files, nil
}

// publicSummary is what the root keeps of a deployment that the gateway checks.
type publicSummary struct {
	Part int `json:"part"`
}

// publicPartsFor checks that parts holds exactly the files that the root names, each with its
// digest and size; that the root's parts hold exactly the deployments that the root places in
// them; and that the archive holds exactly the records that the runtime catalog lists as
// retired, each in the archive part that the index names.
func publicPartsFor(root []byte, summaries map[string]publicSummary, retired retiredNodes, parts map[string][]byte) (map[string][]byte, error) {
	listing, err := listPublicFiles(root)
	if err != nil {
		return nil, err
	}
	differ := errors.New("public catalog parts differ from the root")
	held := make(map[string][]byte, len(parts))
	read := func(file PublicFile, value any) error {
		data, ok := parts[file.SHA256]
		sum := sha256.Sum256(data)
		if !ok || int64(len(data)) != file.Size || hex.EncodeToString(sum[:]) != file.SHA256 {
			return differ
		}
		held[file.SHA256] = append([]byte(nil), data...)
		if err := json.Unmarshal(data, value); err != nil {
			return fmt.Errorf("decode public catalog part: %w", err)
		}
		return nil
	}
	deployments := 0
	for index, file := range listing.Parts {
		var part struct {
			Schema      string                     `json:"schema"`
			Deployments map[string]json.RawMessage `json:"deployments"`
		}
		if err := read(file, &part); err != nil {
			return nil, err
		}
		if part.Schema != publicPartSchema {
			return nil, fmt.Errorf("public catalog part schema %q is unsupported", part.Schema)
		}
		for id := range part.Deployments {
			if summary, ok := summaries[id]; !ok || summary.Part != index {
				return nil, fmt.Errorf("public catalog part %d holds deployment %s that the root places elsewhere", index, id)
			}
		}
		deployments += len(part.Deployments)
	}
	// Each part holds only its own deployments, so equal counts mean every deployment is there.
	if deployments != len(summaries) {
		return nil, errors.New("public catalog parts omit a deployment")
	}
	if archive := listing.Archive; archive != nil {
		if err := checkArchive(archive.Index, archive.Parts, retired, read); err != nil {
			return nil, err
		}
	} else if len(retired.Deployments) > 0 || len(retired.Models) > 0 {
		return nil, errors.New("catalog archive does not match the runtime catalog")
	}
	if len(held) != len(parts) {
		return nil, differ
	}
	return held, nil
}

// checkArchive checks that the archive index lists exactly the deployments that the runtime
// catalog lists as retired, and the models that it lists under their IDs and aliases, each with
// its retirement day, and that each archive part holds exactly the records that the index places
// in it.
func checkArchive(indexFile PublicFile, partFiles []PublicFile, retired retiredNodes, read func(PublicFile, any) error) error {
	var index struct {
		Schema      string `json:"schema"`
		Deployments map[string]struct {
			Part           int    `json:"part"`
			RetirementDate string `json:"retirementDate"`
		} `json:"deployments"`
		Models map[string]struct {
			Aliases        []string `json:"aliases"`
			Part           int      `json:"part"`
			RetirementDate string   `json:"retirementDate"`
		} `json:"models"`
	}
	if err := read(indexFile, &index); err != nil {
		return err
	}
	mismatch := errors.New("catalog archive does not match the runtime catalog")
	if index.Schema != archiveIndexSchema || len(index.Deployments) != len(retired.Deployments) {
		return mismatch
	}
	for id, entry := range index.Deployments {
		if date, ok := retired.Deployments[id]; !ok || date != entry.RetirementDate {
			return mismatch
		}
	}
	selectors := 0
	for id, entry := range index.Models {
		for _, selector := range append([]string{id}, entry.Aliases...) {
			if date, ok := retired.Models[selector]; !ok || date != entry.RetirementDate {
				return mismatch
			}
			selectors++
		}
	}
	if selectors != len(retired.Models) {
		return mismatch
	}
	records := 0
	for position, file := range partFiles {
		var part struct {
			Schema      string                     `json:"schema"`
			Deployments map[string]json.RawMessage `json:"deployments"`
			Models      map[string]json.RawMessage `json:"models"`
		}
		if err := read(file, &part); err != nil {
			return err
		}
		if part.Schema != archivePartSchema {
			return fmt.Errorf("catalog archive part schema %q is unsupported", part.Schema)
		}
		for id := range part.Deployments {
			if entry, ok := index.Deployments[id]; !ok || entry.Part != position {
				return fmt.Errorf("catalog archive part %d holds deployment %s that the index places elsewhere", position, id)
			}
		}
		for id := range part.Models {
			if entry, ok := index.Models[id]; !ok || entry.Part != position {
				return fmt.Errorf("catalog archive part %d holds model %s that the index places elsewhere", position, id)
			}
		}
		records += len(part.Deployments) + len(part.Models)
	}
	if records != len(index.Deployments)+len(index.Models) {
		return errors.New("catalog archive parts omit a record")
	}
	return nil
}

// validateRetired checks that each archived deployment and model has the date it retired and
// that no request can reach it in the graph: a deployment by its ID, and a model by its ID or an
// alias.
func validateRetired(retired retiredNodes, base *snapshot) error {
	active := func(selector string) bool {
		_, deployment := base.graph.Deployments[selector]
		_, model := base.modelSelectors[selector]
		return deployment || model
	}
	for id, date := range retired.Deployments {
		if active(id) || !validDate(date) {
			return fmt.Errorf("retired deployment %s is invalid", id)
		}
	}
	for selector, date := range retired.Models {
		if active(selector) || !validDate(date) {
			return fmt.Errorf("retired model %s is invalid", selector)
		}
	}
	return nil
}

func snapshotFromRelease(runtimeData, publicData []byte, parts map[string][]byte, identity Identity) (*snapshot, error) {
	if len(runtimeData) == 0 || len(runtimeData) > runtimeSizeLimit {
		return nil, fmt.Errorf("runtime catalog size is outside the accepted range")
	}
	catalog, err := decodeCompiledCatalog(runtimeData)
	if err != nil {
		return nil, fmt.Errorf("decode runtime catalog: %w", err)
	}
	if catalog.Schema != runtimeSchema {
		return nil, fmt.Errorf("runtime catalog schema %q is unsupported", catalog.Schema)
	}
	if !validSHA256Digest(catalog.PublicDigest) {
		return nil, fmt.Errorf("runtime catalog public digest is invalid")
	}
	base, err := stateFromGraph(catalog.Graph)
	if err != nil {
		return nil, err
	}
	if err := validateRetired(catalog.Retired, base); err != nil {
		return nil, err
	}
	states := []*snapshot{base}
	for index, entry := range catalog.Schedule {
		if entry.Start.IsZero() || (index > 0 && !entry.Start.After(catalog.Schedule[index-1].Start)) {
			return nil, fmt.Errorf("catalog schedule entry %d does not start after the entry before it", index)
		}
		graph, err := scheduledGraph(catalog.Graph, entry.Graph)
		if err != nil {
			return nil, fmt.Errorf("catalog schedule entry %d: %w", index, err)
		}
		state, err := stateFromGraph(graph)
		if err != nil {
			return nil, fmt.Errorf("catalog state from %s: %w", entry.Start.Format(time.RFC3339), err)
		}
		base.schedule = append(base.schedule, datedState{start: entry.Start, state: state})
		states = append(states, state)
	}
	var publicParts map[string][]byte
	if len(publicData) > 0 {
		if len(publicData) > publicSizeLimit {
			return nil, fmt.Errorf("public catalog exceeds the accepted size")
		}
		var publicHeader struct {
			Schema string `json:"schema"`
			Graph  struct {
				Authors     map[string]json.RawMessage `json:"authors"`
				Deployments map[string]publicSummary   `json:"deployments"`
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
		if publicParts, err = publicPartsFor(publicData, publicHeader.Graph.Deployments, catalog.Retired, parts); err != nil {
			return nil, err
		}
	}

	runtimeDigest := sha256.Sum256(runtimeData)
	digest := "sha256:" + hex.EncodeToString(runtimeDigest[:])
	if identity.Digest == "" {
		identity.Digest = digest
	} else if identity.Digest != digest {
		return nil, fmt.Errorf("runtime catalog digest does not match the signed release")
	}
	if len(publicData) > 0 {
		sum := sha256.Sum256(publicData)
		actualPublicDigest := "sha256:" + hex.EncodeToString(sum[:])
		if actualPublicDigest != catalog.PublicDigest {
			return nil, fmt.Errorf("public catalog digest does not match the runtime catalog")
		}
	}
	publicRaw, raw := append([]byte(nil), publicData...), append([]byte(nil), runtimeData...)
	for _, state := range states {
		state.identity, state.publicDigest, state.publicRaw, state.publicParts, state.raw = identity, catalog.PublicDigest, publicRaw, publicParts, raw
		state.retired = catalog.Retired
	}
	return base, nil
}

// stateFromGraph validates one catalog state and indexes it for requests.
func stateFromGraph(graph compiledGraph) (*snapshot, error) {
	if err := validateCompiledGraph(graph); err != nil {
		return nil, err
	}
	modelSelectors := make(map[string]string)
	groups := make(map[string]bool)
	for modelID, model := range graph.Models {
		modelSelectors[modelID] = modelID
		for _, alias := range model.Aliases {
			modelSelectors[alias] = modelID
		}
		for _, groupID := range model.GroupIDs {
			groups[groupID] = true
		}
	}
	routeDeployments := routeDeploymentsForGraph(graph)
	routes := make(map[string]compiledRoute, len(graph.Routes))
	for routeID, route := range graph.Routes {
		route.ID = routeID
		route.DeploymentIDs = routeDeployments[routeID]
		sortDeploymentIDs(route.DeploymentIDs, graph.Deployments)
		routes[routeID] = route
	}
	graph.Routes = routes
	state := &snapshot{graph: graph, groups: groups, modelSelectors: modelSelectors}
	if err := validatePolicyVocabulary(state); err != nil {
		return nil, err
	}
	return state, nil
}

// scheduledGraph returns the base graph with an entry's nodes in place of the base nodes. An
// entry changes facts about nodes; it never adds one.
func scheduledGraph(base, entry compiledGraph) (compiledGraph, error) {
	graph := compiledGraph{
		Authors:     overlay(base.Authors, entry.Authors),
		Deployments: overlay(base.Deployments, entry.Deployments),
		Models:      overlay(base.Models, entry.Models),
		Providers:   overlay(base.Providers, entry.Providers),
		Routes:      overlay(base.Routes, entry.Routes),
	}
	if len(graph.Authors) != len(base.Authors) ||
		len(graph.Deployments) != len(base.Deployments) ||
		len(graph.Models) != len(base.Models) ||
		len(graph.Providers) != len(base.Providers) ||
		len(graph.Routes) != len(base.Routes) {
		return compiledGraph{}, fmt.Errorf("a dated state adds catalog nodes")
	}
	return graph, nil
}

func overlay[T any](base, entry map[string]T) map[string]T {
	if len(entry) == 0 {
		return base
	}
	merged := maps.Clone(base)
	maps.Copy(merged, entry)
	return merged
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validateCompiledGraph(graph compiledGraph) error {
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
		if !uniqueNonEmpty(provider.CredentialModes) {
			return fmt.Errorf("provider %s has invalid credential modes", providerID)
		}
	}
	return nil
}

func validateCompiledModels(graph compiledGraph, selectors selectorRegistry) error {
	groups := make(map[string]bool)
	for modelID, model := range graph.Models {
		if len(model.Aliases) > maxAliasesPerNode {
			return fmt.Errorf("model %s has too many aliases", modelID)
		}
		if _, ok := graph.Authors[model.AuthorID]; !ok {
			return fmt.Errorf("model %s references unknown author %s", modelID, model.AuthorID)
		}
		// Groups name their newest model, so every model needs a release date.
		if !validDate(model.ReleaseDate) {
			return fmt.Errorf("model %s has an invalid releaseDate", modelID)
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
		for _, groupID := range model.GroupIDs {
			groups[groupID] = true
		}
	}
	for groupID := range groups {
		if err := selectors.add(groupID, "group:"+groupID); err != nil {
			return err
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
		if err := validateDocumentFormats(route.DocumentFormats); err != nil {
			return fmt.Errorf("route %s: %w", routeID, err)
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
	model, ok := graph.Models[deployment.ModelID]
	if !ok {
		return fmt.Errorf("deployment %s references unknown model %s", deploymentID, deployment.ModelID)
	}
	if deployment.Upstream.Model == "" ||
		deployment.ContextWindowTokens <= 0 ||
		deployment.MaxInputTokens <= 0 ||
		deployment.MaxInputTokens > deployment.ContextWindowTokens ||
		deployment.MaxOutputTokens <= 0 ||
		deployment.MaxOutputTokens > deployment.ContextWindowTokens {
		return fmt.Errorf("deployment %s is not executable", deploymentID)
	}
	if !uniqueNonEmpty(deployment.OutputModalities) {
		return fmt.Errorf("deployment %s has invalid modalities", deploymentID)
	}
	if deployment.RetirementDate != nil && !validDate(*deployment.RetirementDate) {
		return fmt.Errorf("deployment %s has an invalid retirementDate", deploymentID)
	}
	if err := selectors.add(deploymentID, "deployment:"+deploymentID); err != nil {
		return err
	}
	providerID, err := validateDeploymentRoutes(graph, deploymentID, deployment)
	if err != nil {
		return err
	}
	if err := validateDeploymentUpstreamSelector(deploymentID, providerID, deployment); err != nil {
		return err
	}
	for _, routeID := range sortedRouteIDs(deployment) {
		route := deployment.Routes[routeID]
		owner := "deployment " + deploymentID + " route " + routeID
		if !validSHA256Digest(route.ChainHash) {
			return fmt.Errorf("%s has an invalid resolved chain", owner)
		}
		if !uniqueNonEmpty(route.InputModalities) {
			return fmt.Errorf("%s has invalid modalities", owner)
		}
		if err := validateDeploymentDataHandling(owner, route.DataHandling); err != nil {
			return err
		}
		if err := validateDeploymentPricing(owner, providerID, deployment.ModelID, route); err != nil {
			return err
		}
		if err := validateReasoningEfforts(owner, route.ReasoningEfforts); err != nil {
			return err
		}
	}
	if err := validateReasoningConfiguration(deploymentID, providerID, model.AuthorID, deployment, graph); err != nil {
		return err
	}
	return validateDeploymentReasoningInheritance(deploymentID, model, deployment)
}

// validateDeploymentRoutes returns the provider of a deployment whose routes belong to one
// provider and serve different interfaces, so each interface has one route.
func validateDeploymentRoutes(graph compiledGraph, deploymentID string, deployment compiledDeployment) (string, error) {
	providerID := ""
	interfaces := make(map[string]bool)
	for _, routeID := range sortedRouteIDs(deployment) {
		route, ok := graph.Routes[routeID]
		if !ok {
			return "", fmt.Errorf("deployment %s references unknown route %s", deploymentID, routeID)
		}
		if providerID != "" && route.ProviderID != providerID {
			return "", fmt.Errorf("deployment %s spans multiple providers", deploymentID)
		}
		providerID = route.ProviderID
		for _, name := range route.Interfaces {
			if interfaces[name] {
				return "", fmt.Errorf("deployment %s serves %s on more than one route", deploymentID, name)
			}
			interfaces[name] = true
		}
	}
	if providerID == "" {
		return "", fmt.Errorf("deployment %s has no route", deploymentID)
	}
	return providerID, nil
}

func sortedRouteIDs(deployment compiledDeployment) []string {
	return slices.Sorted(maps.Keys(deployment.Routes))
}

func validateDeploymentUpstreamSelector(deploymentID, providerID string, deployment compiledDeployment) error {
	selector := deployment.Upstream
	if _, offered := offeredTiers(schemas.ModelProvider(providerID), selector.ModelFormat)[selector.ServiceTier]; !offered {
		return fmt.Errorf("deployment %s has a service tier that its provider does not offer", deploymentID)
	}
	switch providerID {
	case "openai":
		if selector.ChuteID != "" || selector.GPUCount != nil || selector.InferenceGeo != "" ||
			selector.Hosting != "" || selector.DeploymentType != "" || selector.ModelFormat != "" || selector.ModelVersion != "" {
			return fmt.Errorf("deployment %s has an invalid OpenAI upstream selector", deploymentID)
		}
	case "anthropic":
		if selector.ChuteID != "" || selector.GPUCount != nil || selector.ReasoningMode != "" ||
			selector.Hosting != "" || selector.DeploymentType != "" || selector.ModelFormat != "" || selector.ModelVersion != "" {
			return fmt.Errorf("deployment %s has an invalid Anthropic upstream selector", deploymentID)
		}
	case "chutes":
		if selector.ChuteID == "" ||
			selector.GPUCount == nil || *selector.GPUCount < 1 || *selector.GPUCount > 8 || selector.InferenceGeo != "" ||
			selector.ReasoningMode != "" ||
			selector.Hosting != "" || selector.DeploymentType != "" || selector.ModelFormat != "" || selector.ModelVersion != "" {
			return fmt.Errorf("deployment %s has an invalid Chutes upstream selector", deploymentID)
		}
	case "azure":
		return validateAzureUpstreamSelector(deploymentID, deployment)
	default:
		return fmt.Errorf("deployment %s uses unsupported provider %s", deploymentID, providerID)
	}
	return nil
}

func validateAzureUpstreamSelector(deploymentID string, deployment compiledDeployment) error {
	selector := deployment.Upstream
	if selector.ChuteID != "" || selector.GPUCount != nil || selector.InferenceGeo != "" ||
		selector.ModelFormat == "" || strings.TrimSpace(selector.ModelVersion) == "" ||
		selector.Hosting == "" || selector.DeploymentType == "" {
		return fmt.Errorf("deployment %s has an invalid Azure upstream selector", deploymentID)
	}
	// Core sends the Anthropic wire format when the catalog model ID names Claude, so only the
	// Anthropic Messages route can serve those models.
	anthropicWire := schemas.IsAnthropicModel(deployment.ModelID)
	for routeID := range deployment.Routes {
		if (routeID == "azure-anthropic-messages") != anthropicWire {
			return fmt.Errorf("deployment %s has an invalid Azure protocol route", deploymentID)
		}
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

func validateDeploymentDataHandling(owner string, handling DataHandling) error {
	if handling.TEEVerified && !handling.TEE {
		return fmt.Errorf("%s verifies a TEE that is not enabled", owner)
	}
	if handling.ZeroDataRetention &&
		(handling.StorageLocation != "none" || handling.RetentionDays == nil || *handling.RetentionDays != 0 || handling.TrainingUse) {
		return fmt.Errorf("%s has contradictory zero data retention", owner)
	}
	return nil
}

// uniqueNonEmpty accepts a list with at least one value and no repeats. The policy vocabulary
// pass checks the values themselves.
func uniqueNonEmpty(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	return len(seen) > 0
}

func validateDeploymentPricing(owner, providerID, modelID string, route compiledDeploymentRoute) error {
	pricing := route.Pricing
	for _, required := range []string{
		billing.MeterInputTokens,
		billing.MeterOutputTokens,
	} {
		if len(pricing[required]) == 0 {
			return fmt.Errorf("%s is missing required pricing meter %s", owner, required)
		}
	}
	if (route.Capabilities.ImplicitPromptCaching || route.Capabilities.ExplicitPromptCaching) &&
		len(pricing[billing.MeterCachedInputTokens]) == 0 {
		return fmt.Errorf("%s is missing required pricing meter %s", owner, billing.MeterCachedInputTokens)
	}
	for meterKey, rates := range pricing {
		switch {
		case tokenPricingMeters[meterKey]:
			if !validTokenRates(rates) {
				return fmt.Errorf("%s has invalid token rates for %s", owner, meterKey)
			}
		case callPricingMeters[meterKey]:
			if !validExactRates(rates, billing.RatePerThousandCalls) {
				return fmt.Errorf("%s has invalid call rates for %s", owner, meterKey)
			}
		case meterKey == meterOpenAIChatCompletionSearchPreviewModelCalls:
			if !validExactRates(
				rates,
				ratePerThousandSearchContextLowCalls,
				ratePerThousandSearchContextMediumCalls,
				ratePerThousandSearchContextHighCalls,
			) {
				return fmt.Errorf("%s has invalid search-context rates for %s", owner, meterKey)
			}
		default:
			return fmt.Errorf("%s uses unsupported pricing meter %s", owner, meterKey)
		}
	}
	// Only the Anthropic wire reports cache writes by duration; billing an
	// unpriced write as ordinary input would undercharge it.
	if providerID == "anthropic" || (providerID == "azure" && schemas.IsAnthropicModel(modelID)) {
		if len(pricing[billing.MeterCacheWriteInputTokens]) > 0 {
			return fmt.Errorf("%s uses OpenAI cache-write pricing", owner)
		}
		for _, required := range []string{
			billing.MeterCacheWrite5mInputTokens,
			billing.MeterCacheWrite1hInputTokens,
		} {
			if len(pricing[required]) == 0 {
				return fmt.Errorf("%s is missing Anthropic pricing meter %s", owner, required)
			}
		}
	} else if len(pricing[billing.MeterCacheWrite5mInputTokens]) > 0 ||
		len(pricing[billing.MeterCacheWrite1hInputTokens]) > 0 {
		return fmt.Errorf("%s uses Anthropic cache-write meters", owner)
	}
	return nil
}

func validTokenRates(rates map[string]string) bool {
	if _, ok := rates[billing.RatePerMillionTokens]; !ok {
		return false
	}
	for key, raw := range rates {
		if _, isContextRate := billing.ContextCutoff(key); key != billing.RatePerMillionTokens && !isContextRate {
			return false
		}
		if _, ok := billing.ParseRate(raw); !ok {
			return false
		}
	}
	return true
}

func validExactRates(rates map[string]string, keys ...string) bool {
	if len(rates) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := billing.ParseRate(rates[key]); !ok {
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
	for _, route := range deployment.Routes {
		for _, effort := range route.ReasoningEfforts {
			if !stringIn(model.ReasoningEfforts, effort) {
				return fmt.Errorf("deployment %s enables a model-unsupported reasoning effort", deploymentID)
			}
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

func validateReasoningConfiguration(deploymentID, providerID, modelAuthorID string, deployment compiledDeployment, graph compiledGraph) error {
	if deployment.Reasoning == "unsupported" {
		exposed := deployment.ReasoningMaxTokens != nil
		for _, route := range deployment.Routes {
			exposed = exposed || len(route.ReasoningEfforts) > 0
		}
		if exposed {
			return fmt.Errorf("deployment %s exposes controls for unsupported reasoning", deploymentID)
		}
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
		modelAuthorID != "openai" {
		return fmt.Errorf("deployment %s has an invalid fixed reasoning mode", deploymentID)
	}
	for routeID := range deployment.Routes {
		route := graph.Routes[routeID]
		if len(route.Interfaces) != 1 || route.Interfaces[0] != "responses" {
			return fmt.Errorf("deployment %s fixed reasoning mode requires the Responses API", deploymentID)
		}
	}
	return nil
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

func validDate(value string) bool {
	parsed, err := time.Parse(time.DateOnly, value)
	return err == nil && parsed.Format(time.DateOnly) == value
}

func routeDeploymentsForGraph(graph compiledGraph) map[string][]string {
	out := make(map[string][]string, len(graph.Routes))
	for deploymentID, deployment := range graph.Deployments {
		for routeID := range deployment.Routes {
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
			return tierRank(left.Upstream.ServiceTier) < tierRank(right.Upstream.ServiceTier)
		}
		return ids[i] < ids[j]
	})
}
