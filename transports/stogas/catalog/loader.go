package catalog

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"iter"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

const (
	catalogSchema     = "stogas.catalog.v9"
	catalogPartSchema = "stogas.catalog.part.v9"
	// Evidence approves a release by the digest of its root, and the root names each part by
	// digest and size. The build refuses a larger root, part or catalog, so the gateway refuses
	// one before it downloads it.
	rootSizeLimit     = 16 * 1024 * 1024
	partSizeLimit     = 1024 * 1024
	catalogSizeLimit  = 128 * 1024 * 1024
	maxAliasesPerNode = 8
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

// The fallback is a build's root and every part that it names.
//
//go:embed fallback
var fallbackFiles embed.FS

// loadSnapshot reads the fallback with every record, so that no date can stop a gateway from
// starting; requests still refuse each record once it retires.
func loadSnapshot() (*snapshot, error) {
	root, err := fallbackFiles.ReadFile("fallback/catalog.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded catalog root: %w", err)
	}
	files, err := partFiles(root)
	if err != nil {
		return nil, err
	}
	parts := make(map[string][]byte, len(files))
	for _, file := range files {
		data, err := fallbackFiles.ReadFile("fallback/catalog.parts/" + file.SHA256 + ".json")
		if err != nil {
			return nil, fmt.Errorf("read embedded catalog part: %w", err)
		}
		parts[file.SHA256] = data
	}
	return snapshotFromFiles(root, parts, Identity{}, time.Time{})
}

// PartFile names a part by the SHA-256, in hex, and size of its bytes, with the latest date
// that one of its records retires, or none while one of them never does.
type PartFile struct {
	SHA256  string  `json:"sha256"`
	Size    int64   `json:"size"`
	Through *string `json:"through"`
}

// partFiles reads the parts that a root names, after checking the root's size and schema, each
// part's name, size and date, and the size of the root with every part.
func partFiles(root []byte) ([]PartFile, error) {
	if len(root) == 0 || len(root) > rootSizeLimit {
		return nil, errors.New("catalog root size is outside the accepted range")
	}
	var listing struct {
		Schema string     `json:"schema"`
		Parts  []PartFile `json:"parts"`
	}
	if err := json.Unmarshal(root, &listing); err != nil {
		return nil, fmt.Errorf("decode catalog root: %w", err)
	}
	if listing.Schema != catalogSchema {
		return nil, fmt.Errorf("catalog schema %q is unsupported", listing.Schema)
	}
	seen := make(map[string]bool, len(listing.Parts))
	total := int64(len(root))
	for _, file := range listing.Parts {
		decoded, err := hex.DecodeString(file.SHA256)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != file.SHA256 ||
			seen[file.SHA256] || file.Size < 1 || file.Size > partSizeLimit ||
			(file.Through != nil && !validDate(*file.Through)) {
			return nil, errors.New("catalog root names an invalid part")
		}
		seen[file.SHA256] = true
		total += file.Size
	}
	if total > catalogSizeLimit {
		return nil, errors.New("catalog exceeds the accepted size")
	}
	return listing.Parts, nil
}

// PartsInEffect lists the parts of a root that hold a record that has not retired at an
// instant, which is each part whose records do not all retire by then.
func PartsInEffect(root []byte, at time.Time) ([]PartFile, error) {
	files, err := partFiles(root)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(files, func(file PartFile) bool { return retiredAt(file.Through, at) }), nil
}

// retiredAt says whether a record that retires on a date, or never when there is none, has
// retired at an instant: once the date has ended everywhere on Earth, at 12:00 UTC on the next
// day. A provider that names a date can mean its start or its end in any time zone, so the
// gateway never stops a record before the provider does.
func retiredAt(date *string, at time.Time) bool {
	return date != nil && *date <= at.Add(-36*time.Hour).UTC().Format(time.DateOnly)
}

// snapshotFromFiles reads a release at an instant from its root and parts, which holds some of
// the parts that the root names, by SHA-256 in hex, including each part in effect then. The
// snapshot serves the parts that it was given.
func snapshotFromFiles(root []byte, parts map[string][]byte, identity Identity, at time.Time) (*snapshot, error) {
	files, err := partFiles(root)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(root)
	if digest := "sha256:" + hex.EncodeToString(sum[:]); identity.Digest == "" {
		identity.Digest = digest
	} else if identity.Digest != digest {
		return nil, errors.New("catalog root digest does not match the signed release")
	}
	held := make(map[string][]byte, len(parts))
	for _, file := range files {
		data, ok := parts[file.SHA256]
		if !ok {
			continue
		}
		sum := sha256.Sum256(data)
		if int64(len(data)) != file.Size || hex.EncodeToString(sum[:]) != file.SHA256 {
			return nil, errors.New("catalog part differs from the root")
		}
		held[file.SHA256] = bytes.Clone(data)
	}
	if len(held) != len(parts) {
		return nil, errors.New("catalog part is not in the root")
	}
	compiled, err := assemble(root, files, held, at)
	if err != nil {
		return nil, err
	}
	base, err := snapshotFromCompiled(compiled)
	if err != nil {
		return nil, err
	}
	served := servedRoot(root, identity)
	for _, state := range base.states() {
		state.identity, state.served, state.parts = identity, served, held
	}
	return base, nil
}

// assemble reads a release at an instant: the authors and providers that the root holds whole,
// and the records of the parts in effect then that have not retired, of which each model has a
// deployment, with their changes in each dated state. Each selector of a deployment or model
// that has retired keeps the day that it retired.
func assemble(rootData []byte, files []PartFile, parts map[string][]byte, at time.Time) (compiledCatalog, error) {
	prices := sharedJSON[Pricing]()
	var root catalogRoot
	if err := decodeStrict(rootData, &root, prices); err != nil {
		return compiledCatalog{}, fmt.Errorf("decode catalog root: %w", err)
	}
	summaries := root.Summaries
	kinds := []struct {
		name      string
		summaries map[string]summary
	}{{"model", summaries.Models}, {"route", summaries.Routes}, {"deployment", summaries.Deployments}}
	// A part's date bounds the dates of its records, so a part that leaves holds no record that
	// still serves.
	records := make([]int, len(files))
	for _, kind := range kinds {
		for id, summary := range kind.summaries {
			if summary.Part < 0 || summary.Part >= len(files) {
				return compiledCatalog{}, fmt.Errorf("%s %s names no part of the root", kind.name, id)
			}
			date, through := summary.RetirementDate, files[summary.Part].Through
			if (date != nil && !validDate(*date)) || (through != nil && (date == nil || *date > *through)) {
				return compiledCatalog{}, fmt.Errorf("%s %s retires after its part", kind.name, id)
			}
			records[summary.Part]++
		}
	}
	graph := compiledGraph{
		Authors:     summaries.Authors,
		Deployments: make(map[string]*compiledDeployment),
		Models:      make(map[string]compiledModel),
		Providers:   summaries.Providers,
		Routes:      make(map[string]compiledRoute),
	}
	starts := make(map[string]int, len(root.Schedule))
	for position, entry := range root.Schedule {
		starts[entry.Start] = position
	}
	changes := make([]compiledGraph, len(root.Schedule))
	for index, file := range files {
		if retiredAt(file.Through, at) {
			continue
		}
		data, ok := parts[file.SHA256]
		if !ok {
			return compiledCatalog{}, fmt.Errorf("catalog part %d is in effect but missing", index)
		}
		var part catalogPart
		if err := decodeStrict(data, &part, prices); err != nil {
			return compiledCatalog{}, fmt.Errorf("decode catalog part %d: %w", index, err)
		}
		if part.Schema != catalogPartSchema {
			return compiledCatalog{}, fmt.Errorf("catalog part schema %q is unsupported", part.Schema)
		}
		// Each record in the part, and each of its changes, belongs to a summary that places it
		// here.
		placed := func(changed partGraph) error {
			for _, kind := range []struct {
				name string
				ids  iter.Seq[string]
				in   map[string]summary
			}{
				{"model", maps.Keys(changed.Models), summaries.Models},
				{"route", maps.Keys(changed.Routes), summaries.Routes},
				{"deployment", maps.Keys(changed.Deployments), summaries.Deployments},
			} {
				for id := range kind.ids {
					if summary, ok := kind.in[id]; !ok || summary.Part != index {
						return fmt.Errorf("catalog part %d holds %s %s that the root places elsewhere", index, kind.name, id)
					}
				}
			}
			return nil
		}
		if err := placed(part.Graph); err != nil {
			return compiledCatalog{}, err
		}
		if err := inAncestorGroups(part.Graph.Models, summaries.Groups); err != nil {
			return compiledCatalog{}, err
		}
		if len(part.Graph.Models)+len(part.Graph.Routes)+len(part.Graph.Deployments) != records[index] {
			return compiledCatalog{}, fmt.Errorf("catalog part %d omits a record", index)
		}
		for id, deployment := range part.Graph.Deployments {
			if !equalDates(deployment.RetirementDate, summaries.Deployments[id].RetirementDate) {
				return compiledCatalog{}, fmt.Errorf("deployment %s retires on another date than its summary", id)
			}
		}
		maps.Copy(graph.Models, part.Graph.Models)
		maps.Copy(graph.Routes, part.Graph.Routes)
		maps.Copy(graph.Deployments, part.Graph.Deployments)
		for _, entry := range part.Schedule {
			position, ok := starts[entry.Start]
			if !ok {
				return compiledCatalog{}, fmt.Errorf("catalog part %d changes records from %s, which the root does not list", index, entry.Start)
			}
			if err := placed(entry.Graph); err != nil {
				return compiledCatalog{}, err
			}
			if err := inAncestorGroups(entry.Graph.Models, summaries.Groups); err != nil {
				return compiledCatalog{}, err
			}
			changed := &changes[position]
			changed.Models = merged(changed.Models, entry.Graph.Models)
			changed.Routes = merged(changed.Routes, entry.Graph.Routes)
			changed.Deployments = merged(changed.Deployments, entry.Graph.Deployments)
		}
	}
	retired := make(map[string]string)
	for id, summary := range summaries.Deployments {
		if retiredAt(summary.RetirementDate, at) {
			delete(graph.Deployments, id)
			retired[id] = *summary.RetirementDate
		}
	}
	for id, summary := range summaries.Routes {
		if retiredAt(summary.RetirementDate, at) {
			delete(graph.Routes, id)
		}
	}
	for id, summary := range summaries.Models {
		if retiredAt(summary.RetirementDate, at) {
			for _, selector := range append([]string{id}, summary.Aliases...) {
				retired[selector] = *summary.RetirementDate
			}
		}
	}
	// A model serves only through a deployment.
	deployed := make(map[string]bool, len(graph.Models))
	for _, deployment := range graph.Deployments {
		deployed[deployment.ModelID] = true
	}
	maps.DeleteFunc(graph.Models, func(id string, _ compiledModel) bool { return !deployed[id] })
	schedule := make([]scheduleEntry, len(root.Schedule))
	for position, entry := range root.Schedule {
		start, err := time.Parse(time.RFC3339, entry.Start)
		if err != nil {
			return compiledCatalog{}, fmt.Errorf("catalog schedule entry %d has an invalid start", position)
		}
		changed := changes[position]
		schedule[position] = scheduleEntry{Start: start, Graph: compiledGraph{
			Authors:     entry.Summaries.Authors,
			Deployments: inGraph(changed.Deployments, graph.Deployments),
			Models:      inGraph(changed.Models, graph.Models),
			Providers:   entry.Summaries.Providers,
			Routes:      inGraph(changed.Routes, graph.Routes),
		}}
	}
	return compiledCatalog{Graph: graph, Schedule: schedule, Retired: retired}, nil
}

// inAncestorGroups puts each model in every group that contains a group that it names, so that
// each of those groups selects it. Its groups are in order.
func inAncestorGroups(models map[string]compiledModel, groups map[string]groupSummary) error {
	for id, model := range models {
		in := make(map[string]bool, len(model.GroupIDs))
		for pending := slices.Clone(model.GroupIDs); len(pending) > 0; {
			groupID := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			group, ok := groups[groupID]
			if !ok {
				return fmt.Errorf("model %s is in unknown group %s", id, groupID)
			}
			if !in[groupID] {
				in[groupID] = true
				pending = append(pending, group.ParentIDs...)
			}
		}
		model.GroupIDs = slices.AppendSeq(make([]string, 0, len(in)), maps.Keys(in))
		slices.Sort(model.GroupIDs)
		models[id] = model
	}
	return nil
}

// merged adds a part's changes of one kind to a dated state's.
func merged[T any](state, part map[string]T) map[string]T {
	if state == nil {
		return part
	}
	maps.Copy(state, part)
	return state
}

// inGraph keeps the changes to the records that the graph holds.
func inGraph[T, U any](changes map[string]T, graph map[string]U) map[string]T {
	maps.DeleteFunc(changes, func(id string, _ T) bool {
		_, ok := graph[id]
		return !ok
	})
	return changes
}

func equalDates(left, right *string) bool {
	return (left == nil) == (right == nil) && (left == nil || *left == *right)
}

// servedRoot is a root as readers fetch it: the identity of its release, then the root's own
// members, which follow its opening brace.
func servedRoot(root []byte, identity Identity) []byte {
	header, _ := json.Marshal(identity)
	members := bytes.TrimLeft(root, " \t\r\n")[1:]
	return slices.Concat(header[:len(header)-1], []byte{','}, members)
}

// validateRetired checks that each selector that retired has the day it retired, and that no
// request can reach it in the graph: a deployment by its ID, and a model by its ID or an alias.
func validateRetired(retired map[string]string, base *snapshot) error {
	for selector, date := range retired {
		_, deployment := base.graph.Deployments[selector]
		_, model := base.modelSelectors[selector]
		if deployment || model || !validDate(date) {
			return fmt.Errorf("retired selector %s is invalid", selector)
		}
	}
	return nil
}

// snapshotFromCompiled validates a release's base state and each dated state, and indexes them
// for requests.
func snapshotFromCompiled(catalog compiledCatalog) (*snapshot, error) {
	base, err := stateFromGraph(catalog.Graph)
	if err != nil {
		return nil, err
	}
	if err := validateRetired(catalog.Retired, base); err != nil {
		return nil, err
	}
	for index, entry := range catalog.Schedule {
		if entry.Start.IsZero() || (index > 0 && !entry.Start.After(catalog.Schedule[index-1].Start)) {
			return nil, fmt.Errorf("catalog schedule entry %d does not start after the entry before it", index)
		}
		state, err := base.datedState(entry.Graph)
		if err != nil {
			return nil, fmt.Errorf("catalog state from %s: %w", entry.Start.Format(time.RFC3339), err)
		}
		base.schedule = append(base.schedule, datedState{start: entry.Start, state: state})
	}
	for _, state := range base.states() {
		state.retired = catalog.Retired
	}
	return base, nil
}

// states lists a base state and each dated state that follows it.
func (base *snapshot) states() []*snapshot {
	states := []*snapshot{base}
	for _, entry := range base.schedule {
		states = append(states, entry.state)
	}
	return states
}

// stateFromGraph validates the base catalog state and indexes it for requests.
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
	graph.Routes = indexedRoutes(graph)
	state := &snapshot{graph: graph, groups: groups, modelSelectors: modelSelectors}
	if err := validatePolicyVocabulary(state, graph); err != nil {
		return nil, err
	}
	return state, nil
}

// datedState returns the state that a schedule entry makes of the base state. The entry keeps
// every ID, alias and link, so the state shares the base's selectors, and the checks across
// nodes that the base passed still hold; only the nodes that the entry changes, and the
// deployments that read them, need checking again.
func (base *snapshot) datedState(entry compiledGraph) (*snapshot, error) {
	graph, err := scheduledGraph(base.graph, entry)
	if err != nil {
		return nil, err
	}
	if err := validateScheduledNodes(graph, entry); err != nil {
		return nil, err
	}
	if len(entry.Deployments) > 0 || len(entry.Routes) > 0 {
		graph.Routes = indexedRoutes(graph)
	}
	state := &snapshot{graph: graph, groups: base.groups, modelSelectors: base.modelSelectors}
	if err := validatePolicyVocabulary(state, entry); err != nil {
		return nil, err
	}
	return state, nil
}

// indexedRoutes returns a graph's routes, each with its ID and its deployments in serving order.
func indexedRoutes(graph compiledGraph) map[string]compiledRoute {
	routeDeployments := routeDeploymentsForGraph(graph)
	routes := make(map[string]compiledRoute, len(graph.Routes))
	for routeID, route := range graph.Routes {
		route.ID = routeID
		route.DeploymentIDs = routeDeployments[routeID]
		sortDeploymentIDs(route.DeploymentIDs, graph.Deployments)
		routes[routeID] = route
	}
	return routes
}

// scheduledGraph returns the base graph with an entry's nodes in place of the base nodes. An
// entry changes facts about nodes; it never adds one or changes an ID, alias or link.
func scheduledGraph(base, entry compiledGraph) (compiledGraph, error) {
	for id, author := range entry.Authors {
		if current, ok := base.Authors[id]; !ok || !slices.Equal(author.Aliases, current.Aliases) {
			return compiledGraph{}, fmt.Errorf("a dated state adds author %s or changes its aliases", id)
		}
	}
	for id, provider := range entry.Providers {
		if current, ok := base.Providers[id]; !ok || !slices.Equal(provider.Aliases, current.Aliases) {
			return compiledGraph{}, fmt.Errorf("a dated state adds provider %s or changes its aliases", id)
		}
	}
	for id, model := range entry.Models {
		current, ok := base.Models[id]
		if !ok || !slices.Equal(model.Aliases, current.Aliases) || model.AuthorID != current.AuthorID ||
			!slices.Equal(model.GroupIDs, current.GroupIDs) {
			return compiledGraph{}, fmt.Errorf("a dated state adds model %s or changes its aliases or links", id)
		}
	}
	for id, route := range entry.Routes {
		if current, ok := base.Routes[id]; !ok || route.ProviderID != current.ProviderID {
			return compiledGraph{}, fmt.Errorf("a dated state adds route %s or changes its provider", id)
		}
	}
	for id, deployment := range entry.Deployments {
		current, ok := base.Deployments[id]
		if !ok || deployment.ModelID != current.ModelID || !sameKeys(deployment.Routes, current.Routes) {
			return compiledGraph{}, fmt.Errorf("a dated state adds deployment %s or changes its links", id)
		}
	}
	return compiledGraph{
		Authors:     overlay(base.Authors, entry.Authors),
		Deployments: overlay(base.Deployments, entry.Deployments),
		Models:      overlay(base.Models, entry.Models),
		Providers:   overlay(base.Providers, entry.Providers),
		Routes:      overlay(base.Routes, entry.Routes),
	}, nil
}

// validateScheduledNodes checks a dated state's changed nodes and each deployment that reads a
// changed model or route.
func validateScheduledNodes(graph, entry compiledGraph) error {
	for providerID, provider := range entry.Providers {
		if err := validateCompiledProvider(providerID, provider); err != nil {
			return err
		}
	}
	for modelID, model := range entry.Models {
		if err := validateCompiledModel(modelID, model); err != nil {
			return err
		}
	}
	for routeID, route := range entry.Routes {
		if err := validateCompiledRoute(graph, routeID, route); err != nil {
			return err
		}
	}
	for deploymentID, deployment := range graph.Deployments {
		_, changed := entry.Deployments[deploymentID]
		_, modelChanged := entry.Models[deployment.ModelID]
		if !changed && !modelChanged && !hasAnyKey(deployment.Routes, entry.Routes) {
			continue
		}
		if err := validateCompiledDeployment(graph, make(selectorRegistry), deploymentID, deployment); err != nil {
			return err
		}
	}
	return nil
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
		if err := validateCompiledProvider(providerID, provider); err != nil {
			return err
		}
	}
	return nil
}

func validateCompiledProvider(providerID string, provider compiledProvider) error {
	if !uniqueNonEmpty(provider.CredentialModes) {
		return fmt.Errorf("provider %s has invalid credential modes", providerID)
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
		if err := validateCompiledModel(modelID, model); err != nil {
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

func validateCompiledModel(modelID string, model compiledModel) error {
	// Groups name their newest model, so every model needs a release date.
	if !validDate(model.ReleaseDate) {
		return fmt.Errorf("model %s has an invalid releaseDate", modelID)
	}
	return validateModelReasoning(modelID, model)
}

func validateCompiledRoutes(graph compiledGraph) error {
	for routeID, route := range graph.Routes {
		if err := validateCompiledRoute(graph, routeID, route); err != nil {
			return err
		}
	}
	return nil
}

func validateCompiledRoute(graph compiledGraph, routeID string, route compiledRoute) error {
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

func validateCompiledDeployment(graph compiledGraph, selectors selectorRegistry, deploymentID string, deployment *compiledDeployment) error {
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
func validateDeploymentRoutes(graph compiledGraph, deploymentID string, deployment *compiledDeployment) (string, error) {
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

func sortedRouteIDs(deployment *compiledDeployment) []string {
	return slices.Sorted(maps.Keys(deployment.Routes))
}

func validateDeploymentUpstreamSelector(deploymentID, providerID string, deployment *compiledDeployment) error {
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

func validateAzureUpstreamSelector(deploymentID string, deployment *compiledDeployment) error {
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

func validateDeploymentReasoningInheritance(deploymentID string, model compiledModel, deployment *compiledDeployment) error {
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

func validateReasoningConfiguration(deploymentID, providerID, modelAuthorID string, deployment *compiledDeployment, graph compiledGraph) error {
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

func hasAnyKey[A, B any](left map[string]A, right map[string]B) bool {
	for key := range left {
		if _, ok := right[key]; ok {
			return true
		}
	}
	return false
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

func sortDeploymentIDs(ids []string, deployments map[string]*compiledDeployment) {
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
