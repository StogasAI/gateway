package catalog

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// A request's model field names what serves the request and, if the client wants, where. It
// holds terms separated by spaces:
//
//   - an ID, which names a model by its ID or an alias, a group or a deployment;
//   - author/ID, OpenRouter's form, which also names the author of the model;
//   - kind:ID, where kind is author, provider, route, model, group or deployment.
//
// Each term narrows the deployments that the field selects, each kind appears once, and the field
// names at most one model, group or deployment. A field that names none selects among every
// model, like an omitted field. IDs ignore case, and a dot or an underscore matches a hyphen, so
// claude-opus-4.5 names claude-opus-4-5; the catalog keeps the IDs of each kind distinct under
// that rule.
type modelSelection struct {
	author, provider, route  string
	model, group, deployment string
}

// maxModelTerms bounds the field: six kinds, each once.
const maxModelTerms = 6

// maxModelFieldBytes bounds the text that errors repeat: six terms of a kind and a 128-character
// ID, the longest that policies accept, fit with room to spare.
const maxModelFieldBytes = 1024

// names says whether the selection names a model, group or deployment.
func (sel modelSelection) names() bool {
	return sel.model != "" || sel.group != "" || sel.deployment != ""
}

// approved says whether the selection reaches deployments that need the provider's approval:
// only one that names their model or the deployment itself does.
func (sel modelSelection) approved() bool {
	return sel.model != "" || sel.deployment != ""
}

// normalizedID is the form in which the model field matches a catalog ID.
func normalizedID(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '.' || r == '_':
			return '-'
		case 'A' <= r && r <= 'Z':
			return r + ('a' - 'A')
		}
		return r
	}, id)
}

type catalogSelector struct {
	kind, id string
}

// selectorIndex finds catalog IDs by their normalized form. Dated states share their base's
// index, since they keep every ID and alias.
type selectorIndex struct {
	// names holds the models, by ID and alias, the groups and the deployments.
	names     map[string]catalogSelector
	authors   map[string]string
	providers map[string]string
	routes    map[string]string
	// retired holds the day that each selector that had retired when the release loaded
	// retired; a route's is under routeSelector.
	retired map[string]string
	// unsupported holds why Stogas does not serve each selector that names only what it does
	// not serve, keyed as retired is.
	unsupported map[string]string
	// paths holds every deployment through each of its routes, current or retired.
	paths []servedPath
}

func newSelectorIndex(graph compiledGraph) *selectorIndex {
	index := &selectorIndex{
		names:     make(map[string]catalogSelector),
		authors:   make(map[string]string),
		providers: make(map[string]string),
		routes:    make(map[string]string),
	}
	for authorID, author := range graph.Authors {
		index.authors[normalizedID(authorID)] = authorID
		for _, alias := range author.Aliases {
			index.authors[normalizedID(alias)] = authorID
		}
	}
	for providerID, provider := range graph.Providers {
		index.providers[normalizedID(providerID)] = providerID
		for _, alias := range provider.Aliases {
			index.providers[normalizedID(alias)] = providerID
		}
	}
	for routeID := range graph.Routes {
		index.routes[normalizedID(routeID)] = routeID
	}
	for modelID, model := range graph.Models {
		index.names[normalizedID(modelID)] = catalogSelector{kind: "model", id: modelID}
		for _, alias := range model.Aliases {
			index.names[normalizedID(alias)] = catalogSelector{kind: "model", id: modelID}
		}
		for _, groupID := range model.GroupIDs {
			index.names[normalizedID(groupID)] = catalogSelector{kind: "group", id: groupID}
		}
	}
	for deploymentID := range graph.Deployments {
		index.names[normalizedID(deploymentID)] = catalogSelector{kind: "deployment", id: deploymentID}
	}
	return index
}

func normalizedRetired(retired map[string]string) map[string]string {
	normalized := make(map[string]string, len(retired))
	for selector, date := range retired {
		normalized[normalizedID(selector)] = date
	}
	return normalized
}

func invalidModel(format string, args ...any) APIError {
	return APIError{StatusCode: http.StatusBadRequest, Code: "invalid_request", Type: ErrorTypeInvalidRequest, Message: fmt.Sprintf(format, args...), Param: "model"}
}

// unknownModel is the error for an ID that names nothing in the catalog.
func unknownModel(kind, id string) APIError {
	return APIError{
		StatusCode: http.StatusBadRequest, Code: ErrModelUnavailable.Code, Type: ErrorTypeInvalidRequest, Param: "model",
		Message: fmt.Sprintf("The catalog has no %s %s. GET /v1/models lists the IDs.", kind, id),
	}
}

// parseModelSelection reads a request's model field.
func (s *snapshot) parseModelSelection(field string) (modelSelection, error) {
	var sel modelSelection
	if len(field) > maxModelFieldBytes {
		return sel, invalidModel("The model field takes at most %d bytes.", maxModelFieldBytes)
	}
	terms := strings.Fields(field)
	if len(terms) > maxModelTerms {
		return sel, invalidModel("The model field takes at most %d terms.", maxModelTerms)
	}
	// A term that names only what Stogas does not serve fails once every term has parsed, so
	// that a term that retired, or that the field cannot take, goes first whatever the order.
	unserved := ""
	for _, term := range terms {
		kind, value, typed := strings.Cut(term, ":")
		if !typed {
			kind, value = "", term
			if author, rest, slashed := strings.Cut(term, "/"); slashed {
				if author == "" || rest == "" || strings.Contains(rest, "/") {
					return sel, invalidModel("Write %q as author/model, such as openai/gpt-5.5, or use terms such as provider:azure gpt-5.5.", term)
				}
				if err := s.selectTerm(&sel, "author", author, term); err != nil {
					return sel, err
				}
				value = rest
			}
		} else if value == "" || strings.Contains(value, ":") {
			return sel, invalidModel("Write %q as kind:ID, such as provider:azure.", term)
		}
		if err := s.selectTerm(&sel, kind, value, term); err != nil {
			if reason, ok := err.(unservedTerm); ok {
				unserved = cmp.Or(unserved, string(reason))
				continue
			}
			return sel, err
		}
	}
	if unserved != "" {
		return sel, modelUnsupported(unserved)
	}
	if sel.author != "" {
		modelID := sel.model
		if deployment, ok := s.graph.Deployments[sel.deployment]; ok {
			modelID = deployment.ModelID
		}
		if model, ok := s.graph.Models[modelID]; ok && model.AuthorID != sel.author {
			return sel, invalidModel("%s is a model by %s, not by %s.", modelID, model.AuthorID, sel.author)
		}
	}
	return sel, nil
}

// unservedTerm is the reason why Stogas does not serve what a term names.
type unservedTerm string

func (reason unservedTerm) Error() string { return string(reason) }

// selectTerm adds one term to a selection. An empty kind names a model, group or deployment.
func (s *snapshot) selectTerm(sel *modelSelection, kind, value, term string) error {
	index := s.index
	normalized := normalizedID(value)
	var id string
	var slot *string
	switch kind {
	case "author":
		id, slot = index.authors[normalized], &sel.author
	case "provider":
		id, slot = index.providers[normalized], &sel.provider
	case "route":
		id, slot = index.routes[normalized], &sel.route
		if date, retired := index.retired[normalizedID(routeSelector(value))]; id == "" && retired {
			return modelRetired(date)
		}
		if reason, unserved := index.unsupported[normalizedID(routeSelector(value))]; id == "" && unserved {
			return unservedTerm(reason)
		}
	case "", "model", "group", "deployment":
		target, ok := index.names[normalized]
		if ok && kind != "" && target.kind != kind {
			return invalidModel("%s is a %s. Write %s:%s, or the ID alone.", value, target.kind, target.kind, value)
		}
		if !ok {
			if date, retired := index.retired[normalized]; retired {
				return modelRetired(date)
			}
			if reason, unserved := index.unsupported[normalized]; unserved {
				return unservedTerm(reason)
			}
			if kind == "" {
				if _, author := index.authors[normalized]; author {
					return invalidModel("%s is an author. Write author:%s to select among its models.", value, value)
				}
				if _, provider := index.providers[normalized]; provider {
					return invalidModel("%s is a provider. Write provider:%s to select among its deployments.", value, value)
				}
				return unknownModel("model, group or deployment", value)
			}
			return unknownModel(kind, value)
		}
		kind, id = target.kind, target.id
		if sel.names() {
			return invalidModel("The model field names more than one model, group or deployment.")
		}
		slot = map[string]*string{"model": &sel.model, "group": &sel.group, "deployment": &sel.deployment}[kind]
	default:
		return invalidModel("Unknown term %q. Terms are IDs, author/model, or author:, provider:, route:, model:, group: or deployment: followed by an ID.", term)
	}
	if id == "" {
		if author, _, slashed := strings.Cut(term, "/"); slashed && kind == "author" && author == value {
			if _, provider := index.providers[normalized]; provider {
				return invalidModel("%s is not an author. To choose a provider, write provider:%s %s.", value, value, strings.TrimPrefix(term, author+"/"))
			}
		}
		return unknownModel(kind, value)
	}
	if *slot != "" {
		return invalidModel("The model field names more than one %s.", kind)
	}
	*slot = id
	return nil
}

// selects says whether a deployment on a route is one that the selection names.
func (s *snapshot) selects(sel modelSelection, routeNode compiledRoute, deploymentID string, deployment *compiledDeployment) bool {
	if sel.deployment != "" && deploymentID != sel.deployment ||
		sel.model != "" && deployment.ModelID != sel.model ||
		sel.route != "" && routeNode.ID != sel.route ||
		sel.provider != "" && routeNode.ProviderID != sel.provider {
		return false
	}
	if sel.group == "" && sel.author == "" {
		return true
	}
	model := s.graph.Models[deployment.ModelID]
	return (sel.group == "" || slices.Contains(model.GroupIDs, sel.group)) &&
		(sel.author == "" || model.AuthorID == sel.author)
}

// unservedSelection is the error for a selection that names only paths that do not serve now:
// every path that it selects, of any deployment through any route, has retired by now or is one
// that Stogas does not serve. A path that retired names the last day on which one did, whether it
// retired before the release loaded or after; otherwise the error gives Stogas's reason for the
// first path by deployment and route. A selection of a model, group, deployment, route, provider
// or author, or of several, gets the same error. It is nil while a path serves.
func (s *snapshot) unservedSelection(sel modelSelection, now time.Time) error {
	if sel == (modelSelection{}) {
		return nil
	}
	last, reason, first := "", "", ""
	for _, path := range s.index.paths {
		if sel.deployment != "" && path.deployment != sel.deployment ||
			sel.model != "" && path.model != sel.model ||
			sel.route != "" && path.route != sel.route ||
			sel.provider != "" && path.provider != sel.provider ||
			sel.author != "" && path.author != sel.author ||
			sel.group != "" && !slices.Contains(path.groups, sel.group) {
			continue
		}
		switch key := path.deployment + "\x00" + path.route; {
		case retiredAt(path.retirementDate, now):
			last = max(last, *path.retirementDate)
		case path.unsupported != "":
			if reason == "" || key < first {
				reason, first = path.unsupported, key
			}
		default:
			return nil
		}
	}
	if last != "" {
		return modelRetired(last)
	}
	if reason != "" {
		return modelUnsupported(reason)
	}
	return nil
}

// routingSelections returns the deployments that a selection reaches on an interface at a
// variant. A named deployment keeps its own tier and reasoning mode unless the request sets one;
// other selections use the Standard tier, or the request's. Deployments that need approval join
// only when the selection names their model or the deployment. A deployment joins through the
// translation only when no route that the selection allows takes the interface itself for it.
//
// A trace names providers without a credential or the interface, deployments that need approval,
// and, for a selection that names a model, group or deployment, providers that serve it only at
// another tier or reasoning mode. A selection without a name leaves out providers without the
// interface, since every provider would show.
func (s *snapshot) routingSelections(route Route, sel modelSelection, want variant, availableCredentials map[string][]int, trace *routingTrace, now time.Time) []routingSelection {
	pinned := sel.deployment != ""
	tier, mode := cmp.Or(want.tier, TierStandard), want.upstreamMode()
	selections := make([]routingSelection, 0)
	skipped := providerSkips{trace: trace}
	// otherVariant holds the providers that serve the selection only at another variant, and
	// whether they serve it in the requested mode.
	otherVariant := map[schemas.ModelProvider]bool{}
	for _, routeNode := range s.graph.Routes {
		if sel.route != "" && routeNode.ID != sel.route || sel.provider != "" && routeNode.ProviderID != sel.provider {
			continue
		}
		provider := schemas.ModelProvider(routeNode.ProviderID)
		bridging := routeBridges(routeNode, route)
		supported := bridging || routeSupportsInterface(routeNode, route)
		credentialed := availableCredentials == nil || len(availableCredentials[routeNode.ProviderID]) > 0
		if trace == nil && (!supported || !credentialed) || trace != nil && !supported && !sel.names() {
			continue
		}
		for _, id := range routeNode.DeploymentIDs {
			compiled := s.graph.Deployments[id]
			if !servesAt(compiled, routeNode, now) || !s.selects(sel, routeNode, id, compiled) ||
				bridging && s.takesItself(sel, route, id, compiled, now) {
				continue
			}
			inMode := compiled.Upstream.ReasoningMode == mode
			atTier := compiled.Upstream.ServiceTier == tier
			if pinned {
				inMode, atTier = want.mode == "" || inMode, want.tier == "" || compiled.Upstream.ServiceTier == want.tier
			}
			if !inMode || !atTier {
				if supported && credentialed {
					otherVariant[provider] = otherVariant[provider] || inMode
				}
				continue
			}
			if !supported || !credentialed {
				skipped.add(provider, supported)
				break
			}
			if compiled.ApprovalRequired && !sel.approved() {
				if trace != nil {
					if deployment, ok := s.deploymentFromCompiledAt(id, routeNode, now); ok {
						trace.removeSelection(routingSelection{deployment: deployment, provider: provider}, RemovedApproval, nil)
					}
				}
				continue
			}
			if deployment, ok := s.deploymentFromCompiledAt(id, routeNode, now); ok {
				selections = append(selections, routingSelection{deployment: deployment, provider: provider})
			}
		}
	}
	served := map[schemas.ModelProvider]bool{}
	for _, selection := range selections {
		served[selection.provider] = true
		skipped.served(selection.provider)
	}
	skipped.record()
	if trace != nil && sel.names() {
		for _, provider := range slices.Sorted(maps.Keys(otherVariant)) {
			if served[provider] {
				continue
			}
			if otherVariant[provider] {
				trace.removeProvider(provider, RemovedServiceTier)
			} else if want.mode != "" {
				trace.removeProvider(provider, RemovedReasoningMode)
			}
		}
	}
	// Stable ties must not depend on Go map iteration or catalog serialization.
	slices.SortFunc(selections, func(a, b routingSelection) int {
		return cmp.Or(cmp.Compare(a.deployment.ID, b.deployment.ID), cmp.Compare(a.deployment.RouteID, b.deployment.RouteID))
	})
	return selections
}
