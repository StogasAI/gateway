package catalog

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// A request's model field names what serves the request and, if the client wants, where. It
// holds terms separated by spaces:
//
//   - an ID, which names a model by its ID or an alias, or a deployment, as the model field of an
//     OpenAI or Anthropic client does;
//   - author/ID, OpenRouter's form, which also names the author of the model;
//   - kind:ID, where kind is author, provider, route, model, group or deployment.
//
// Groups have a namespace of their own, so a group needs group:, and an alias may share a group's
// ID: gpt-5.6 names GPT-5.6 Sol, as at OpenAI, and group:gpt-5.6 every GPT-5.6 model. Each term
// narrows the deployments that the field selects, each kind appears once, and the field names at
// most one model, group or deployment. A field that names none selects among every model, like an
// omitted field. Kinds and IDs ignore case, and a dot or an underscore in an ID matches a hyphen,
// so claude-opus-4.5 names claude-opus-4-5; the catalog keeps the IDs of each namespace distinct
// under that rule.
type modelSelection struct {
	author, provider, route  string
	model, group, deployment string
}

// String writes the selection as request.model reads it: kind:ID terms in the order of
// policy.SelectionKinds with the catalog's IDs, so that policies read what a request names,
// however the client spelled it.
func (sel modelSelection) String() string {
	ids := [len(policy.SelectionKinds)]string{sel.author, sel.provider, sel.route, sel.model, sel.group, sel.deployment}
	terms := make([]string, 0, len(ids))
	for index, id := range ids {
		if id != "" {
			terms = append(terms, policy.SelectionKinds[index]+":"+id)
		}
	}
	return strings.Join(terms, " ")
}

// maxModelTerms bounds the field: each kind once.
const maxModelTerms = len(policy.SelectionKinds)

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
	// names holds the models, by ID and alias, and the deployments.
	names     map[string]catalogSelector
	groups    map[string]string
	authors   map[string]string
	providers map[string]string
	routes    map[string]string
	// retired holds the day that each selector that had retired when the release loaded
	// retired; a group's is under groupSelector and a route's under routeSelector.
	retired map[string]string
	// unsupported holds each selector that names only what Stogas does not serve, keyed as
	// retired is.
	unsupported map[string]bool
	// paths holds every deployment through each of its routes, current or retired.
	paths []servedPath
}

func newSelectorIndex(graph compiledGraph) *selectorIndex {
	index := &selectorIndex{
		names:     make(map[string]catalogSelector),
		groups:    make(map[string]string),
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
			index.groups[normalizedID(groupID)] = groupID
		}
	}
	for deploymentID := range graph.Deployments {
		index.names[normalizedID(deploymentID)] = catalogSelector{kind: "deployment", id: deploymentID}
	}
	return index
}

func normalizedRetired[Value any](retired map[string]Value) map[string]Value {
	normalized := make(map[string]Value, len(retired))
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
	unserved := false
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
		} else if kind == "" || value == "" || strings.ContainsAny(value, ":/") {
			return sel, invalidModel("Write %q as kind:ID, such as provider:azure, or author/model alone.", term)
		}
		kind = strings.ToLower(kind)
		if err := s.selectTerm(&sel, kind, value, term); err != nil {
			if err == errUnservedTerm {
				unserved = true
				continue
			}
			return sel, err
		}
	}
	if unserved {
		return sel, modelUnsupported()
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

// errUnservedTerm says that a term names only what Stogas does not serve.
var errUnservedTerm = errors.New("Stogas does not serve what the term names")

// selectTerm adds one term to a selection. An empty kind names a model or a deployment.
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
		if id == "" {
			if err := index.gone(routeSelector(normalized)); err != nil {
				return err
			}
		}
	case "group":
		id, slot = index.groups[normalized], &sel.group
		if id == "" {
			if err := index.gone(groupSelector(normalized)); err != nil {
				return err
			}
			if target, ok := index.names[normalized]; ok {
				return invalidModel("%s is a %s. Write %s alone.", value, target.kind, value)
			}
		}
	case "", "model", "deployment":
		target, ok := index.names[normalized]
		if ok && kind != "" && target.kind != kind {
			return invalidModel("%s is a %s. Write %s alone.", value, target.kind, value)
		}
		if !ok {
			if err := index.gone(normalized); err != nil {
				return err
			}
			if _, group := index.groups[normalized]; group {
				return invalidModel("%s is a group. Write group:%s to select among its models.", value, value)
			}
			if kind != "" {
				return unknownModel(kind, value)
			}
			if err := index.gone(groupSelector(normalized)); err != nil {
				return err
			}
			if _, author := index.authors[normalized]; author {
				return invalidModel("%s is an author. Write author:%s to select among its models.", value, value)
			}
			if _, provider := index.providers[normalized]; provider {
				return invalidModel("%s is a provider. Write provider:%s to select among its deployments.", value, value)
			}
			return unknownModel("model or deployment", value)
		}
		kind, id = target.kind, target.id
		slot = map[string]*string{"model": &sel.model, "deployment": &sel.deployment}[kind]
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
	if (kind == "model" || kind == "group" || kind == "deployment") && sel.names() {
		return invalidModel("The model field names more than one model, group or deployment.")
	}
	if *slot != "" {
		return invalidModel("The model field names more than one %s.", kind)
	}
	*slot = id
	return nil
}

// gone returns the error for a selector, keyed as retired is, that names only what has retired or
// what Stogas does not serve, and nil for any other.
func (index *selectorIndex) gone(key string) error {
	if date, retired := index.retired[key]; retired {
		return modelRetired(date)
	}
	if index.unsupported[key] {
		return errUnservedTerm
	}
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
// retired before the release loaded or after; otherwise the error says that Stogas does not serve
// the model. A selection of a model, group, deployment, route, provider
// or author, or of several, gets the same error. It is nil while a path serves.
func (s *snapshot) unservedSelection(sel modelSelection, now time.Time) error {
	if sel == (modelSelection{}) {
		return nil
	}
	last, unserved := "", false
	for _, path := range s.index.paths {
		if sel.deployment != "" && path.deployment != sel.deployment ||
			sel.model != "" && path.model != sel.model ||
			sel.route != "" && path.route != sel.route ||
			sel.provider != "" && path.provider != sel.provider ||
			sel.author != "" && path.author != sel.author ||
			sel.group != "" && !slices.Contains(path.groups, sel.group) {
			continue
		}
		switch {
		case retiredAt(path.retirementDate, now):
			last = max(last, *path.retirementDate)
		case path.unsupported:
			unserved = true
		default:
			return nil
		}
	}
	if last != "" {
		return modelRetired(last)
	}
	if unserved {
		return modelUnsupported()
	}
	return nil
}

// routingSelections returns the deployments that a selection reaches on an interface at a
// variant. A named deployment keeps its own tier and reasoning mode unless the request sets one;
// other selections use the Standard tier, or the request's. Deployments that need approval join
// only when the selection names their model or the deployment. A deployment joins on one route
// (servedElsewhere). throughResponses, which may be nil, reports a Chat Completions request that
// deployments with both interfaces serve through Responses (chatThroughResponses).
//
// A trace names providers without a credential or the interface, deployments that need approval,
// and, for a selection that names a model, group or deployment, providers that serve it only at
// another tier or reasoning mode. A selection without a name leaves out providers without the
// interface, since every provider would show.
func (s *snapshot) routingSelections(route Route, sel modelSelection, want variant, throughResponses func() bool, availableCredentials map[string][]int, trace *routingTrace, now time.Time) []routingSelection {
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
				s.servedElsewhere(sel, route, bridging, id, compiled, throughResponses, now) {
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
