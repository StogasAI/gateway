package catalog

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	runtimeSchema    = "stogas.catalog.runtime.v3"
	publicSchema     = "stogas.catalog.public.v3"
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
	"openai-chat-completions": {
		providerID: "openai",
		interfaces: []string{"chat_completions"},
	},
	"openai-responses": {
		providerID: "openai",
		interfaces: []string{"responses"},
	},
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
			!sameKeys(publicHeader.Graph.Models, catalog.Graph.Models) ||
			!sameKeys(publicHeader.Graph.Providers, catalog.Graph.Providers) ||
			!sameKeys(publicHeader.Graph.Routes, catalog.Graph.Routes) ||
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
	aliases := make(map[string]string)
	for deploymentID, deployment := range catalog.Graph.Deployments {
		for _, alias := range deployment.Aliases {
			aliases[alias] = deploymentID
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
		aliases:          aliases,
		graph:            catalog.Graph,
		identity:         identity,
		publicDigest:     publicDigest,
		publicRaw:        append([]byte(nil), publicData...),
		raw:              append([]byte(nil), runtimeData...),
		routeDeployments: routeDeployments,
	}, nil
}

func validateCompiledCatalog(catalog compiledCatalog) error {
	graph := catalog.Graph
	if len(graph.Authors) == 0 ||
		len(graph.Models) == 0 ||
		len(graph.Providers) == 0 ||
		len(graph.Routes) == 0 ||
		len(graph.Deployments) == 0 {
		return fmt.Errorf("compiled catalog is missing required graph nodes or aliases")
	}
	for modelID, model := range graph.Models {
		if _, ok := graph.Authors[model.AuthorID]; !ok {
			return fmt.Errorf("model %s references unknown author %s", modelID, model.AuthorID)
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
		if _, ok := graph.Models[deployment.ModelID]; !ok {
			return fmt.Errorf("deployment %s references unknown model %s", deploymentID, deployment.ModelID)
		}
		if deployment.Upstream.Model == "" ||
			deployment.Limits.ContextTokens <= 0 ||
			deployment.Limits.OutputTokens <= 0 ||
			deployment.Status != "active" ||
			len(deployment.Aliases) == 0 {
			return fmt.Errorf("deployment %s is not executable", deploymentID)
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
		selector := deployment.Upstream.FixedRequest
		switch providerID {
		case "openai":
			if selector.InferenceGeo != "" || selector.Speed != "" ||
				(selector.ServiceTier != "default" &&
					selector.ServiceTier != "flex" &&
					selector.ServiceTier != "priority") {
				return fmt.Errorf("deployment %s has an invalid OpenAI upstream selector", deploymentID)
			}
		case "anthropic":
			if selector.ServiceTier != "standard_only" ||
				(selector.Speed != "standard" && selector.Speed != "fast") ||
				(selector.InferenceGeo != "global" && selector.InferenceGeo != "us") {
				return fmt.Errorf("deployment %s has an invalid Anthropic upstream selector", deploymentID)
			}
		default:
			return fmt.Errorf("deployment %s uses unsupported provider %s", deploymentID, providerID)
		}
		for _, alias := range deployment.Aliases {
			if strings.TrimSpace(alias) != alias || strings.Contains(alias, "/") {
				return fmt.Errorf("alias %q is not canonical", alias)
			}
			for otherDeploymentID, otherDeployment := range graph.Deployments {
				if otherDeploymentID == deploymentID {
					continue
				}
				for _, otherAlias := range otherDeployment.Aliases {
					if alias == otherAlias {
						return fmt.Errorf(
							"alias %s is shared by deployments %s and %s",
							alias,
							deploymentID,
							otherDeploymentID,
						)
					}
				}
			}
		}
	}
	return nil
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
		if left.Upstream.FixedRequest.ServiceTier != right.Upstream.FixedRequest.ServiceTier {
			return serviceTierRank(left.Upstream.FixedRequest.ServiceTier) < serviceTierRank(right.Upstream.FixedRequest.ServiceTier)
		}
		if left.Upstream.FixedRequest.Speed != right.Upstream.FixedRequest.Speed {
			return left.Upstream.FixedRequest.Speed < right.Upstream.FixedRequest.Speed
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
