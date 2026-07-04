package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed generated/catalog.json
var embeddedCatalogJSON []byte

func loadSnapshot() (*snapshot, error) {
	return snapshotFromCatalogBytes(embeddedCatalogJSON)
}

func snapshotFromCatalogBytes(data []byte) (*snapshot, error) {
	catalog := compiledCatalog{}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	if len(catalog.Graph.Deployments) == 0 || len(catalog.Graph.Models) == 0 || len(catalog.Graph.ProviderEndpoints) == 0 || len(catalog.Graph.StogasEndpoints) == 0 {
		return nil, fmt.Errorf("compiled catalog is missing required graph nodes")
	}
	providerEndpointDeployments := make(map[string][]string)
	for deploymentID, deployment := range catalog.Graph.Deployments {
		for _, endpointID := range deployment.ParentProviderEndpointNodes {
			providerEndpointDeployments[endpointID] = append(providerEndpointDeployments[endpointID], deploymentID)
		}
	}
	for id, route := range catalog.Graph.ProviderEndpoints {
		route.ID = id
		route.DeploymentIDs = providerEndpointDeployments[id]
		sortDeploymentIDs(route.DeploymentIDs, catalog.Graph.Deployments)
		catalog.Graph.ProviderEndpoints[id] = route
	}
	snap := &snapshot{
		graph:                       catalog.Graph,
		providerEndpointRequestSlugs: catalog.Indexes.ProviderEndpointRequestSlugs,
		raw:                         append([]byte(nil), data...),
		responseMetadataFields:      responseMetadataFields(catalog.Graph),
	}
	if snap.providerEndpointRequestSlugs == nil {
		snap.providerEndpointRequestSlugs = map[string]string{}
	}
	return snap, nil
}

func sortDeploymentIDs(ids []string, deployments map[string]compiledDeployment) {
	sort.SliceStable(ids, func(i, j int) bool {
		left := deployments[ids[i]]
		right := deployments[ids[j]]
		if left.ModelID != right.ModelID {
			return ids[i] < ids[j]
		}
		if left.ServiceTier != right.ServiceTier {
			return serviceTierRank(left.ServiceTier) < serviceTierRank(right.ServiceTier)
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

func responseMetadataFields(graph compiledGraph) map[string]struct{} {
	fields := make(map[string]struct{})
	for _, field := range graph.Stogas.ResponseMetadataFields {
		normalized := strings.ToLower(strings.TrimSpace(field))
		if normalized != "" {
			fields[normalized] = struct{}{}
		}
	}
	return fields
}
