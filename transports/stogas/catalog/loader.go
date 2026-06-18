package catalog

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func loadSnapshot(source Source) (*snapshot, error) {
	data, err := loadCompiledCatalog(source)
	if err != nil {
		return nil, err
	}
	return snapshotFromCatalogBytes(data)
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
		for _, endpointID := range deployment.ProviderEndpointIDs {
			providerEndpointDeployments[endpointID] = append(providerEndpointDeployments[endpointID], deploymentID)
		}
	}
	for id, route := range catalog.Graph.ProviderEndpoints {
		route.ID = id
		route.DeploymentIDs = providerEndpointDeployments[id]
		sortDeploymentIDs(route.DeploymentIDs, catalog.Graph.Deployments)
		route.ParameterPolicies = route.Schema.Parameters
		catalog.Graph.ProviderEndpoints[id] = route
	}
	for id, deployment := range catalog.Graph.Deployments {
		deployment.ParameterPolicies = deployment.Schema.Parameters
		if provider, ok := catalog.Graph.Providers[deployment.ProviderID]; ok {
			deployment.Pricing = mergedPricing(provider.Pricing, deployment.Pricing)
		}
		catalog.Graph.Deployments[id] = deployment
	}
	snap := &snapshot{
		graph:                    catalog.Graph,
		providerNativeModelSlugs: catalog.Indexes.ProviderNativeModelSlugs,
		responseMetadataFields:   responseMetadataFields(catalog.Graph),
	}
	if snap.providerNativeModelSlugs == nil {
		snap.providerNativeModelSlugs = map[string]string{}
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
	case "default", "standard", "":
		return 0
	case "flex":
		return 1
	case "priority":
		return 2
	default:
		return 9
	}
}

func mergedPricing(base Pricing, overrides Pricing) Pricing {
	if len(base) == 0 {
		return overrides
	}
	if len(overrides) == 0 {
		return base
	}
	merged := make(Pricing, len(base)+len(overrides))
	for key, meter := range base {
		merged[key] = meter
	}
	for key, meter := range overrides {
		merged[key] = meter
	}
	return merged
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

func loadCompiledCatalog(source Source) ([]byte, error) {
	if strings.TrimSpace(source.URL) != "" {
		return loadCatalogURL(source.URL)
	}
	path := strings.TrimSpace(source.Path)
	if path == "" {
		var err error
		path, err = defaultCatalogPath()
		if err != nil {
			return nil, err
		}
	}
	return loadCatalogFile(path)
}

func loadCatalogURL(rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create catalog request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch catalog: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch catalog: status %d", res.StatusCode)
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("read catalog response: %w", err)
	}
	return extractCatalogFromEvidence(data)
}

func loadCatalogFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog file %s: %w", path, err)
	}
	return extractCatalogFromLocalFile(data)
}

func extractCatalogFromEvidence(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return nil, fmt.Errorf("catalog source must be catalog-bundle.json.gz evidence")
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzipped catalog: %w", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("decompress catalog: %w", err)
	}
	return verifyCatalogEvidenceBundle(decoded)
}

func extractCatalogFromLocalFile(data []byte) ([]byte, error) {
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("open gzipped catalog: %w", err)
		}
		defer reader.Close()
		decoded, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("decompress catalog: %w", err)
		}
		if looksLikeCompiledCatalog(decoded) {
			return decoded, nil
		}
		return verifyCatalogEvidenceBundle(decoded)
	}
	if looksLikeCompiledCatalog(data) {
		return data, nil
	}
	return nil, fmt.Errorf("catalog file must be compiled catalog JSON or catalog-bundle.json.gz evidence")
}

func looksLikeCompiledCatalog(data []byte) bool {
	var catalog struct {
		Graph json.RawMessage `json:"graph"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return false
	}
	return len(catalog.Graph) > 0
}

func defaultCatalogPath() (string, error) {
	candidates := []string{
		filepath.Join("apps", "catalog", "compiled", "catalog.json.gz"),
		filepath.Join("apps", "catalog", "compiled", "catalog-bundle.json.gz"),
		filepath.Join("..", "catalog", "compiled", "catalog.json.gz"),
		filepath.Join("..", "catalog", "compiled", "catalog-bundle.json.gz"),
		filepath.Join("..", "..", "..", "catalog", "compiled", "catalog.json.gz"),
		filepath.Join("..", "..", "..", "catalog", "compiled", "catalog-bundle.json.gz"),
		filepath.Join("..", "..", "..", "..", "catalog", "compiled", "catalog.json.gz"),
		filepath.Join("..", "..", "..", "..", "catalog", "compiled", "catalog-bundle.json.gz"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("local compiled catalog or signed evidence bundle not found; set STOGAS_CATALOG_URL or STOGAS_CATALOG_BUNDLE_PATH")
}
