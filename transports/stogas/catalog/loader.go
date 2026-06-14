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
	"strings"
	"time"
)

func loadSnapshot(source Source) (*snapshot, error) {
	data, err := loadCompiledCatalog(source)
	if err != nil {
		return nil, err
	}
	catalog := compiledCatalog{}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	if len(catalog.Graph.Deployments) == 0 || len(catalog.Graph.Models) == 0 || len(catalog.Graph.ProviderEndpoints) == 0 || len(catalog.Graph.StogasEndpoints) == 0 {
		return nil, fmt.Errorf("compiled catalog is missing required graph nodes")
	}
	for id, route := range catalog.Graph.ProviderEndpoints {
		route.ParameterPolicies = route.Schema.Parameters
		catalog.Graph.ProviderEndpoints[id] = route
	}
	for id, deployment := range catalog.Graph.Deployments {
		deployment.ParameterPolicies = deployment.Schema.Parameters
		catalog.Graph.Deployments[id] = deployment
	}
	snap := &snapshot{
		graph:                  catalog.Graph,
		modelAliases:           make(map[string]string),
		responseMetadataFields: responseMetadataFields(catalog.Graph),
	}
	for id, model := range catalog.Graph.Models {
		snap.modelAliases[id] = id
		if model.CanonicalSlug != "" {
			snap.modelAliases[model.CanonicalSlug] = id
		}
		for _, alias := range model.AliasSlugs {
			snap.modelAliases[alias] = id
		}
	}
	return snap, nil
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
	return maybeGunzip(data)
}

func loadCatalogFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog file %s: %w", path, err)
	}
	return maybeGunzip(data)
}

func maybeGunzip(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
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
	return decoded, nil
}

func defaultCatalogPath() (string, error) {
	candidates := []string{
		filepath.Join("apps", "catalog", "compiled", "catalog.json.gz"),
		filepath.Join("apps", "catalog", "compiled", "catalog.json"),
		filepath.Join("..", "catalog", "compiled", "catalog.json.gz"),
		filepath.Join("..", "catalog", "compiled", "catalog.json"),
		filepath.Join("..", "..", "..", "catalog", "compiled", "catalog.json.gz"),
		filepath.Join("..", "..", "..", "catalog", "compiled", "catalog.json"),
		filepath.Join("..", "..", "..", "..", "catalog", "compiled", "catalog.json.gz"),
		filepath.Join("..", "..", "..", "..", "catalog", "compiled", "catalog.json"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("compiled catalog not found; set STOGAS_CATALOG_PATH or STOGAS_CATALOG_URL")
}
