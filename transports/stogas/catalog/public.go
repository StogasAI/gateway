package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

const PublicCatalogVersion = "stogas.gateway.catalog.v1"

type PublicCatalog struct {
	GeneratedAt string        `json:"generatedAt"`
	Graph       compiledGraph `json:"graph"`
	Indexes     PublicIndexes `json:"indexes"`
	Version     string        `json:"version"`
}

type PublicIndexes struct {
	ProviderEndpointRequestSlugs map[string]string `json:"provider_endpoint_request_slugs"`
}

type PublicModelsResponse struct {
	Object string        `json:"object"`
	Data   []PublicModel `json:"data"`
}

type PublicModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

func PublicCatalogPayload() (PublicCatalog, bool) {
	snap := active.Load()
	if snap == nil {
		return PublicCatalog{}, false
	}
	return PublicCatalog{
		GeneratedAt: time.Unix(1, 0).UTC().Format(time.RFC3339),
		Graph:       snap.graph,
		Indexes: PublicIndexes{
			ProviderEndpointRequestSlugs: snap.providerEndpointRequestSlugs,
		},
		Version: PublicCatalogVersion,
	}, true
}

func PublicCatalogJSON() ([]byte, bool) {
	payload, ok := PublicCatalogPayload()
	if !ok {
		return nil, false
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

func PublicCatalogHash() (string, bool) {
	encoded, ok := PublicCatalogJSON()
	if !ok {
		return "", false
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), true
}

func PublicModelsPayload() (PublicModelsResponse, bool) {
	snap := active.Load()
	if snap == nil {
		return PublicModelsResponse{}, false
	}
	ids := make([]string, 0, len(snap.providerEndpointRequestSlugs))
	seen := map[string]bool{}
	for _, id := range snap.providerEndpointRequestSlugs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	models := make([]PublicModel, 0, len(ids))
	for _, id := range ids {
		models = append(models, PublicModel{ID: id, Object: "model", Created: 1, OwnedBy: "stogas"})
	}
	return PublicModelsResponse{Object: "list", Data: models}, true
}
