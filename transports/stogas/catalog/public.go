package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

type PublicCatalog struct {
	GeneratedAt    string                     `json:"generatedAt"`
	Graph          compiledGraph              `json:"graph"`
	Hash           string                     `json:"hash"`
	Indexes        PublicIndexes              `json:"indexes"`
	PolicyProfiles []PolicyProfileDescription `json:"policyProfiles"`
	Schema         string                     `json:"schema"`
}

type PublicIndexes struct {
	ProviderNativeModelSlugs map[string]string `json:"provider_native_model_slugs"`
}

type OpenAIModelsResponse struct {
	Object string        `json:"object"`
	Data   []OpenAIModel `json:"data"`
}

type OpenAIModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

func CatalogHash() string {
	snap := active.Load()
	if snap == nil {
		return ""
	}
	sum := sha256.Sum256(snap.raw)
	return hex.EncodeToString(sum[:])
}

func PublicCatalogPayload() (PublicCatalog, bool) {
	snap := active.Load()
	if snap == nil {
		return PublicCatalog{}, false
	}
	return PublicCatalog{
		GeneratedAt: time.Unix(1, 0).UTC().Format(time.RFC3339),
		Graph:       snap.graph,
		Hash:        CatalogHash(),
		Indexes: PublicIndexes{
			ProviderNativeModelSlugs: snap.providerNativeModelSlugs,
		},
		PolicyProfiles: sortedProfileDescriptions(),
		Schema:         "stogas.gateway.catalog.v1",
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

func PublicModelsPayload() (OpenAIModelsResponse, bool) {
	snap := active.Load()
	if snap == nil {
		return OpenAIModelsResponse{}, false
	}
	ids := make([]string, 0, len(snap.providerNativeModelSlugs))
	seen := map[string]bool{}
	for _, id := range snap.providerNativeModelSlugs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	models := make([]OpenAIModel, 0, len(ids))
	for _, id := range ids {
		models = append(models, OpenAIModel{ID: id, Object: "model", Created: 1, OwnedBy: "stogas"})
	}
	return OpenAIModelsResponse{Object: "list", Data: models}, true
}

func sortedProfileDescriptions() []PolicyProfileDescription {
	descriptions := profileDescriptions()
	sort.Slice(descriptions, func(i, j int) bool {
		return descriptions[i].ID < descriptions[j].ID
	})
	return descriptions
}
