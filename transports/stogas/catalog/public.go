package catalog

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const PublicCatalogVersion = "stogas.gateway.catalog.v3"

type PublicCatalog struct {
	Schema        string                     `json:"schema"`
	Sequence      uint64                     `json:"sequence"`
	RuntimeDigest string                     `json:"runtimeDigest"`
	PublicDigest  string                     `json:"publicDigest"`
	Graph         map[string]json.RawMessage `json:"graph"`
}

type publicBundle struct {
	Schema string                     `json:"schema"`
	Graph  map[string]json.RawMessage `json:"graph"`
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
	if snap == nil || len(snap.publicRaw) == 0 {
		return PublicCatalog{}, false
	}
	bundle := publicBundle{}
	if err := json.Unmarshal(snap.publicRaw, &bundle); err != nil || bundle.Schema != publicSchema {
		return PublicCatalog{}, false
	}
	return PublicCatalog{
		Schema:        PublicCatalogVersion,
		Sequence:      snap.identity.Sequence,
		RuntimeDigest: snap.identity.Digest,
		PublicDigest:  snap.publicDigest,
		Graph:         bundle.Graph,
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
	identity, ok := ActiveIdentity()
	if !ok {
		return "", false
	}
	return strings.TrimPrefix(identity.Digest, "sha256:"), true
}

func ActiveIdentity() (Identity, bool) {
	snap := active.Load()
	if snap == nil || snap.identity.Digest == "" {
		return Identity{}, false
	}
	return snap.identity, true
}

func PublicModelsPayload() (PublicModelsResponse, bool) {
	snap := active.Load()
	if snap == nil {
		return PublicModelsResponse{}, false
	}
	ids := make([]string, 0, len(snap.aliases))
	for alias := range snap.aliases {
		if alias == "" {
			continue
		}
		ids = append(ids, alias)
	}
	sort.Strings(ids)
	models := make([]PublicModel, 0, len(ids))
	for _, id := range ids {
		deployment := snap.graph.Deployments[snap.aliases[id]]
		model := snap.graph.Models[deployment.ModelID]
		created := int64(1)
		if released, err := time.Parse("2006-01-02", model.ReleaseDate); err == nil {
			created = released.Unix()
		}
		models = append(models, PublicModel{
			ID:      id,
			Object:  "model",
			Created: created,
			OwnedBy: model.AuthorID,
		})
	}
	return PublicModelsResponse{Object: "list", Data: models}, true
}
