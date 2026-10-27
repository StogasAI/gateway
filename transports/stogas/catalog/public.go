package catalog

import (
	"encoding/json"
	"maps"
	"sort"
	"time"
)

// PublicCatalog is the root of the public catalog with the identity of its release. The root
// names each part by SHA-256, and ActivePublicPart holds it.
type PublicCatalog struct {
	Schema        string                     `json:"schema"`
	Sequence      uint64                     `json:"sequence"`
	RuntimeDigest string                     `json:"runtimeDigest"`
	PublicDigest  string                     `json:"publicDigest"`
	Graph         map[string]json.RawMessage `json:"graph"`
	Parts         json.RawMessage            `json:"parts"`
	Schedule      json.RawMessage            `json:"schedule"`
	Periods       json.RawMessage            `json:"periods"`
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
	payload := PublicCatalog{}
	if err := json.Unmarshal(snap.publicRaw, &payload); err != nil || payload.Schema != publicSchema {
		return PublicCatalog{}, false
	}
	payload.Sequence, payload.RuntimeDigest, payload.PublicDigest = snap.identity.Sequence, snap.identity.Digest, snap.publicDigest
	return payload, true
}

// PublicDeployments is every deployment record of the active public catalog, as its parts hold
// them.
func PublicDeployments() (map[string]json.RawMessage, bool) {
	snap := active.Load()
	if snap == nil || len(snap.publicRaw) == 0 {
		return nil, false
	}
	deployments := make(map[string]json.RawMessage)
	for _, part := range snap.publicParts {
		var decoded struct {
			Deployments map[string]json.RawMessage `json:"deployments"`
		}
		if err := json.Unmarshal(part, &decoded); err != nil {
			return nil, false
		}
		maps.Copy(deployments, decoded.Deployments)
	}
	return deployments, true
}

func ActiveIdentity() (Identity, bool) {
	snap := active.Load()
	if snap == nil || snap.identity.Digest == "" {
		return Identity{}, false
	}
	return snap.identity, true
}

// PublicModelsPayload lists the selectors that reach an available deployment. Each entry shows
// the release date and author of the model it names. A group names its newest model, so a group
// whose newest models share a release date is left out.
func PublicModelsPayload() (PublicModelsResponse, bool) {
	snap := activeState()
	if snap == nil {
		return PublicModelsResponse{}, false
	}
	modelIDsBySelector := make(map[string]string)
	available := make(map[string]bool)
	type newestModel struct {
		id   string
		tied bool
	}
	groups := make(map[string]newestModel)
	for deploymentID, deployment := range snap.graph.Deployments {
		if !deploymentAvailableNow(deployment) {
			continue
		}
		modelIDsBySelector[deploymentID] = deployment.ModelID
		available[deployment.ModelID] = true
		if deployment.ApprovalRequired {
			continue
		}
		released := snap.graph.Models[deployment.ModelID].ReleaseDate
		for _, groupID := range snap.graph.Models[deployment.ModelID].GroupIDs {
			newest, listed := groups[groupID]
			if !listed || snap.graph.Models[newest.id].ReleaseDate < released {
				groups[groupID] = newestModel{id: deployment.ModelID}
			} else if newest.id != deployment.ModelID && snap.graph.Models[newest.id].ReleaseDate == released {
				groups[groupID] = newestModel{id: newest.id, tied: true}
			}
		}
	}
	for selector, modelID := range snap.modelSelectors {
		if available[modelID] {
			modelIDsBySelector[selector] = modelID
		}
	}
	for groupID, newest := range groups {
		if !newest.tied {
			modelIDsBySelector[groupID] = newest.id
		}
	}
	ids := make([]string, 0, len(modelIDsBySelector))
	for selector := range modelIDsBySelector {
		ids = append(ids, selector)
	}
	sort.Strings(ids)
	models := make([]PublicModel, 0, len(ids))
	for _, id := range ids {
		model := snap.graph.Models[modelIDsBySelector[id]]
		// The loader accepts only valid release dates.
		released, _ := time.Parse(time.DateOnly, model.ReleaseDate)
		models = append(models, PublicModel{
			ID:      id,
			Object:  "model",
			Created: released.Unix(),
			OwnedBy: model.AuthorID,
		})
	}
	return PublicModelsResponse{Object: "list", Data: models}, true
}
