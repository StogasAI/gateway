package catalog

import (
	"maps"
	"sort"
	"time"
)

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

// ActiveCatalog is the active release's root as readers fetch it: the release's digest and
// sequence, then the root's members. ActiveCatalogPart serves the parts that it names.
func ActiveCatalog() ([]byte, bool) {
	snap := active.Load()
	if snap == nil || len(snap.served) == 0 {
		return nil, false
	}
	return snap.served, true
}

func ActiveIdentity() (Identity, bool) {
	snap := active.Load()
	if snap == nil || snap.identity.Digest == "" {
		return Identity{}, false
	}
	return snap.identity, true
}

// PublicModelsPayload lists the selectors that reach an available deployment. Each entry shows
// the release date and author of the model it names; a group shows its newest model's, because
// policies, not the list, decide which of its models serves a request.
func PublicModelsPayload() (PublicModelsResponse, bool) {
	snap := activeState()
	if snap == nil {
		return PublicModelsResponse{}, false
	}
	modelIDsBySelector := make(map[string]string)
	available := make(map[string]bool)
	// groups maps each group to its newest model, the first by ID on a tie.
	groups := make(map[string]string)
	now := time.Now()
	for deploymentID, deployment := range snap.graph.Deployments {
		if !deploymentAvailableAt(deployment, now) {
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
			if !listed || snap.graph.Models[newest].ReleaseDate < released || snap.graph.Models[newest].ReleaseDate == released && deployment.ModelID < newest {
				groups[groupID] = deployment.ModelID
			}
		}
	}
	for selector, modelID := range snap.modelSelectors {
		if available[modelID] {
			modelIDsBySelector[selector] = modelID
		}
	}
	maps.Copy(modelIDsBySelector, groups)
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
