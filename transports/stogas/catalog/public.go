package catalog

import (
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
