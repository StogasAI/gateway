package catalog

import (
	"math/rand/v2"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func selectRoutingTargets(candidates []*ResolvedRequest, selection *policy.Selection) ([][]*ResolvedRequest, error) {
	byDeployment := make(map[string][]*ResolvedRequest, len(candidates))
	for _, candidate := range candidates {
		id := candidate.Deployment.ID
		byDeployment[id] = append(byDeployment[id], candidate)
	}
	groups := make([][]*ResolvedRequest, 0, len(byDeployment))
	if len(selection.Targets) != 0 {
		for _, id := range selection.Targets {
			if group := byDeployment[id]; len(group) > 0 {
				groups = append(groups, group)
			}
		}
	} else {
		for _, group := range byDeployment {
			groups = append(groups, group)
		}
	}
	if len(groups) == 0 {
		return nil, ErrModelUnavailable
	}
	if selection.Mode == "random" {
		// Shuffle deployments once, without replacement. Credential count never
		// changes a deployment's probability, and no cross-request state is kept.
		rand.Shuffle(len(groups), func(i, j int) { groups[i], groups[j] = groups[j], groups[i] })
	}
	return groups, nil
}
