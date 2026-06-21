package catalog

import (
	"fmt"

	"github.com/maximhq/bifrost/transports/stogas/providers"
	openaiadapter "github.com/maximhq/bifrost/transports/stogas/providers/openai"
)

type PolicyProfileDescription = providers.ProfileDescription

var policyProfiles = indexPolicyProfiles(openaiadapter.Profiles())

func indexPolicyProfiles(profiles []providers.Profile) map[string]providers.Profile {
	out := make(map[string]providers.Profile, len(profiles))
	for _, profile := range profiles {
		if profile.Description.ID != "" {
			out[profile.Description.ID] = profile
		}
	}
	return out
}

func profileDescriptions() []PolicyProfileDescription {
	descriptions := make([]PolicyProfileDescription, 0, len(policyProfiles))
	for _, profile := range policyProfiles {
		descriptions = append(descriptions, profile.Description)
	}
	return descriptions
}

func combinedProfileIDs(groups ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, ids := range groups {
		for _, id := range ids {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return stableStrings(out)
}

func validatePolicyProfiles(profileIDs []string) error {
	for _, id := range profileIDs {
		if _, ok := policyProfiles[id]; !ok {
			return fmt.Errorf("unknown policy profile %q", id)
		}
	}
	return nil
}
