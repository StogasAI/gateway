package catalog

import (
	"fmt"
	"slices"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// AccountOption is one thing about a customer's account with a provider that changes how the
// provider handles requests: an agreement, a setting, or a place for stored content. The catalog
// states the facts of an account that changed nothing, and an option states what it changes. It
// never changes the upstream, a price, a limit or a TEE fact, which are a deployment's.
type AccountOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Group names a setting with several values: a credential holds one option of a group at most.
	Group *string `json:"group"`
	// Routes are the provider's routes whose requests the option covers.
	Routes       []string                  `json:"routes"`
	DataHandling AccountOptionDataHandling `json:"dataHandling"`
	// Grants are the certifications that hold once the account has taken the option up, each for
	// a deployment that lists the entry with the suffix -eligible.
	Grants []string `json:"grants"`
}

// AccountOptionDataHandling holds the facts that an option sets, each as a whole value. An unset
// field leaves the deployment's value.
type AccountOptionDataHandling struct {
	StorageLocation   string `json:"storageLocation,omitzero"`
	RetentionDays     *int   `json:"retentionDays,omitzero"`
	TrainingUse       *bool  `json:"trainingUse,omitzero"`
	ZeroDataRetention *bool  `json:"zeroDataRetention,omitzero"`
}

// HeldOption is an account option that a credential holds.
type HeldOption = billing.HeldOption

const eligibleSuffix = "-eligible"

// AppliedOptions returns, in the provider's order, the options among held that reach the
// deployment.
func (d Deployment) AppliedOptions(held []HeldOption) []HeldOption {
	var applied []HeldOption
	for _, option := range d.AccountOptions {
		if i := slices.IndexFunc(held, func(h HeldOption) bool { return h.ID == option.ID }); i >= 0 {
			applied = append(applied, held[i])
		}
	}
	return applied
}

// optionsKey names a set of applied options, so that pairs with equal options share a candidate.
func optionsKey(applied []HeldOption) string {
	var key strings.Builder
	for _, option := range applied {
		key.WriteString(option.ID)
		if option.Declared {
			key.WriteByte('!')
		}
		key.WriteByte(' ')
	}
	return key.String()
}

// set writes the facts that the option sets over the deployment's.
func (o AccountOption) set(handling *DataHandling) {
	effect := o.DataHandling
	if effect.StorageLocation != "" {
		handling.StorageLocation = effect.StorageLocation
	}
	if effect.RetentionDays != nil {
		days := *effect.RetentionDays
		handling.RetentionDays = &days
	}
	if effect.TrainingUse != nil {
		training := *effect.TrainingUse
		handling.TrainingUse = &training
	}
	if effect.ZeroDataRetention != nil {
		handling.ZeroDataRetention = *effect.ZeroDataRetention
	}
}

// grant adds each granted certification whose -eligible entry the facts still list, so a hosted
// tool that an agreement leaves out, which removes that entry, also keeps the grant away.
func grant(handling *DataHandling, options []AccountOption) {
	for _, option := range options {
		for _, id := range option.Grants {
			if slices.Contains(handling.Certifications, id+eligibleSuffix) && !slices.Contains(handling.Certifications, id) {
				handling.Certifications = append(slices.Clone(handling.Certifications), id)
			}
		}
	}
	slices.SortFunc(handling.Certifications, func(a, b string) int {
		return slices.Index(policy.Certifications, a) - slices.Index(policy.Certifications, b)
	})
}

// optionsNamed returns the provider's options with the IDs that a deployment's route record lists.
func (p compiledProvider) optionsNamed(ids []string) []AccountOption {
	var options []AccountOption
	for _, option := range p.AccountOptions {
		if slices.Contains(ids, option.ID) {
			options = append(options, option)
		}
	}
	return options
}

// validateReachingOptions checks the account options that a deployment's route record lists: each
// is an option of the provider that covers the route, once, in the provider's order, and none
// brings the record under its model's minimum retention or leaves facts that no record may state.
func validateReachingOptions(owner, routeID string, record compiledDeploymentRoute, provider compiledProvider, model compiledModel) error {
	options := provider.optionsNamed(record.AccountOptions)
	if !slices.EqualFunc(options, record.AccountOptions, func(option AccountOption, id string) bool { return option.ID == id }) {
		return fmt.Errorf("%s lists account options that are not its provider's, in its provider's order", owner)
	}
	for _, option := range options {
		if !slices.Contains(option.Routes, routeID) {
			return fmt.Errorf("%s lists account option %s, which does not cover its route", owner, option.ID)
		}
		if days, minimum := option.DataHandling.RetentionDays, model.MinimumRetentionDays; days != nil && minimum != nil && *days < *minimum {
			return fmt.Errorf("%s lists account option %s, which is under its model's minimum retention", owner, option.ID)
		}
		handling := record.DataHandling
		option.set(&handling)
		if err := validateDeploymentDataHandling(owner+" with account option "+option.ID, handling); err != nil {
			return err
		}
	}
	return nil
}

// validateAccountOptions checks a provider's options as the catalog's build does: unique IDs, no
// route of another provider, an effect, and granted certifications that have an -eligible entry.
func validateAccountOptions(providerID string, provider compiledProvider, routes map[string]compiledRoute) error {
	seen := make(map[string]bool, len(provider.AccountOptions))
	for _, option := range provider.AccountOptions {
		owner := fmt.Sprintf("provider %s account option %q", providerID, option.ID)
		if !policy.ValidFieldValue("credential.accountOptions", option.ID) || seen[option.ID] {
			return fmt.Errorf("%s has an invalid or repeated ID", owner)
		}
		seen[option.ID] = true
		if strings.TrimSpace(option.Name) == "" || option.Group != nil && *option.Group == "" {
			return fmt.Errorf("%s needs a name, and a group that is not empty", owner)
		}
		if !uniqueNonEmpty(option.Routes) {
			return fmt.Errorf("%s must list each route that it covers once", owner)
		}
		// The catalog also lists routes that the gateway does not load.
		for _, routeID := range option.Routes {
			if route, ok := routes[routeID]; ok && route.ProviderID != providerID {
				return fmt.Errorf("%s covers %s, which is not a route of its provider", owner, routeID)
			}
		}
		effect := option.DataHandling
		if effect == (AccountOptionDataHandling{}) && len(option.Grants) == 0 {
			return fmt.Errorf("%s changes nothing", owner)
		}
		if effect.ZeroDataRetention != nil && !*effect.ZeroDataRetention || effect.RetentionDays != nil && *effect.RetentionDays < 0 {
			return fmt.Errorf("%s states an invalid fact", owner)
		}
		for _, id := range option.Grants {
			if strings.HasSuffix(id, eligibleSuffix) || !slices.Contains(policy.Certifications, id+eligibleSuffix) {
				return fmt.Errorf("%s grants %s, which no -eligible entry leads to", owner, id)
			}
		}
	}
	return nil
}
