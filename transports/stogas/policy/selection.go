package policy

import "slices"

// Selection orders the already authorized deployment pool. It never broadens
// catalog selectors, filters, credential eligibility, or inherited restrictions.
type Selection struct {
	Mode    string   `json:"mode"`
	Targets []string `json:"targets,omitempty"`
}

func (s *Selection) Same(other *Selection) bool {
	if s == other {
		return true
	}
	if s == nil || other == nil || s.Mode != other.Mode || len(s.Targets) != len(other.Targets) {
		return false
	}
	if s.Mode == "ordered" {
		return slices.Equal(s.Targets, other.Targets)
	}
	// Random targets form a set; JSON list order cannot create a conflict.
	targets := make(map[string]bool, len(s.Targets))
	for _, id := range s.Targets {
		targets[id] = true
	}
	for _, id := range other.Targets {
		if !targets[id] {
			return false
		}
	}
	return true
}

func (r *Routing) validateSelection() error {
	s := r.Selection
	if s == nil {
		return nil
	}
	if s.Mode != "ordered" && s.Mode != "random" {
		return configError("routing.selection.mode must be ordered or random")
	}
	if (s.Mode == "ordered" || s.Targets != nil) && len(s.Targets) == 0 {
		return configError("routing.selection.targets must contain deployment IDs")
	}
	if r.Query != nil && len(r.Query.OrderBy) > 0 {
		return configError("routing.sort and routing.selection cannot both select an order")
	}
	return (&AllowedCatalogNodes{Deployments: s.Targets}).validate()
}
