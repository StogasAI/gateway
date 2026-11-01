// Package location reads a catalog's locations: world, the regions within it, and ISO 3166
// countries and their subdivisions, each with the places that directly contain it. A data
// handling location is a place, unknown when the provider does not say where, or, for storage
// only, none when the provider keeps nothing.
package location

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

const (
	World   = "world"
	Unknown = "unknown"
	None    = "none"
)

var form = regexp.MustCompile(`^([A-Z]{2}(-[A-Z0-9]{1,3})?|[a-z][a-z0-9]*(-[a-z0-9]+)*)$`)

// Form reports whether value has the form of a location: an ISO 3166 code such as 'DE' or
// 'US-CA', or a lowercase name such as 'eu', 'north-america', 'unknown' or 'none'. Only a
// catalog says which places there are.
func Form(value string) bool {
	return form.MatchString(value)
}

// Country reports whether value has the form of an ISO 3166-1 alpha-2 code, such as 'US'.
func Country(value string) bool {
	return len(value) == 2 && 'A' <= value[0] && value[0] <= 'Z' && 'A' <= value[1] && value[1] <= 'Z'
}

// Places are a catalog's places.
type Places struct {
	// within lists each place with every place that contains it, in order.
	within map[string][]string
	// inside lists each place with every place inside it, in order.
	inside map[string][]string
	// folded gives each place by its ID in lowercase, which no two places share.
	folded map[string]string
}

// Read checks a catalog's places, each with the places that directly contain it: world contains
// every other place, and no place contains itself.
func Read(parents map[string][]string) (*Places, error) {
	if direct, ok := parents[World]; !ok || len(direct) != 0 {
		return nil, errors.New("the catalog's locations must have world, in no other place")
	}
	ids := slices.Sorted(maps.Keys(parents))
	folded := make(map[string]string, len(ids))
	for _, id := range ids {
		direct := parents[id]
		if !Form(id) || id == Unknown || id == None {
			return nil, fmt.Errorf("location %q has an invalid ID", id)
		}
		if other, ok := folded[strings.ToLower(id)]; ok {
			return nil, fmt.Errorf("locations %s and %s differ only in case", other, id)
		}
		folded[strings.ToLower(id)] = id
		if id != World && len(direct) == 0 {
			return nil, fmt.Errorf("location %s lies in no place", id)
		}
		for index, parent := range direct {
			if _, ok := parents[parent]; !ok {
				return nil, fmt.Errorf("location %s lies in unknown place %s", id, parent)
			}
			if slices.Contains(direct[:index], parent) {
				return nil, fmt.Errorf("location %s repeats place %s", id, parent)
			}
		}
	}
	places := &Places{within: make(map[string][]string, len(ids)), inside: make(map[string][]string, len(ids)), folded: folded}
	// A visit finishes a place's parents first, so reaching a place again before its own visit
	// finishes means that it contains itself.
	visiting := make(map[string]bool)
	var visit func(id string) error
	visit = func(id string) error {
		if _, done := places.within[id]; done {
			return nil
		}
		if visiting[id] {
			return fmt.Errorf("location %s lies in itself", id)
		}
		visiting[id] = true
		within := []string{id}
		for _, parent := range parents[id] {
			if err := visit(parent); err != nil {
				return err
			}
			for _, place := range places.within[parent] {
				if !slices.Contains(within, place) {
					within = append(within, place)
				}
			}
		}
		slices.Sort(within)
		places.within[id] = slices.Clip(within)
		visiting[id] = false
		return nil
	}
	for _, id := range ids {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	for _, id := range ids {
		for _, place := range places.within[id] {
			places.inside[place] = append(places.inside[place], id)
		}
	}
	for id, inside := range places.inside {
		places.inside[id] = slices.Clip(inside)
	}
	return places, nil
}

// Decode reads places as a catalog root lists them: each by its ID, with its name and the places
// that directly contain it.
func Decode(data []byte) (*Places, error) {
	var locations map[string]struct {
		ParentIDs []string `json:"parentIds"`
	}
	if err := json.Unmarshal(data, &locations); err != nil {
		return nil, err
	}
	parents := make(map[string][]string, len(locations))
	for id, place := range locations {
		parents[id] = place.ParentIDs
	}
	return Read(parents)
}

// Place reports whether value is one of the places.
func (p *Places) Place(value string) bool {
	_, ok := p.within[value]
	return ok
}

// Fold gives the place whose ID differs from value only in case, such as 'eu' for 'EU'.
func (p *Places) Fold(value string) (string, bool) {
	place, ok := p.folded[strings.ToLower(value)]
	return place, ok
}

// Valid reports whether value can be a data handling location: a place or unknown, or none for
// storage.
func (p *Places) Valid(value string, storage bool) bool {
	return p.Place(value) || value == Unknown || storage && value == None
}

// Within reports whether a location lies within a boundary: it is the boundary or a place inside
// it, or the boundary is world or unknown, which bound nothing.
func (p *Places) Within(actual, boundary string) bool {
	if !p.Valid(actual, true) || !p.Valid(boundary, true) {
		return false
	}
	return actual == boundary || boundary == World || boundary == Unknown ||
		slices.Contains(p.within[actual], boundary)
}

var (
	unknownOnly = []string{Unknown}
	noneOnly    = []string{None}
)

// Containing lists a location and every place that contains it, in order. Unknown and none list
// only themselves.
func (p *Places) Containing(value string) []string {
	switch value {
	case Unknown:
		return unknownOnly
	case None:
		return noneOnly
	}
	return p.within[value]
}

// Inside lists the locations within a boundary, in order, or returns nil when the boundary is
// world or unknown, which bound nothing. Only none lies within none.
func (p *Places) Inside(boundary string) []string {
	switch boundary {
	case World, Unknown:
		return nil
	case None:
		return noneOnly
	}
	if inside, ok := p.inside[boundary]; ok {
		return inside
	}
	return []string{}
}
