// Package location reads a catalog's locations: world, the regions within it, and ISO 3166
// countries and their subdivisions, each with the places that directly contain it. A data
// handling location is a place, unknown when the provider does not say where, or, for storage
// only, none when the provider keeps nothing. Nothing kept is kept nowhere, so none lies within
// every location: a deployment that keeps less is never refused where one that keeps more is
// accepted.
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

// countryCodes are the ISO 3166-1 alpha-2 codes, with XK, which IP address data uses for Kosovo.
var countryCodes = strings.Fields(`
	AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS
	BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE
	EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM
	HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC
	LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA
	NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
	SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO
	TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW`)

// CountryCode reports whether code is one of the countryCodes, whether or not a catalog lists it
// as a place: a company's headquarters and a client's country can be any country.
func CountryCode(code string) bool {
	_, ok := slices.BinarySearch(countryCodes, code)
	return ok
}

// Places are a catalog's places.
type Places struct {
	// within lists each place with every place that contains it, in order.
	within map[string][]string
	// inside lists each place with every place inside it, in order.
	inside map[string][]string
	// folded gives each place by its ID in lowercase, which no two places share.
	folded map[string]string
	// all lists none and every place, in order: the locations that contain none.
	all []string
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
	places.all = insert(ids, None)
	return places, nil
}

// insert adds a value to a sorted list that lacks it.
func insert(sorted []string, value string) []string {
	index, _ := slices.BinarySearch(sorted, value)
	return slices.Insert(slices.Clone(sorted), index, value)
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

// Within reports whether a location lies within a boundary: it is the boundary, a place inside
// it or none, or the boundary is world or unknown, which bound nothing.
func (p *Places) Within(actual, boundary string) bool {
	if !p.Valid(actual, true) || !p.Valid(boundary, true) {
		return false
	}
	return actual == boundary || actual == None || boundary == World || boundary == Unknown ||
		slices.Contains(p.within[actual], boundary)
}

// Join gives the smallest location that holds both a and b: a location joins none to itself
// and unknown to unknown, and two places join to the smallest place that contains both. Where
// several places contain both without one holding another, as Asia and the EU both hold Cyprus,
// their own join answers, so the result is always one location that holds both.
func (p *Places) Join(a, b string) string {
	switch {
	case a == b:
		return a
	case a == None:
		return b
	case b == None:
		return a
	case a == Unknown || b == Unknown || p == nil || !p.Place(a) || !p.Place(b):
		return Unknown
	}
	var common []string
	for _, place := range p.within[a] {
		if slices.Contains(p.within[b], place) {
			common = append(common, place)
		}
	}
	// The smallest common places are those that contain no other.
	var smallest []string
	for _, place := range common {
		if !slices.ContainsFunc(common, func(other string) bool {
			return other != place && slices.Contains(p.within[other], place)
		}) {
			smallest = append(smallest, place)
		}
	}
	if len(smallest) == 0 {
		return World
	}
	joined := smallest[0]
	for _, place := range smallest[1:] {
		joined = p.Join(joined, place)
	}
	return joined
}

var unknownOnly = []string{Unknown}

// Containing lists a location and every place that contains it, in order. Unknown lists only
// itself, and none every place.
func (p *Places) Containing(value string) []string {
	switch value {
	case Unknown:
		return unknownOnly
	case None:
		return p.all
	}
	return p.within[value]
}

// Inside lists the locations within a boundary that a processing location, or with storage a
// storage location, can be, in order. It returns nil when the boundary is world or unknown, which
// bound nothing.
func (p *Places) Inside(boundary string, storage bool) []string {
	switch {
	case boundary == World || boundary == Unknown:
		return nil
	case !p.Valid(boundary, true):
		return []string{}
	case storage:
		return insert(p.inside[boundary], None)
	}
	if inside := p.inside[boundary]; inside != nil {
		return inside
	}
	// None holds no place.
	return []string{}
}
