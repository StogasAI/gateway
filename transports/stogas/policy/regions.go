package policy

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"maps"
	"slices"

	"github.com/maximhq/bifrost/transports/stogas/location"
)

// regionsJSON gives world and each continent, region and union of the catalog
// that the gateway embeds as its fallback, such as eu, with every country
// that it covers. The gateway's catalog sync writes it beside this file.
//
//go:embed regions.json
var regionsJSON []byte

// regionCountries gives the countries that each region in access.countries
// stands for, and under world every country of the catalog. A policy compiles
// with the places that its compiler was built with, not with the catalog in
// effect, so a catalog publication cannot change which countries a saved deny
// list refuses.
var regionCountries = func() map[string][]string {
	var regions map[string][]string
	if err := json.Unmarshal(regionsJSON, &regions); err != nil {
		panic(err)
	}
	return regions
}()

// regionsBySize lists the regions with the most countries first.
var regionsBySize = slices.SortedFunc(maps.Keys(regionCountries), func(a, b string) int {
	return cmp.Or(len(regionCountries[b])-len(regionCountries[a]), cmp.Compare(a, b))
})

// catalogCountries are the countries of that catalog.
var catalogCountries = func() map[string]bool {
	countries := make(map[string]bool, len(regionCountries[location.World]))
	for _, country := range regionCountries[location.World] {
		countries[country] = true
	}
	return countries
}()

// countryCode reports whether code is a country of the catalog: a client's
// country and a company's headquarters can be any of them.
func countryCode(code string) bool {
	return catalogCountries[code]
}

// countryEntry reports whether an entry of access.countries is a country of
// the catalog or a place that holds countries.
func countryEntry(entry string) bool {
	_, region := regionCountries[entry]
	return region || countryCode(entry)
}

// countriesOf gives the countries of the entries in order, each once, with
// each region in place of its countries. It keeps an empty list apart from an
// absent one.
func countriesOf(entries []string) []string {
	if entries == nil {
		return nil
	}
	countries := []string{}
	for _, entry := range entries {
		if members, ok := regionCountries[entry]; ok {
			countries = append(countries, members...)
		} else {
			countries = append(countries, entry)
		}
	}
	slices.Sort(countries)
	return slices.Compact(countries)
}

// namedCountries names countries by each largest region that they hold whole,
// and then by the countries that those regions leave, so that the effective
// policy shows eu where policies named it.
func namedCountries(countries []string) []string {
	if len(countries) == 0 {
		return countries
	}
	held := make(map[string]bool, len(countries))
	for _, country := range countries {
		held[country] = true
	}
	named := make(map[string]bool, len(countries))
	var out []string
	for _, region := range regionsBySize {
		members := regionCountries[region]
		whole := !slices.ContainsFunc(members, func(country string) bool { return !held[country] })
		adds := slices.ContainsFunc(members, func(country string) bool { return !named[country] })
		if !whole || !adds {
			continue
		}
		out = append(out, region)
		for _, country := range members {
			named[country] = true
		}
	}
	for _, country := range countries {
		if !named[country] {
			out = append(out, country)
		}
	}
	slices.Sort(out)
	return out
}
