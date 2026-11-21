package policy

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestRegionsHoldCountriesThatPoliciesTake(t *testing.T) {
	if len(regionCountries) == 0 {
		t.Fatal("no regions")
	}
	for region, countries := range regionCountries {
		if countryCode(region) || len(countries) == 0 || !slices.IsSorted(countries) || len(slices.Compact(slices.Clone(countries))) != len(countries) {
			t.Errorf("%s: %q", region, countries)
		}
		for _, country := range countries {
			if !countryCode(country) {
				t.Errorf("%s holds %s, which access.countries does not take", region, country)
			}
		}
	}
}

func TestCountriesTakeRegions(t *testing.T) {
	for raw, message := range map[string]string{
		`{"access":{"countries":{"deny":["EU"]}}}`:                     `has "EU", which is not an ISO 3166-1 alpha-2 country code or a region such as eu`,
		`{"access":{"countries":{"deny":["US-CA"]}}}`:                  "a region such as eu",
		`{"access":{"countries":{"allow":["eu","eu"]}}}`:               "access.countries.allow lists eu twice",
		`{"access":{"countries":{"allow":["AT","FR"],"deny":["eu"]}}}`: "access.countries.deny holds every country that allow lists",
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("%s: %v, want %q", raw, err, message)
		}
	}
	// world holds every country that the catalog lists, so an allow list of it refuses only a
	// client that no country holds.
	everywhere := ruleSource(t, `{"access":{"countries":{"allow":["world"]}}}`).Config
	for country, admitted := range map[string]bool{"AQ": true, "CN": true, "XK": true, "": false} {
		client := Client{Address: netip.MustParseAddr("203.0.113.5"), Country: country}
		if got := everywhere.ClientRefusal(client); (got == Admitted) != admitted {
			t.Errorf("world, %q: %v", country, got)
		}
	}
	// A region may hold another entry of its list.
	overlap := ruleSource(t, `{"access":{"countries":{"allow":["eu","AT"]}}}`).Config
	if !slices.Equal(overlap.Access.Countries.Allow, regionCountries["eu"]) {
		t.Fatalf("allow %q", overlap.Access.Countries.Allow)
	}
	config := ruleSource(t, `{"access":{"countries":{"allow":["europe","US"],"deny":["eu"]}}}`).Config
	for country, admitted := range map[string]bool{"CH": true, "NO": true, "US": true, "AT": false, "CN": false, "": false} {
		client := Client{Address: netip.MustParseAddr("203.0.113.5"), Country: country}
		if got := config.ClientRefusal(client); (got == Admitted) != admitted {
			t.Errorf("%q: %v", country, got)
		}
	}
}

func TestEffectivePolicyNamesRegionsThatCountriesFill(t *testing.T) {
	inspect := func(org, key string) *Inspection {
		t.Helper()
		result, err := InspectSources([]InspectionSource{
			{Scope: OrganizationScope, Config: json.RawMessage(org)},
			{Scope: KeyScope, ID: "key", Config: json.RawMessage(key)},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	effective := func(result *Inspection) string {
		raw, err := json.Marshal(result.Effective["access"])
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	// Europe and the countries of eu or the US share eu.
	result := inspect(`{"access":{"countries":{"allow":["europe"],"deny":["RU"]}}}`, `{"access":{"countries":{"allow":["eu","US"],"deny":["asia"]}}}`)
	if got := effective(result); got != `{"countries":{"allow":["eu"],"deny":["RU","asia"]}}` {
		t.Fatalf("effective access %s", got)
	}
	if !slices.Equal(result.Compiled.Access.Countries.Allow, regionCountries["eu"]) {
		t.Fatalf("compiled allow %q", result.Compiled.Access.Countries.Allow)
	}
	// Allow lists that share no country admit none.
	if got := effective(inspect(`{"access":{"countries":{"allow":["eu"]}}}`, `{"access":{"countries":{"allow":["US"]}}}`)); got != `{"countries":{"allow":[]}}` {
		t.Fatalf("disjoint access %s", got)
	}

	for _, test := range []struct{ countries, want []string }{
		{nil, nil},
		{append(slices.Clone(regionCountries["europe"]), "US"), []string{"US", "europe"}},
		{append(slices.Clone(regionCountries["eu"]), "CH"), []string{"CH", "eu"}},
		{regionCountries["eu"][1:], regionCountries["eu"][1:]},
	} {
		if got := namedCountries(countriesOf(test.countries)); !slices.Equal(got, test.want) || (got == nil) != (test.want == nil) {
			t.Errorf("%q: %q, want %q", test.countries, got, test.want)
		}
	}
}
