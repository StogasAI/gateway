package location

import (
	"slices"
	"testing"
)

// testPlaces nest like the catalog's: Cyprus lies in Asia and in the EU, which lies in Europe.
func testPlaces(t *testing.T) *Places {
	t.Helper()
	places, err := Read(map[string][]string{
		"world":  {},
		"asia":   {"world"},
		"europe": {"world"},
		"eu":     {"europe"},
		"CY":     {"asia", "eu"},
		"DE":     {"eu"},
		"NO":     {"europe"},
		"US":     {"world"},
		"US-CA":  {"US"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return places
}

func TestWithin(t *testing.T) {
	places := testPlaces(t)
	for _, tc := range []struct {
		actual, boundary string
		want             bool
	}{
		{"DE", "eu", true},
		{"DE", "europe", true},
		{"eu", "europe", true},
		{"CY", "asia", true},
		{"CY", "europe", true},
		{"US-CA", "US", true},
		{"DE", "DE", true},
		{"NO", "eu", false},
		{"europe", "eu", false},
		{"world", "eu", false},
		{"unknown", "eu", false},
		{"DE", "world", true},
		{"unknown", "world", true},
		{"DE", "unknown", true},
		{"none", "none", true},
		{"DE", "none", false},
		{"none", "eu", false},
		{"FR", "eu", false},
		{"FR", "world", false},
		{"DE", "FR", false},
	} {
		if got := places.Within(tc.actual, tc.boundary); got != tc.want {
			t.Errorf("Within(%q, %q) = %v", tc.actual, tc.boundary, got)
		}
	}
}

func TestContainingAndInsideAgreeWithWithin(t *testing.T) {
	places := testPlaces(t)
	values := []string{"unknown", "none", "FR"}
	for id := range places.within {
		values = append(values, id)
	}
	for _, boundary := range values {
		inside := places.Inside(boundary)
		for _, actual := range values {
			within := places.Within(actual, boundary)
			if got := inside == nil && places.Valid(actual, true) || slices.Contains(inside, actual); got != within {
				t.Errorf("Inside(%q) has %q = %v, Within = %v", boundary, actual, got, within)
			}
			if boundary != World && boundary != Unknown && slices.Contains(places.Containing(actual), boundary) != within {
				t.Errorf("Containing(%q) has %q, Within = %v", actual, boundary, within)
			}
		}
	}
	if got := places.Containing("CY"); !slices.Equal(got, []string{"CY", "asia", "eu", "europe", "world"}) {
		t.Errorf("Containing(CY) = %v", got)
	}
	if got := places.Containing("unknown"); !slices.Equal(got, []string{"unknown"}) {
		t.Errorf("Containing(unknown) = %v", got)
	}
	if got := places.Inside("eu"); !slices.Equal(got, []string{"CY", "DE", "eu"}) {
		t.Errorf("Inside(eu) = %v", got)
	}
}

func TestReadRefusesMalformedPlaces(t *testing.T) {
	for name, parents := range map[string]map[string][]string{
		"no world":            {"eu": {"europe"}, "europe": {}},
		"world in a place":    {"world": {"eu"}, "eu": {"world"}},
		"orphan":              {"world": {}, "eu": {}},
		"unknown parent":      {"world": {}, "eu": {"europe"}},
		"repeated parent":     {"world": {}, "europe": {"world", "world"}},
		"cycle":               {"world": {}, "a": {"world", "b"}, "b": {"a"}},
		"self":                {"world": {}, "a": {"a"}},
		"unknown is no place": {"world": {}, "unknown": {"world"}},
		"none is no place":    {"world": {}, "none": {"world"}},
		"bad ID":              {"world": {}, "Europe": {"world"}},
		"bad subdivision":     {"world": {}, "US-": {"world"}},
		"IDs only in case":    {"world": {}, "eu": {"world"}, "EU": {"world"}},
	} {
		if _, err := Read(parents); err == nil {
			t.Errorf("%s: Read accepted %v", name, parents)
		}
	}
}

func TestFoldFindsThePlaceThatDiffersOnlyInCase(t *testing.T) {
	places := testPlaces(t)
	for value, want := range map[string]string{"EU": "eu", "de": "DE", "Us-ca": "US-CA", "eu": "eu", "mars": "", "": ""} {
		if place, ok := places.Fold(value); place != want || ok != (want != "") {
			t.Errorf("Fold(%q) = %q, %v; want %q", value, place, ok, want)
		}
	}
}

func TestDecodeReadsARootsLocations(t *testing.T) {
	places, err := Decode([]byte(`{"eu":{"name":"European Union","parentIds":["world"]},"world":{"name":"World","parentIds":[]}}`))
	if err != nil || !places.Place("eu") || !places.Within("eu", "world") {
		t.Fatalf("Decode = %v, %v", places, err)
	}
	for _, data := range []string{``, `[]`, `{"world":{"parentIds":"none"}}`, `{"eu":{"parentIds":["world"]}}`} {
		if _, err := Decode([]byte(data)); err == nil {
			t.Errorf("Decode accepted %s", data)
		}
	}
}

func TestForm(t *testing.T) {
	for value, want := range map[string]bool{
		"DE": true, "US-CA": true, "GB-ENG": true, "eu": true, "north-america": true, "unknown": true,
		"none": true, "world": true, "Europe": false, "EU ": false, "": false, "-eu": false,
		"eu-": false, "US-ABCD": false, "D": false, "DEU": false, "north--america": false,
	} {
		if Form(value) != want {
			t.Errorf("Form(%q) = %v", value, !want)
		}
	}
	for value, want := range map[string]bool{"US": true, "US-CA": false, "us": false, "U": false, "": false} {
		if Country(value) != want {
			t.Errorf("Country(%q) = %v", value, !want)
		}
	}
}
