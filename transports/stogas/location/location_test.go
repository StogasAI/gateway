package location

import (
	"strings"
	"testing"
)

func TestWithin(t *testing.T) {
	tests := map[string]struct {
		actual   string
		boundary string
		allowed  bool
	}{
		"exact country":            {actual: "US", boundary: "US", allowed: true},
		"country outside country":  {actual: "CA", boundary: "US", allowed: false},
		"EU country":               {actual: "SE", boundary: "eu", allowed: true},
		"non-EU European country":  {actual: "CH", boundary: "eu", allowed: false},
		"European country":         {actual: "CH", boundary: "europe", allowed: true},
		"EU within Europe":         {actual: "eu", boundary: "europe", allowed: true},
		"APAC country":             {actual: "JP", boundary: "apac", allowed: true},
		"country outside APAC":     {actual: "US", boundary: "apac", allowed: false},
		"world boundary":           {actual: "US", boundary: "world", allowed: true},
		"unknown boundary":         {actual: "unknown", boundary: "unknown", allowed: true},
		"unknown actual is not EU": {actual: "unknown", boundary: "eu", allowed: false},
		"invalid country":          {actual: "ZZ", boundary: "world", allowed: false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Within(test.actual, test.boundary); got != test.allowed {
				t.Fatalf("Within(%q, %q) = %v, want %v", test.actual, test.boundary, got, test.allowed)
			}
		})
	}
	for _, country := range strings.Split(strings.Trim(euCountries, "|"), "|") {
		if !Within(country, "europe") {
			t.Fatalf("EU country %s is outside Europe", country)
		}
	}
}
