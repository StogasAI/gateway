package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/location"
)

// The tests check policies as Control saves them, against the places of the catalog that its
// policy compiler embeds.
func TestMain(m *testing.M) {
	data, err := os.ReadFile("../../cmd/stogas-policy-wasm/places.json")
	if err != nil {
		panic(err)
	}
	known, err := location.Decode(data)
	if err != nil {
		panic(err)
	}
	CheckPlaces(known)
	os.Exit(m.Run())
}

func TestSavedLocationsAreCatalogPlaces(t *testing.T) {
	for source, message := range map[string]string{
		`deployment.dataHandling.processingLocation == "EU"`:             "processingLocation cannot be 'EU'; use 'eu'",
		`deployment.dataHandling.storageLocation in ["eu", "us"]`:        "storageLocation cannot be 'us'; use 'US'",
		`"Europe" in deployment.dataHandling.processingWithin`:           "processingWithin cannot be 'Europe'; use 'europe'",
		`deployment.dataHandling.processingLocation == "mars"`:           "cannot be 'mars'; use a location that the catalog lists",
		`deployment.dataHandling.processingLocation == "none"`:           "cannot be 'none'; use a location that the catalog lists",
		`author.headquarteredCountry == "EU"`:                            "cannot be 'EU'; use an uppercase ISO country code",
		`deployment.dataHandling.storageWithin.exists(p, p == "Europe")`: "storageWithin cannot be 'Europe'; use 'europe'",
	} {
		if _, err := CompileCEL(source); err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("%s: error = %v, want %q", source, err, message)
		}
	}
	for _, source := range []string{
		`deployment.dataHandling.processingLocation in ["eu", "DE", "world", "unknown"]`,
		`deployment.dataHandling.storageLocation == "none"`,
		`"north-america" in deployment.dataHandling.storageWithin`,
		`author.headquarteredCountry == "US"`,
	} {
		if _, err := CompileCEL(source); err != nil {
			t.Errorf("%s: %v", source, err)
		}
	}
}

// The gateway checks only a location's form, since its catalog can list places that the compiler
// that saved a policy did not.
func TestGatewayChecksOnlyTheFormOfLocations(t *testing.T) {
	saved := places
	CheckPlaces(nil)
	defer CheckPlaces(saved)
	if _, err := CompileCEL(`deployment.dataHandling.processingLocation in ["middle-east", "EU"]`); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		`deployment.dataHandling.processingLocation == "none"`,
		`deployment.dataHandling.processingLocation == "Europe"`,
		`deployment.dataHandling.storageLocation == "e_u"`,
	} {
		if _, err := CompileCEL(source); err == nil {
			t.Errorf("accepted %s", source)
		}
	}
}
