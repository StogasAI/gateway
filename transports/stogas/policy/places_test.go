package policy

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/location"
)

// The tests check policies as Control saves them, against the places and companies of the catalog
// that its policy compiler embeds.
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
	data, err = os.ReadFile("../../cmd/stogas-policy-wasm/companies.json")
	if err != nil {
		panic(err)
	}
	var listed map[string]json.RawMessage
	if err := json.Unmarshal(data, &listed); err != nil {
		panic(err)
	}
	CheckCompanies(slices.Collect(maps.Keys(listed)))
	os.Exit(m.Run())
}

func TestSavedCompaniesAreCatalogCompanies(t *testing.T) {
	for _, source := range []string{
		`deployment.hosting == "aws"`,
		`provider.companyId == "Anthropic"`,
		`deployment.companies.all(company, company in ["anthropic", "azure"])`,
		`"google-cloud" in deployment.dataHandling.sharedWith`,
	} {
		if _, err := CompileCEL(source); err == nil || !strings.Contains(err.Error(), "use a company that the catalog lists") {
			t.Errorf("%s: error = %v", source, err)
		}
	}
	for _, source := range []string{
		`deployment.hosting == provider.companyId`,
		`deployment.hosting in ["amazon", "anthropic", "unknown"]`,
		`author.companyId == "google"`,
		`deployment.companies.all(company, company in ["anthropic", "microsoft"])`,
		`deployment.dataHandling.sharedWith.size() == 0`,
	} {
		if _, err := CompileCEL(source); err != nil {
			t.Errorf("%s: %v", source, err)
		}
	}
	// The gateway checks only an ID's form, since its catalog can list companies that the compiler
	// that saved a policy did not.
	saved := companies
	CheckCompanies(nil)
	defer func() { companies = saved }()
	if _, err := CompileCEL(`deployment.hosting == "a-new-company"`); err != nil {
		t.Fatal(err)
	}
	if _, err := CompileCEL(`deployment.hosting == "A New Company"`); err == nil {
		t.Fatal("accepted a company ID of another form")
	}
}

func TestSavedCertificationsAreKnown(t *testing.T) {
	for _, source := range []string{
		`"soc-2" in deployment.dataHandling.certifications`,
		`deployment.dataHandling.certifications.exists(c, c == "SOC2-TYPE2")`,
	} {
		if _, err := CompileCEL(source); err == nil || !strings.Contains(err.Error(), "'soc2-type2'") {
			t.Errorf("%s: error = %v", source, err)
		}
	}
	for _, source := range []string{
		`"soc2-type2" in deployment.dataHandling.certifications && "iso-27001" in deployment.dataHandling.certifications`,
		`["fedramp-high", "dod-il5"].all(c, c in deployment.dataHandling.certifications)`,
		`deployment.dataHandling.certifications.size() > 0`,
	} {
		if _, err := CompileCEL(source); err != nil {
			t.Errorf("%s: %v", source, err)
		}
	}
}

func TestSavedLocationsAreCatalogPlaces(t *testing.T) {
	for source, message := range map[string]string{
		`deployment.dataHandling.processingLocation == "EU"`:             "processingLocation cannot be 'EU'; use 'eu'",
		`deployment.dataHandling.storageLocation in ["eu", "us"]`:        "storageLocation cannot be 'us'; use 'US'",
		`"Europe" in deployment.dataHandling.processingWithin`:           "processingWithin cannot be 'Europe'; use 'europe'",
		`deployment.dataHandling.processingLocation == "mars"`:           "cannot be 'mars'; use a location that the catalog lists",
		`deployment.dataHandling.processingLocation == "none"`:           "cannot be 'none'; use a location that the catalog lists",
		`author.headquarteredCountry == "EU"`:                            "cannot be 'EU'; use an uppercase ISO country code",
		`provider.headquarteredCountry != "cn"`:                          "headquarteredCountry cannot be 'cn'; use 'CN'",
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
		// A headquarters can be a country that the catalog does not list as a place.
		`provider.headquarteredCountry != "KP"`,
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
