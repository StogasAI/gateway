package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// at is a client at an address that the gateway's lists know nothing about.
func at(address string) Client {
	return Client{Address: netip.MustParseAddr(address)}
}

var onionClient = Client{Onion: true}

func TestNetworksTakeAddressesAndRangesThatStartAtTheirFirstAddress(t *testing.T) {
	source := ruleSource(t, `{"access":{"networks":{"allow":["203.0.113.5","198.51.100.0/24","2001:db8::/32","2001:db8:ffff::7"]}}}`)
	for address, allowed := range map[string]bool{
		"203.0.113.5": true, "203.0.113.6": false, "198.51.100.255": true, "198.51.101.0": false,
		"2001:db8:1::1": true, "2001:db9::1": false,
	} {
		if refusal := source.Config.ClientRefusal(at(address)); (refusal == Admitted) != allowed || !allowed && refusal != RefusedAddress {
			t.Errorf("%s: %v", address, refusal)
		}
	}
	// A client whose address the gateway could not read passes no list.
	for raw, allowed := range map[string]bool{
		`{}`:                                  true,
		`{"access":{"networks":{"deny":[]}}}`: true,
		`{"access":{"networks":{"allow":["0.0.0.0/0","::/0"]}}}`: false,
		`{"access":{"networks":{"deny":["hosting"]}}}`:           false,
	} {
		if refusal := ruleSource(t, raw).Config.ClientRefusal(Client{}); (refusal == Admitted) != allowed {
			t.Errorf("%s: unknown client %v", raw, refusal)
		}
	}

	for raw, message := range map[string]string{
		`{"access":{}}`:                                            "schedule, networks, countries or transports",
		`{"access":{"schedule":{}}}`:                               "access.schedule requires deny",
		`{"access":{"networks":{}}}`:                               "allow or deny",
		`{"access":{"networks":["10.0.0.0/8"]}}`:                   "cannot unmarshal",
		`{"access":{"networks":{"deny":["10.0.0.1/8"]}}}`:          "access.networks.deny has \"10.0.0.1/8\", which must start at 10.0.0.0/8",
		`{"access":{"networks":{"deny":["10.0.0.1","10.0.0.1"]}}}`: "access.networks.deny lists 10.0.0.1/32 twice",
		// A deny list that leaves no allowed address is a mistake, which enabled states plainly.
		`{"access":{"networks":{"allow":["10.0.0.0/8","192.0.2.7"],"deny":["192.0.2.0/24","0.0.0.0/5","8.0.0.0/5"]}}}`: "holds every network that allow lists",
		`{"access":{"networks":{"allow":["onion"],"deny":["onion"]}}}`:                                                 "holds every network that allow lists",
		`{"access":{"networks":{"allow":[]}}}`:                                                                         "at least one",
		`{"access":{"networks":{"allow":["10.0.0.1/8"]}}}`:                                                             "must start at 10.0.0.0/8",
		`{"access":{"networks":{"allow":["::ffff:10.0.0.0/104"]}}}`:                                                    "IPv4 form",
		`{"access":{"networks":{"allow":["fe80::1%eth0"]}}}`:                                                           "not an IP address, CIDR range or onion",
		`{"access":{"networks":{"allow":["10.0.0.0/33"]}}}`:                                                            "not an IP address",
		`{"access":{"networks":{"allow":["example.com"]}}}`:                                                            "not an IP address",
		`{"access":{"networks":{"allow":["10.0.0.1","10.0.0.1/32"]}}}`:                                                 "twice",
		// Anyone can send from these networks, so they cannot bound where a key works.
		`{"access":{"networks":{"allow":["AS64496"]}}}`:           "access.networks.allow has \"AS64496\", which only deny lists take",
		`{"access":{"networks":{"allow":["hosting"]}}}`:           "which only deny lists take",
		`{"access":{"networks":{"allow":["tor"]}}}`:               "which only deny lists take",
		`{"access":{"networks":{"deny":["AS0"]}}}`:                "not an IP address, CIDR range, AS number, onion, tor, vpn or hosting",
		`{"access":{"networks":{"deny":["AS064496"]}}}`:           "AS number",
		`{"access":{"networks":{"deny":["as64496"]}}}`:            "AS number",
		`{"access":{"networks":{"deny":["AS4294967296"]}}}`:       "AS number",
		`{"access":{"networks":{"deny":["Tor"]}}}`:                "AS number",
		`{"access":{"networks":{"deny":["AS64496","AS64496"]}}}`:  "access.networks.deny lists AS64496 twice",
		`{"access":{"networks":{"deny":["vpn","vpn"]}}}`:          "access.networks.deny lists vpn twice",
		`{"access":{"countries":{}}}`:                             "access.countries requires allow or deny",
		`{"access":{"countries":{"allow":[]}}}`:                   "access.countries.allow requires at least one country",
		`{"access":{"countries":{"allow":["UK"]}}}`:               "access.countries.allow has \"UK\", which is not an ISO 3166-1 alpha-2 country code",
		`{"access":{"countries":{"deny":["us"]}}}`:                "not an ISO 3166-1",
		`{"access":{"countries":{"deny":["eu"]}}}`:                "not an ISO 3166-1",
		`{"access":{"countries":{"deny":["DE","DE"]}}}`:           "access.countries.deny lists DE twice",
		`{"access":{"countries":{"allow":["DE"],"deny":["DE"]}}}`: "holds every country that allow lists",
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("%s: %v, want %q", raw, err, message)
		}
	}
	for _, raw := range []string{
		`{"access":{"networks":{"deny":["AS1","AS4294967295","tor","vpn","hosting","onion","192.0.2.0/24"]}}}`,
		`{"access":{"networks":{"allow":["onion","10.0.0.0/8"],"deny":["onion"]}}}`,
		`{"access":{"countries":{"allow":["XK","AQ"],"deny":[]}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestDenyListsRefuseByWhatTheGatewaysListsSay(t *testing.T) {
	config := ruleSource(t, `{"access":{"networks":{"deny":["AS64496","tor","vpn","hosting"]}}}`).Config
	for name, test := range map[string]struct {
		client Client
		want   Refusal
	}{
		"other":   {at("203.0.113.5"), Admitted},
		"AS":      {Client{Address: netip.MustParseAddr("203.0.113.5"), AS: 64496}, RefusedAS},
		"Tor":     {Client{Address: netip.MustParseAddr("203.0.113.5"), AS: 64497, TorExit: true}, RefusedTorExit},
		"VPN":     {Client{Address: netip.MustParseAddr("203.0.113.5"), AS: 64497, VPN: true}, RefusedVPN},
		"hosting": {Client{Address: netip.MustParseAddr("203.0.113.5"), AS: 64497, Hosting: true}, RefusedHosting},
		// A Tor exit in a denied AS is named as a Tor exit, the narrower fact.
		"Tor in a denied AS": {Client{Address: netip.MustParseAddr("203.0.113.5"), AS: 64496, TorExit: true}, RefusedTorExit},
		// Without the lists the gateway cannot tell, and the onion service needs none.
		"missing":         {Client{Address: netip.MustParseAddr("203.0.113.5"), Missing: HostingList}, ListsMissing},
		"onion":           {onionClient, Admitted},
		"onion, missing":  {Client{Onion: true, Missing: TorExitList | ASList}, Admitted},
		"no list missing": {Client{Address: netip.MustParseAddr("203.0.113.5"), Missing: CountryList}, Admitted},
	} {
		if got := config.ClientRefusal(test.client); got != test.want {
			t.Errorf("%s: %v, want %v", name, got, test.want)
		}
	}
	// A list reads only what its entries need.
	torOnly := ruleSource(t, `{"access":{"networks":{"deny":["tor"]}}}`).Config
	if got := torOnly.ClientRefusal(Client{Address: netip.MustParseAddr("203.0.113.5"), Missing: ASList | VPNList | HostingList}); got != Admitted {
		t.Fatalf("a Tor list read the AS lists: %v", got)
	}
	if got := torOnly.ClientRefusal(Client{Address: netip.MustParseAddr("203.0.113.5"), Missing: TorExitList}); got != ListsMissing {
		t.Fatalf("a Tor list passed without its list: %v", got)
	}
	// An address that a range refuses needs no list.
	ranges := ruleSource(t, `{"access":{"networks":{"allow":["10.0.0.0/8"],"deny":["tor"]}}}`).Config
	if got := ranges.ClientRefusal(Client{Address: netip.MustParseAddr("192.0.2.1"), Missing: TorExitList}); got != RefusedAddress {
		t.Fatalf("an address outside the allow list waited for a list: %v", got)
	}
}

func TestOnionClientsMatchOnlyOnion(t *testing.T) {
	for raw, allowed := range map[string]bool{
		`{"access":{"networks":{"deny":["192.0.2.0/24","tor","AS64496"]}}}`:        true,
		`{"access":{"networks":{"deny":["onion"]}}}`:                               false,
		`{"access":{"networks":{"allow":["0.0.0.0/0","::/0"]}}}`:                   false,
		`{"access":{"networks":{"allow":["onion"]}}}`:                              true,
		`{"access":{"networks":{"allow":["10.0.0.0/8","onion"]}}}`:                 true,
		`{"access":{"countries":{"deny":["RU"]}}}`:                                 true,
		`{"access":{"countries":{"allow":["US"]}}}`:                                false,
		`{"access":{"networks":{"allow":["onion"]},"countries":{"allow":["US"]}}}`: false,
	} {
		refusal := ruleSource(t, raw).Config.ClientRefusal(onionClient)
		if (refusal == Admitted) != allowed {
			t.Errorf("%s: onion client %v", raw, refusal)
		}
	}
	// Only onion clients pass an allow list of onion alone.
	if got := ruleSource(t, `{"access":{"networks":{"allow":["onion"]}}}`).Config.ClientRefusal(at("203.0.113.5")); got != RefusedAddress {
		t.Fatalf("an address passed an onion allow list: %v", got)
	}
}

func TestCountriesAdmitTheirCountries(t *testing.T) {
	config := ruleSource(t, `{"access":{"countries":{"allow":["US","CA","DE"],"deny":["DE"]}}}`).Config
	in := func(country string) Client {
		return Client{Address: netip.MustParseAddr("203.0.113.5"), Country: country}
	}
	for name, test := range map[string]struct {
		client Client
		want   Refusal
	}{
		"allowed":     {in("US"), Admitted},
		"not allowed": {in("FR"), RefusedCountry},
		"denied":      {in("DE"), RefusedCountry},
		// An address in no known country is outside every allow list.
		"no country": {in(""), RefusedCountry},
		"missing":    {Client{Address: netip.MustParseAddr("203.0.113.5"), Missing: CountryList}, ListsMissing},
	} {
		if got := config.ClientRefusal(test.client); got != test.want {
			t.Errorf("%s: %v, want %v", name, got, test.want)
		}
	}
	deny := ruleSource(t, `{"access":{"countries":{"deny":["RU"]}}}`).Config
	if got := deny.ClientRefusal(in("")); got != Admitted {
		t.Fatalf("a deny list refused an address in no country: %v", got)
	}
	// A refusal that the loaded lists prove comes before a list that is missing.
	both := ruleSource(t, `{"access":{"networks":{"deny":["tor"]},"countries":{"allow":["US"]}}}`).Config
	if got := both.ClientRefusal(Client{Address: netip.MustParseAddr("203.0.113.5"), Country: "RU", Missing: TorExitList}); got != RefusedCountry {
		t.Fatalf("a missing list hid a country refusal: %v", got)
	}
	if got := both.ClientRefusal(Client{Address: netip.MustParseAddr("203.0.113.5"), Country: "US", Missing: TorExitList}); got != ListsMissing {
		t.Fatalf("a missing list admitted a client: %v", got)
	}
}

func TestEveryPolicysNetworksApply(t *testing.T) {
	compose := func(org, key string) *Config {
		t.Helper()
		config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, org)}, {Scope: KeyScope, Value: ruleSource(t, key)}})
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	// Two ranges of the key's list sit inside the organization's range, with a gap between them.
	config := compose(`{"access":{"networks":{"allow":["10.0.0.0/8","192.0.2.0/24","onion"],"deny":["AS64497","tor"]}}}`, `{"access":{"networks":{"allow":["10.255.0.0/16","10.0.0.0/16","198.51.100.0/24"],"deny":["hosting","AS64496","AS64497"]}}}`)
	if want := []string{"10.0.0.0/16", "10.255.0.0/16"}; !slices.Equal(config.Access.Networks.Allow, want) {
		t.Fatalf("combined allow %q, want %q", config.Access.Networks.Allow, want)
	}
	if want := []string{"AS64496", "AS64497", "tor", "hosting"}; !slices.Equal(config.Access.Networks.Deny, want) {
		t.Fatalf("combined deny %q, want %q", config.Access.Networks.Deny, want)
	}
	for address, allowed := range map[string]bool{"10.0.0.1": true, "10.255.0.1": true, "10.128.0.1": false, "192.0.2.1": false, "198.51.100.1": false} {
		if (config.ClientRefusal(at(address)) == Admitted) != allowed {
			t.Errorf("%s: allowed=%v", address, !allowed)
		}
	}
	// One allow list leaves out onion, so onion clients pass neither.
	if got := config.ClientRefusal(onionClient); got != RefusedOnion {
		t.Fatalf("onion client %v", got)
	}
	if got := config.ClientRefusal(Client{Address: netip.MustParseAddr("10.0.0.1"), AS: 64496}); got != RefusedAS {
		t.Fatalf("AS of the key's deny list %v", got)
	}

	// Lists that share no address allow no client.
	none := compose(`{"access":{"networks":{"allow":["10.0.0.0/8"]}}}`, `{"access":{"networks":{"allow":["2001:db8::/32"]}}}`)
	if none.Access.Networks.Allow == nil || len(none.Access.Networks.Allow) != 0 || none.ClientRefusal(at("10.0.0.1")) != RefusedAddress {
		t.Fatalf("disjoint lists allowed a client: %+v", none.Access)
	}
	raw, err := json.Marshal(none.Access)
	if err != nil || string(raw) != `{"networks":{"allow":[]}}` {
		t.Fatalf("combined access %s %v", raw, err)
	}

	countries := compose(`{"access":{"countries":{"allow":["US","DE","FR"],"deny":["RU"]}}}`, `{"access":{"countries":{"allow":["FR","US"],"deny":["CN","RU"]}}}`)
	raw, err = json.Marshal(countries.Access)
	if err != nil || string(raw) != `{"countries":{"allow":["FR","US"],"deny":["CN","RU"]}}` {
		t.Fatalf("combined countries %s %v", raw, err)
	}
	disjoint := compose(`{"access":{"countries":{"allow":["US"]}}}`, `{"access":{"countries":{"allow":["CA"]}}}`)
	if raw, _ := json.Marshal(disjoint.Access); string(raw) != `{"countries":{"allow":[]}}` {
		t.Fatalf("disjoint countries %s", raw)
	}
}

func TestDefaultNetworksYieldOnlyToRequiredNetworks(t *testing.T) {
	org := ruleSource(t, `{"rules":{"office":{"mode":"default","access":{"networks":{"allow":["10.0.0.0/8"]}}}}}`)
	for key, allowed := range map[string][3]bool{
		// A deny period is another setting, so the default networks still apply.
		`{"access":{"schedule":{"deny":[{"days":["sun"],"start":"00:00","end":"01:00","timeZone":"UTC"}]}}}`: {true, false, false},
		`{"access":{"networks":{"allow":["192.0.2.0/24"]}}}`:                                                 {false, true, false},
		// An empty deny list replaces the default without a restriction of its own.
		`{"access":{"networks":{"deny":[]}}}`: {true, true, true},
		// A deny list replaces the default too, because networks are one setting.
		`{"access":{"networks":{"deny":["192.0.2.0/24"]}}}`: {true, false, true},
	} {
		config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: ruleSource(t, key)}})
		if err != nil {
			t.Fatal(err)
		}
		active, err := config.Activate(ruleValues{})
		if err != nil {
			t.Fatal(err)
		}
		for index, client := range []Client{at("10.0.0.1"), at("192.0.2.1"), onionClient} {
			if (active.ClientRefusal(client) == Admitted) != allowed[index] {
				t.Errorf("%s: %+v allowed=%v", key, client, !allowed[index])
			}
		}
	}
	// Countries are a setting of their own, with the same neutral value.
	org = ruleSource(t, `{"rules":{"home":{"mode":"default","access":{"countries":{"allow":["US"]}}}}}`)
	for key, allowed := range map[string]bool{
		`{"access":{"networks":{"deny":[]}}}`:  false,
		`{"access":{"countries":{"deny":[]}}}`: true,
	} {
		config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: ruleSource(t, key)}})
		if err != nil {
			t.Fatal(err)
		}
		active, err := config.Activate(ruleValues{})
		if err != nil {
			t.Fatal(err)
		}
		if (active.ClientRefusal(Client{Address: netip.MustParseAddr("203.0.113.5"), Country: "DE"}) == Admitted) != allowed {
			t.Errorf("%s: allowed=%v", key, !allowed)
		}
	}
}

func TestAccessSettingsAreDelegatedApart(t *testing.T) {
	parent := json.RawMessage(`{"delegation":{"keys":["access.schedule"]}}`)
	edit := &InspectionEdit{Scope: KeyScope, Previous: json.RawMessage(`{}`)}
	for key, allowed := range map[string]bool{
		`{"access":{"schedule":{"deny":[{"days":["sun"],"start":"00:00","end":"01:00","timeZone":"UTC"}]}}}`: true,
		`{"access":{"networks":{"allow":["10.0.0.0/8"]}}}`:                                                   false,
		`{"access":{"countries":{"deny":["RU"]}}}`:                                                           false,
		`{"access":{"transports":{"deny":["https"]}}}`:                                                       false,
	} {
		_, err := InspectSources([]InspectionSource{{Scope: OrganizationScope, Config: parent}, {Scope: KeyScope, Config: json.RawMessage(key)}}, edit)
		if allowed != (err == nil) || !allowed && !errors.Is(err, ErrPolicyEditForbidden) {
			t.Errorf("%s: %v", key, err)
		}
	}
	// The whole section still names every setting.
	var permission Permission
	if err := json.Unmarshal([]byte(`["access"]`), &permission); err != nil || permission != permissionSchedule|permissionNetworks|permissionCountries|permissionTransports {
		t.Fatalf("access section %b %v", permission, err)
	}
	if raw, _ := json.Marshal(permission | permissionASCIIOnly | permissionMediaTypes); string(raw) != `["access.countries","access.networks","access.schedule","access.transports","input.asciiOnly","input.mediaTypes"]` {
		t.Fatalf("access permission names %s", raw)
	}
}
