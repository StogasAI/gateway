package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestNetworksTakeAddressesAndRangesThatStartAtTheirFirstAddress(t *testing.T) {
	source := ruleSource(t, `{"access":{"networks":{"allow":["203.0.113.5","198.51.100.0/24","2001:db8::/32","2001:db8:ffff::7"]}}}`)
	for address, allowed := range map[string]bool{
		"203.0.113.5": true, "203.0.113.6": false, "198.51.100.255": true, "198.51.101.0": false,
		// The gateway reads an IPv4 client that reaches it over IPv6 in its IPv4 form.
		"::ffff:198.51.100.7": true, "2001:db8:1::1": true, "2001:db9::1": false,
	} {
		if denied := source.Config.NetworkDenied(netip.MustParseAddr(address)); denied == allowed {
			t.Errorf("%s: denied=%v", address, denied)
		}
	}
	// A client without a known address, such as one of the onion service, is
	// inside only a list that holds every IPv4 and IPv6 address.
	for raw, allowed := range map[string]bool{
		`{}`: true,
		`{"access":{"networks":{"allow":["0.0.0.0/0","::/0"]}}}`:              true,
		`{"access":{"networks":{"allow":["::/0","10.0.0.0/8","0.0.0.0/0"]}}}`: true,
		`{"access":{"networks":{"allow":["0.0.0.0/0"]}}}`:                     false,
	} {
		if ruleSource(t, raw).Config.NetworkDenied(netip.Addr{}) == allowed {
			t.Errorf("%s: unknown client allowed=%v", raw, !allowed)
		}
	}
	if !source.Config.NetworkDenied(netip.Addr{}) {
		t.Fatal("an unknown client passed a list of some networks")
	}

	for raw, message := range map[string]string{
		`{"access":{}}`:                                            "deny or networks",
		`{"access":{"networks":{}}}`:                               "allow or deny",
		`{"access":{"networks":["10.0.0.0/8"]}}`:                   "cannot unmarshal",
		`{"access":{"networks":{"deny":["10.0.0.1/8"]}}}`:          "access.networks.deny has \"10.0.0.1/8\", which must start at 10.0.0.0/8",
		`{"access":{"networks":{"deny":["10.0.0.1","10.0.0.1"]}}}`: "access.networks.deny lists 10.0.0.1/32 twice",
		// A deny list that leaves no allowed address is a mistake, which enabled states plainly.
		`{"access":{"networks":{"allow":["10.0.0.0/8","192.0.2.7"],"deny":["192.0.2.0/24","0.0.0.0/5","8.0.0.0/5"]}}}`: "holds every network that allow lists",
		`{"access":{"networks":{"allow":[]}}}`:                         "at least one",
		`{"access":{"networks":{"allow":["10.0.0.1/8"]}}}`:             "must start at 10.0.0.0/8",
		`{"access":{"networks":{"allow":["::ffff:10.0.0.0/104"]}}}`:    "IPv4 form",
		`{"access":{"networks":{"allow":["fe80::1%eth0"]}}}`:           "not an IP address",
		`{"access":{"networks":{"allow":["10.0.0.0/33"]}}}`:            "not an IP address",
		`{"access":{"networks":{"allow":["example.com"]}}}`:            "not an IP address",
		`{"access":{"networks":{"allow":["10.0.0.1","10.0.0.1/32"]}}}`: "twice",
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("%s: %v, want %q", raw, err, message)
		}
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
	config := compose(`{"access":{"networks":{"allow":["10.0.0.0/8","192.0.2.0/24"]}}}`, `{"access":{"networks":{"allow":["10.255.0.0/16","10.0.0.0/16","198.51.100.0/24"]}}}`)
	if want := []string{"10.0.0.0/16", "10.255.0.0/16"}; !slices.Equal(config.Access.Networks.Allow, want) || config.Access.Networks.Deny != nil {
		t.Fatalf("combined networks %+v, want %q", config.Access.Networks, want)
	}
	for address, allowed := range map[string]bool{"10.0.0.1": true, "10.255.0.1": true, "10.128.0.1": false, "192.0.2.1": false, "198.51.100.1": false} {
		if config.NetworkDenied(netip.MustParseAddr(address)) == allowed {
			t.Errorf("%s: allowed=%v", address, !allowed)
		}
	}

	// Lists that share no address allow no client.
	none := compose(`{"access":{"networks":{"allow":["10.0.0.0/8"]}}}`, `{"access":{"networks":{"allow":["2001:db8::/32"]}}}`)
	if none.Access.Networks.Allow == nil || len(none.Access.Networks.Allow) != 0 || !none.NetworkDenied(netip.MustParseAddr("10.0.0.1")) {
		t.Fatalf("disjoint lists allowed a client: %+v", none.Access)
	}
	raw, err := json.Marshal(none.Access)
	if err != nil || string(raw) != `{"networks":{"allow":[]}}` {
		t.Fatalf("combined access %s %v", raw, err)
	}
}

func TestDefaultNetworksYieldOnlyToRequiredNetworks(t *testing.T) {
	org := ruleSource(t, `{"rules":{"office":{"mode":"default","access":{"networks":{"allow":["10.0.0.0/8"]}}}}}`)
	for key, allowed := range map[string][3]bool{
		// A deny period is another setting, so the default networks still apply.
		`{"access":{"deny":[{"days":["sun"],"start":"00:00","end":"01:00","timeZone":"UTC"}]}}`: {true, false, false},
		`{"access":{"networks":{"allow":["192.0.2.0/24"]}}}`:                                    {false, true, false},
		// Every address, or an empty deny list, replaces the default without a restriction of its own.
		`{"access":{"networks":{"allow":["0.0.0.0/0","::/0"]}}}`: {true, true, true},
		`{"access":{"networks":{"deny":[]}}}`:                    {true, true, true},
		// A deny list replaces the default too, because networks are one setting.
		`{"access":{"networks":{"deny":["192.0.2.0/24"]}}}`: {true, false, false},
	} {
		config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: ruleSource(t, key)}})
		if err != nil {
			t.Fatal(err)
		}
		active, err := config.Activate(ruleValues{})
		if err != nil {
			t.Fatal(err)
		}
		// The last client has no known address, as one of the onion service.
		for index, address := range []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.0.2.1"), {}} {
			if active.NetworkDenied(address) == allowed[index] {
				t.Errorf("%s: %s allowed=%v", key, address, !allowed[index])
			}
		}
	}
}

func TestNetworksAndDenyPeriodsAreDelegatedApart(t *testing.T) {
	parent := json.RawMessage(`{"delegation":{"keys":["access.deny"]}}`)
	edit := &InspectionEdit{Scope: KeyScope, Previous: json.RawMessage(`{}`)}
	for key, allowed := range map[string]bool{
		`{"access":{"deny":[{"days":["sun"],"start":"00:00","end":"01:00","timeZone":"UTC"}]}}`: true,
		`{"access":{"networks":{"allow":["10.0.0.0/8"]}}}`:                                      false,
	} {
		_, err := InspectSources([]InspectionSource{{Scope: OrganizationScope, Config: parent}, {Scope: KeyScope, Config: json.RawMessage(key)}}, edit)
		if allowed != (err == nil) || !allowed && !errors.Is(err, ErrPolicyEditForbidden) {
			t.Errorf("%s: %v", key, err)
		}
	}
	// The whole section still names both settings.
	var permission Permission
	if err := json.Unmarshal([]byte(`["access"]`), &permission); err != nil || permission != permissionDeny|permissionNetworks {
		t.Fatalf("access section %b %v", permission, err)
	}
	if raw, _ := json.Marshal(permission | permissionInput); string(raw) != `["access.deny","access.networks","input"]` {
		t.Fatalf("access permission names %s", raw)
	}
}
