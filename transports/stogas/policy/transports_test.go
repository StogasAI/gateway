package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestTransportsAdmitOnlyTheirConnectionModes(t *testing.T) {
	for raw, admitted := range map[string][3]bool{
		`{"access":{"transports":{"allow":["e2ee","attested_tls"]}}}`:           {false, true, true},
		`{"access":{"transports":{"deny":["https"]}}}`:                          {false, true, true},
		`{"access":{"transports":{"allow":["https","e2ee"],"deny":["https"]}}}`: {false, false, true},
		`{"access":{"transports":{"deny":[]}}}`:                                 {true, true, true},
		`{"access":{"transports":{"deny":["https","attested_tls","e2ee"]}}}`:    {false, false, false},
	} {
		source := ruleSource(t, raw)
		for index, transport := range transports {
			if source.Config.TransportDenied(transport) == admitted[index] {
				t.Errorf("%s: %s admitted=%v", raw, transport, !admitted[index])
			}
		}
	}
	for raw, message := range map[string]string{
		`{"access":{"transports":{}}}`:                                 "allow or deny",
		`{"access":{"transports":["e2ee"]}}`:                           "cannot unmarshal",
		`{"access":{"transports":{"allow":["tls"]}}}`:                  `access.transports.allow has "tls", which is not https, attested_tls or e2ee`,
		`{"access":{"transports":{"deny":["e2ee","e2ee"]}}}`:           "access.transports.deny lists e2ee twice",
		`{"access":{"transports":{"allow":[]}}}`:                       "allow requires at least one connection mode",
		`{"access":{"transports":{"allow":["e2ee"],"deny":["e2ee"]}}}`: "deny holds every mode that allow lists",
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("%s: %v, want %q", raw, err, message)
		}
	}
}

func TestEveryPolicysTransportsApply(t *testing.T) {
	compose := func(org, key string) *Config {
		t.Helper()
		config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, org)}, {Scope: KeyScope, Value: ruleSource(t, key)}})
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	config := compose(`{"access":{"transports":{"allow":["e2ee","attested_tls","https"],"deny":["https"]}}}`, `{"access":{"transports":{"allow":["https","e2ee"]}}}`)
	if lists := config.Access.Transports; !slices.Equal(lists.Allow, []string{TransportHTTPS, TransportE2EE}) || !slices.Equal(lists.Deny, []string{TransportHTTPS}) {
		t.Fatalf("combined transports %+v", lists)
	}
	for index, admitted := range [3]bool{false, false, true} {
		if config.TransportDenied(transports[index]) == admitted {
			t.Errorf("%s admitted=%v", transports[index], !admitted)
		}
	}

	// Allow lists that share no mode admit no request, and the empty list
	// stays a restriction when the configuration is shown.
	none := compose(`{"access":{"transports":{"allow":["https"]}}}`, `{"access":{"transports":{"allow":["e2ee"]}}}`)
	for _, transport := range transports {
		if !none.TransportDenied(transport) {
			t.Errorf("disjoint lists admitted %s", transport)
		}
	}
	raw, err := json.Marshal(none.Access)
	if err != nil || string(raw) != `{"transports":{"allow":[]}}` {
		t.Fatalf("combined access %s %v", raw, err)
	}
}

func TestDefaultTransportsYieldOnlyToRequiredTransports(t *testing.T) {
	org := ruleSource(t, `{"rules":{"sealed":{"mode":"default","access":{"transports":{"deny":["https"]}}}}}`)
	for key, admitted := range map[string][3]bool{
		// A network list is another setting, so the default modes still apply.
		`{"access":{"networks":{"allow":["0.0.0.0/0","::/0"]}}}`: {false, true, true},
		`{"access":{"transports":{"allow":["https","e2ee"]}}}`:   {true, false, true},
		// An empty deny list replaces the default without a restriction.
		`{"access":{"transports":{"deny":[]}}}`: {true, true, true},
	} {
		config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: ruleSource(t, key)}})
		if err != nil {
			t.Fatal(err)
		}
		active, err := config.Activate(ruleValues{})
		if err != nil {
			t.Fatal(err)
		}
		for index, transport := range transports {
			if active.TransportDenied(transport) == admitted[index] {
				t.Errorf("%s: %s admitted=%v", key, transport, !admitted[index])
			}
		}
	}
}
