package policy

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// How the client reached the gateway: ordinary TLS, TLS with the gateway's
// attestation evidence, or an end-to-end encrypted session. Request logs name
// the same modes.
const (
	TransportHTTPS       = "https"
	TransportAttestedTLS = "attested_tls"
	TransportE2EE        = "e2ee"
)

var transports = []string{TransportHTTPS, TransportAttestedTLS, TransportE2EE}

// Transports limits requests by their connection mode, as Networks limits them
// by where they come from.
type Transports struct {
	// Allow, when present, admits only requests over its modes. A composed
	// config holds the modes that every policy allows, so an empty list
	// admits none.
	Allow []string `json:"allow,omitzero"`
	// Deny refuses requests over its modes.
	Deny []string `json:"deny,omitzero"`
}

// Networks limits requests by where they come from. Both lists take
// addresses, CIDR ranges and onion, the clients of the onion service. A deny
// list also takes AS numbers, tor, vpn and hosting: networks that anyone can
// send from, so an allow list of them would not bound where a key works.
type Networks struct {
	// Allow, when present, admits only clients in its networks. A composed
	// config holds the networks that every policy allows, so an empty list
	// admits none.
	Allow []string `json:"allow,omitzero"`
	// Deny refuses clients in its networks.
	Deny []string `json:"deny,omitzero"`

	allow, deny networkSet
}

// Countries limits requests by the country that the gateway's lists place
// the client's address in. A client without an address, such as one of the
// onion service, and an address that the lists place nowhere are in no
// country.
type Countries struct {
	// Allow, when present, admits only clients in its countries. A composed
	// config holds the countries that every policy allows, so an empty list
	// admits none.
	Allow []string `json:"allow,omitzero"`
	// Deny refuses clients in its countries.
	Deny []string `json:"deny,omitzero"`
}

// Client is where a request came from, with what the gateway's network lists
// say about its address.
type Client struct {
	// Address is invalid for a client of the onion service, which reaches the
	// gateway through its relay and has no address of its own.
	Address netip.Addr
	Onion   bool
	// Country is the ISO 3166-1 code of the address, or empty.
	Country string
	// AS is the number of the autonomous system that announces the address,
	// or 0.
	AS uint32
	// TorExit is an address of a Tor exit relay. VPN and Hosting are
	// addresses of the networks of VPN providers and of hosting providers.
	TorExit, VPN, Hosting bool
	// Missing holds the lists that the gateway has not loaded, which leave
	// their facts unknown.
	Missing NetworkLists
}

// NetworkLists is a set of the gateway's lists of facts about addresses.
type NetworkLists uint8

const (
	CountryList NetworkLists = 1 << iota
	ASList
	TorExitList
	VPNList
	HostingList
)

// Refusal says why the access lists of a policy refuse a client.
type Refusal uint8

const (
	Admitted Refusal = iota
	// RefusedAddress refuses an address outside every allowed network or
	// inside a denied one, and a client whose address the gateway could not
	// read.
	RefusedAddress
	RefusedOnion
	RefusedAS
	RefusedTorExit
	RefusedVPN
	RefusedHosting
	RefusedCountry
	// ListsMissing means that a list the policy reads is not loaded, so the
	// gateway cannot tell whether the policy admits the client.
	ListsMissing
)

// The names that network lists take besides addresses, ranges and AS
// numbers, in the order that a composed list gives them.
var networkNames = []struct {
	name string
	kind networkKinds
}{{"tor", kindTor}, {"vpn", kindVPN}, {"hosting", kindHosting}, {"onion", kindOnion}}

type networkKinds uint8

const (
	kindOnion networkKinds = 1 << iota
	kindTor
	kindVPN
	kindHosting
)

// networkSet is a parsed network list. Its ranges are sorted and none holds
// another, so at most one holds an address: the last that starts at or
// before it.
type networkSet struct {
	ranges []netip.Prefix
	ases   []uint32
	kinds  networkKinds
}

// ClientRefusal returns why the access lists of the policies refuse the
// client, or Admitted. A refusal that the loaded lists prove comes before
// ListsMissing, so a client learns of a refusal that waiting would not lift.
func (c *Config) ClientRefusal(client Client) Refusal {
	if c == nil || c.Access == nil {
		return Admitted
	}
	refusal := Admitted
	if c.Access.Networks != nil {
		refusal = c.Access.Networks.refusal(client)
	}
	if refusal != Admitted && refusal != ListsMissing {
		return refusal
	}
	if countries := c.Access.Countries; countries != nil {
		if client.Address.IsValid() && client.Missing&CountryList != 0 {
			return ListsMissing
		}
		if !countries.admits(client.Country) {
			return RefusedCountry
		}
	}
	return refusal
}

// TransportDenied reports whether the policies refuse requests over the
// connection mode.
func (c *Config) TransportDenied(transport string) bool {
	return c != nil && c.Access != nil && c.Access.Transports != nil && !c.Access.Transports.admits(transport)
}

func (n *Networks) validate() error {
	if n == nil {
		return nil
	}
	if n.Allow == nil && n.Deny == nil {
		return configError("access.networks requires allow or deny")
	}
	// An empty deny list replaces a default and refuses nobody. An empty
	// allow list would refuse every client, which enabled already says.
	if n.Allow != nil && len(n.Allow) == 0 {
		return configError("access.networks.allow requires at least one entry")
	}
	var err error
	if n.allow, err = parseNetworks("allow", n.Allow); err != nil {
		return err
	}
	if n.deny, err = parseNetworks("deny", n.Deny); err != nil {
		return err
	}
	if n.Allow != nil && len(subtractNetworks(n.allow.ranges, n.deny.ranges)) == 0 && n.allow.kinds&^n.deny.kinds == 0 {
		return configError("access.networks.deny holds every network that allow lists")
	}
	return nil
}

// refusal returns why the lists refuse the client, or Admitted. Address
// ranges decide first, because they need no list of the gateway's.
func (n *Networks) refusal(client Client) Refusal {
	if client.Onion {
		if n.deny.kinds&kindOnion != 0 || n.Allow != nil && n.allow.kinds&kindOnion == 0 {
			return RefusedOnion
		}
		return Admitted
	}
	address := client.Address
	if !address.IsValid() {
		if n.Allow != nil || len(n.deny.ranges) > 0 || len(n.deny.ases) > 0 || n.deny.kinds != 0 {
			return RefusedAddress
		}
		return Admitted
	}
	if _, denied := networkHolding(n.deny.ranges, address); denied {
		return RefusedAddress
	}
	if n.Allow != nil {
		if _, ok := networkHolding(n.allow.ranges, address); !ok {
			return RefusedAddress
		}
	}
	if client.Missing&n.deny.lists() != 0 {
		return ListsMissing
	}
	_, deniedAS := slices.BinarySearch(n.deny.ases, client.AS)
	switch {
	case n.deny.kinds&kindTor != 0 && client.TorExit:
		return RefusedTorExit
	case deniedAS:
		return RefusedAS
	case n.deny.kinds&kindVPN != 0 && client.VPN:
		return RefusedVPN
	case n.deny.kinds&kindHosting != 0 && client.Hosting:
		return RefusedHosting
	}
	return Admitted
}

// lists returns the gateway's lists that the set reads.
func (s networkSet) lists() NetworkLists {
	var lists NetworkLists
	if len(s.ases) > 0 {
		lists |= ASList
	}
	if s.kinds&kindTor != 0 {
		lists |= TorExitList
	}
	if s.kinds&kindVPN != 0 {
		lists |= ASList | VPNList
	}
	if s.kinds&kindHosting != 0 {
		lists |= ASList | HostingList
	}
	return lists
}

// combine returns the networks of both lists: the networks that both allow
// and the networks that either denies.
func (n *Networks) combine(other *Networks) *Networks {
	if n == nil {
		return other
	}
	ases := slices.Concat(n.deny.ases, other.deny.ases)
	slices.Sort(ases)
	out := &Networks{allow: n.allow, deny: networkSet{
		ranges: disjointNetworks(slices.Concat(n.deny.ranges, other.deny.ranges)),
		ases:   slices.Compact(ases),
		kinds:  n.deny.kinds | other.deny.kinds,
	}}
	switch {
	case n.Allow == nil:
		out.allow = other.allow
	case other.Allow != nil:
		out.allow = networkSet{ranges: intersectNetworks(n.allow.ranges, other.allow.ranges), kinds: n.allow.kinds & other.allow.kinds}
	}
	// Allow and Deny stay nil where no policy set them, because an empty
	// allow list admits no client.
	if n.Allow != nil || other.Allow != nil {
		out.Allow = out.allow.strings()
	}
	if n.Deny != nil || other.Deny != nil {
		out.Deny = out.deny.strings()
	}
	return out
}

func (s networkSet) strings() []string {
	out := make([]string, 0, len(s.ranges)+len(s.ases)+len(networkNames))
	for _, network := range s.ranges {
		out = append(out, network.String())
	}
	for _, number := range s.ases {
		out = append(out, "AS"+strconv.FormatUint(uint64(number), 10))
	}
	for _, named := range networkNames {
		if s.kinds&named.kind != 0 {
			out = append(out, named.name)
		}
	}
	return out
}

// parseNetworks reads a network list. A range must name its first address,
// and an IPv4 network takes its IPv4 form, because the gateway reads an IPv4
// client in that form. An AS number takes the form AS64496.
func parseNetworks(list string, entries []string) (networkSet, error) {
	var set networkSet
	for _, entry := range entries {
		number, isAS := parseAS(entry)
		kind := networkKinds(0)
		for _, named := range networkNames {
			if entry == named.name {
				kind = named.kind
			}
		}
		if (isAS || kind != 0 && kind != kindOnion) && list == "allow" {
			return networkSet{}, configError("access.networks.allow has %q, which only deny lists take", entry)
		}
		if isAS && slices.Contains(set.ases, number) || set.kinds&kind != 0 {
			return networkSet{}, configError("access.networks.%s lists %s twice", list, entry)
		}
		if isAS {
			set.ases = append(set.ases, number)
			continue
		}
		if kind != 0 {
			set.kinds |= kind
			continue
		}
		network, err := parseNetwork(list, entry)
		if err != nil {
			return networkSet{}, err
		}
		if slices.Contains(set.ranges, network) {
			return networkSet{}, configError("access.networks.%s lists %s twice", list, network)
		}
		set.ranges = append(set.ranges, network)
	}
	slices.Sort(set.ases)
	set.ranges = disjointNetworks(set.ranges)
	return set, nil
}

func parseNetwork(list, entry string) (netip.Prefix, error) {
	var network netip.Prefix
	if strings.Contains(entry, "/") {
		parsed, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, invalidNetwork(list, entry)
		}
		network = parsed
	} else {
		address, err := netip.ParseAddr(entry)
		if err != nil || address.Zone() != "" {
			return netip.Prefix{}, invalidNetwork(list, entry)
		}
		network = netip.PrefixFrom(address, address.BitLen())
	}
	if network.Addr().Is4In6() {
		return netip.Prefix{}, configError("access.networks.%s has %q, which must use its IPv4 form", list, entry)
	}
	if network != network.Masked() {
		return netip.Prefix{}, configError("access.networks.%s has %q, which must start at %s", list, entry, network.Masked())
	}
	return network, nil
}

func invalidNetwork(list, entry string) error {
	if list == "allow" {
		return configError("access.networks.allow has %q, which is not an IP address, CIDR range or onion", entry)
	}
	return configError("access.networks.deny has %q, which is not an IP address, CIDR range, AS number, onion, tor, vpn or hosting", entry)
}

// parseAS reads an AS number in the form AS64496. AS0 is reserved, and no
// number has a leading zero.
func parseAS(entry string) (uint32, bool) {
	digits, ok := strings.CutPrefix(entry, "AS")
	if !ok || digits == "" || digits[0] == '0' {
		return 0, false
	}
	number, err := strconv.ParseUint(digits, 10, 32)
	return uint32(number), err == nil
}

// disjointNetworks sorts networks and drops each one inside another. Two CIDR
// ranges either nest or do not overlap.
func disjointNetworks(networks []netip.Prefix) []netip.Prefix {
	slices.SortFunc(networks, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	})
	out := networks[:0]
	for _, network := range networks {
		if len(out) == 0 || !out[len(out)-1].Overlaps(network) {
			out = append(out, network)
		}
	}
	return slices.Clip(out)
}

// networkHolding returns the network of disjoint, sorted networks that holds
// address.
func networkHolding(networks []netip.Prefix, address netip.Addr) (netip.Prefix, bool) {
	index, found := slices.BinarySearchFunc(networks, address, func(network netip.Prefix, address netip.Addr) int {
		return network.Addr().Compare(address)
	})
	if found {
		return networks[index], true
	}
	if index > 0 && networks[index-1].Contains(address) {
		return networks[index-1], true
	}
	return netip.Prefix{}, false
}

// intersectNetworks returns the addresses in both disjoint, sorted lists: each
// range of one list that lies inside a range of the other.
func intersectNetworks(a, b []netip.Prefix) []netip.Prefix {
	out := []netip.Prefix{}
	for _, pair := range [2][2][]netip.Prefix{{a, b}, {b, a}} {
		for _, network := range pair[0] {
			if outer, ok := networkHolding(pair[1], network.Addr()); ok && outer.Bits() <= network.Bits() {
				out = append(out, network)
			}
		}
	}
	return disjointNetworks(out)
}

// subtractNetworks returns the ranges of a that no range of b holds. A range
// of b inside one of a leaves that one, since part of it stays.
func subtractNetworks(a, b []netip.Prefix) []netip.Prefix {
	out := []netip.Prefix{}
	for _, network := range a {
		if outer, ok := networkHolding(b, network.Addr()); !ok || outer.Bits() > network.Bits() {
			out = append(out, network)
		}
	}
	return out
}

// validate reads the lists of countries as Networks.validate reads networks.
func (c *Countries) validate() error {
	if c == nil {
		return nil
	}
	if c.Allow == nil && c.Deny == nil {
		return configError("access.countries requires allow or deny")
	}
	if c.Allow != nil && len(c.Allow) == 0 {
		return configError("access.countries.allow requires at least one country")
	}
	for _, list := range [2]struct {
		name  string
		codes []string
	}{{"allow", c.Allow}, {"deny", c.Deny}} {
		for index, code := range list.codes {
			if _, ok := slices.BinarySearch(countryCodes, code); !ok {
				return configError("access.countries.%s has %q, which is not an ISO 3166-1 alpha-2 country code", list.name, code)
			}
			if slices.Contains(list.codes[:index], code) {
				return configError("access.countries.%s lists %s twice", list.name, code)
			}
		}
	}
	if c.Allow != nil && !slices.ContainsFunc(c.Allow, c.admits) {
		return configError("access.countries.deny holds every country that allow lists")
	}
	return nil
}

// admits reports whether the lists accept a client in the country, which is
// empty for a client in none.
func (c *Countries) admits(country string) bool {
	return (c.Allow == nil || slices.Contains(c.Allow, country)) && !slices.Contains(c.Deny, country)
}

// combine returns the countries that both allow and the countries that either
// denies, in alphabetical order.
func (c *Countries) combine(other *Countries) *Countries {
	if c == nil {
		return other
	}
	out := &Countries{}
	switch {
	case c.Allow == nil:
		out.Allow = slices.Clone(other.Allow)
	case other.Allow == nil:
		out.Allow = slices.Clone(c.Allow)
	default:
		out.Allow = []string{}
		for _, code := range c.Allow {
			if slices.Contains(other.Allow, code) {
				out.Allow = append(out.Allow, code)
			}
		}
	}
	if c.Deny != nil || other.Deny != nil {
		out.Deny = slices.Compact(slices.Sorted(slices.Values(slices.Concat(c.Deny, other.Deny))))
	}
	slices.Sort(out.Allow)
	return out
}

// countryCodes are the ISO 3166-1 alpha-2 codes, with XK for Kosovo, as the
// gateway's country list uses them.
var countryCodes = strings.Fields(`
	AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS
	BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE
	EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM
	HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC
	LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA
	NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
	SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO
	TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW`)

// CountryCode reports whether code is one that access.countries takes.
func CountryCode(code string) bool {
	_, ok := slices.BinarySearch(countryCodes, code)
	return ok
}

// validate reads the lists of connection modes as Networks.validate reads
// networks. An empty deny list replaces a default and refuses nothing, and a
// deny list of every mode, as a default, refuses requests until a nearer
// scope sets its own lists. An allow list that admits nothing would refuse
// every request, which disabling the resource already says.
func (t *Transports) validate() error {
	if t == nil {
		return nil
	}
	if t.Allow == nil && t.Deny == nil {
		return configError("access.transports requires allow or deny")
	}
	if t.Allow != nil && len(t.Allow) == 0 {
		return configError("access.transports.allow requires at least one connection mode")
	}
	if err := validateModes("allow", t.Allow); err != nil {
		return err
	}
	if err := validateModes("deny", t.Deny); err != nil {
		return err
	}
	if t.Allow != nil && !slices.ContainsFunc(t.Allow, t.admits) {
		return configError("access.transports.deny holds every mode that allow lists")
	}
	return nil
}

func validateModes(list string, modes []string) error {
	for index, mode := range modes {
		if !slices.Contains(transports, mode) {
			return configError("access.transports.%s has %q, which is not https, attested_tls or e2ee", list, mode)
		}
		if slices.Contains(modes[:index], mode) {
			return configError("access.transports.%s lists %s twice", list, mode)
		}
	}
	return nil
}

// admits reports whether the lists accept requests over the mode.
func (t *Transports) admits(mode string) bool {
	return (t.Allow == nil || slices.Contains(t.Allow, mode)) && !slices.Contains(t.Deny, mode)
}

// combine returns the modes that both allow and the modes that either denies,
// in a fixed order.
func (t *Transports) combine(other *Transports) *Transports {
	if t == nil {
		return other
	}
	out := &Transports{}
	if t.Allow != nil || other.Allow != nil {
		out.Allow = []string{}
	}
	if t.Deny != nil || other.Deny != nil {
		out.Deny = []string{}
	}
	for _, mode := range transports {
		if out.Allow != nil && (t.Allow == nil || slices.Contains(t.Allow, mode)) && (other.Allow == nil || slices.Contains(other.Allow, mode)) {
			out.Allow = append(out.Allow, mode)
		}
		if slices.Contains(t.Deny, mode) || slices.Contains(other.Deny, mode) {
			out.Deny = append(out.Deny, mode)
		}
	}
	return out
}
