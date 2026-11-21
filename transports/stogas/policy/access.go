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

// Lists admits a value that allow, when present, lists and that deny does not.
// Countries, connection modes and each kind of catalog ID use them. A composed
// config holds the values that every policy allows, so an empty allow list
// admits none, and the values that any policy denies.
type Lists struct {
	Allow []string `json:"allow,omitzero"`
	Deny  []string `json:"deny,omitzero"`
	// sorted marks lists that validation or composition put in order, so a
	// lookup searches them instead of reading every value.
	sorted bool
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
	return c != nil && c.Access != nil && !c.Access.Transports.admits(transport)
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

// combineNetworks returns the networks that every list allows and the
// networks that any denies. A chain's lists can hold several hundred thousand
// entries together, so they join in one pass.
func combineNetworks(lists []*Networks) *Networks {
	switch len(lists) {
	case 0:
		return nil
	case 1:
		return lists[0]
	}
	out := &Networks{}
	var ranges []netip.Prefix
	var ases []uint32
	allows, denies := false, false
	for _, list := range lists {
		ranges = append(ranges, list.deny.ranges...)
		ases = append(ases, list.deny.ases...)
		out.deny.kinds |= list.deny.kinds
		denies = denies || list.Deny != nil
		switch {
		case list.Allow == nil:
		case !allows:
			out.allow, allows = list.allow, true
		default:
			out.allow = networkSet{ranges: intersectNetworks(out.allow.ranges, list.allow.ranges), kinds: out.allow.kinds & list.allow.kinds}
		}
	}
	slices.Sort(ases)
	out.deny.ranges, out.deny.ases = disjointNetworks(ranges), slices.Compact(ases)
	// Allow and Deny stay nil where no policy set them, because an empty
	// allow list admits no client.
	if allows {
		out.Allow = out.allow.strings()
	}
	if denies {
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
	ases, ranges := map[uint32]bool{}, map[netip.Prefix]bool{}
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
		if isAS && ases[number] || set.kinds&kind != 0 {
			return networkSet{}, configError("access.networks.%s lists %s twice", list, entry)
		}
		if isAS {
			set.ases, ases[number] = append(set.ases, number), true
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
		if ranges[network] {
			return networkSet{}, configError("access.networks.%s lists %s twice", list, network)
		}
		set.ranges, ranges[network] = append(set.ranges, network), true
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

// validate checks the lists of a setting, whose entries are each a noun that
// valid accepts and that expected describes. An empty deny list replaces a
// default and refuses nothing, and a deny list of every value, as a default,
// refuses until a nearer scope sets its own lists. An allow list that admits
// nothing would refuse every request, which disabling the resource already
// says. Valid lists are left sorted.
func (l *Lists) validate(setting, noun, expected string, valid func(string) bool) error {
	if l == nil {
		return nil
	}
	if l.Allow == nil && l.Deny == nil {
		return configError("%s requires allow or deny", setting)
	}
	if l.Allow != nil && len(l.Allow) == 0 {
		return configError("%s.allow requires at least one %s", setting, noun)
	}
	for _, list := range [2]struct {
		name   string
		values []string
	}{{"allow", l.Allow}, {"deny", l.Deny}} {
		for _, value := range list.values {
			if !valid(value) {
				return configError("%s.%s has %q, which is not %s", setting, list.name, value, expected)
			}
		}
		// A list holds up to a whole source of values, so order finds a repeat
		// without comparing every pair.
		slices.Sort(list.values)
		for index := 1; index < len(list.values); index++ {
			if list.values[index] == list.values[index-1] {
				return configError("%s.%s lists %s twice", setting, list.name, list.values[index])
			}
		}
	}
	l.sorted = true
	if l.Allow != nil && !slices.ContainsFunc(l.Allow, l.admits) {
		return configError("%s.deny holds every %s that allow lists", setting, noun)
	}
	return nil
}

// admits reports whether the lists accept value. Absent lists accept every
// value, and a country of a client in none is empty.
func (l *Lists) admits(value string) bool {
	return l == nil || (l.Allow == nil || l.holds(l.Allow, value)) && !l.holds(l.Deny, value)
}

func (l *Lists) holds(list []string, value string) bool {
	if l.sorted {
		_, found := slices.BinarySearch(list, value)
		return found
	}
	return slices.Contains(list, value)
}

// inOrder returns the lists sorted, which every compiled source's lists are.
// An empty allow list, which admits nothing, stays one.
func (l *Lists) inOrder() *Lists {
	if l.sorted {
		return l
	}
	out := &Lists{Allow: slices.Clone(l.Allow), Deny: slices.Clone(l.Deny), sorted: true}
	slices.Sort(out.Allow)
	slices.Sort(out.Deny)
	return out
}

// combineLists returns the values that every list allows and the values that
// any denies, in order. A chain's lists can hold several hundred thousand
// values together, so they join in one pass.
func combineLists(lists []*Lists) *Lists {
	switch len(lists) {
	case 0:
		return nil
	case 1:
		return lists[0]
	}
	out := &Lists{sorted: true}
	for _, list := range lists {
		list = list.inOrder()
		if list.Deny != nil {
			out.Deny = append(out.Deny, list.Deny...)
		}
		switch {
		case list.Allow == nil:
		case out.Allow == nil:
			out.Allow = list.Allow
		default:
			shared := []string{}
			for i, j := 0, 0; i < len(out.Allow) && j < len(list.Allow); {
				switch order := strings.Compare(out.Allow[i], list.Allow[j]); {
				case order < 0:
					i++
				case order > 0:
					j++
				default:
					shared = append(shared, out.Allow[i])
					i, j = i+1, j+1
				}
			}
			out.Allow = shared
		}
	}
	if out.Deny != nil {
		slices.Sort(out.Deny)
		out.Deny = slices.Compact(out.Deny)
	}
	return out
}
