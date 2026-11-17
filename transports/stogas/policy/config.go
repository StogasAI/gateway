package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"mime"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/maximhq/bifrost/transports/stogas/inputfiles/filetype"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

const (
	CompilerVersion   = 1
	MaxCompiledBytes  = 512 << 10
	MaxSorts          = 4
	MaxRetries        = 3
	MaxFallbacks      = 2
	DefaultFallbacks  = 2
	MaxRequestTimeout = time.Hour
	// Without a policy value only the total limit applies. Models reason for
	// minutes without output, and expiry neither stops nor refunds the call.
	DefaultOutputIdleTimeout = MaxRequestTimeout
	MaxCustomPatterns        = 3
	MaxCustomPatternBytes    = 512
)

// routing.missingEncryptionKeys decides what a candidate does when its
// content needs an encryption key that the request did not send: fail the
// request, the default, or skip only that candidate.
const (
	MissingKeysFail = "fail"
	MissingKeysSkip = "skip"
)

var (
	ErrInvalidConfig = errors.New("invalid compiled API key configuration")
	redactionPresets = stringSet(
		"email_address",
		"phone_number",
		"social_security_number",
		"credit_card_number",
		"ip_address",
		"api_keys_and_secrets",
		"bank_identifiers",
		"national_identifiers",
		"health_identifiers",
	)
	nodeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	// The contract's timeZoneSchema: only UTC and Area/Location names mean the same zone everywhere
	// a policy is read. LoadLocation alone would also take Local, an empty name and abbreviations.
	timeZonePattern = regexp.MustCompile(`^(?:UTC|[A-Z][A-Za-z]*(?:/[A-Za-z0-9_+-]+)+)$`)
)

type Config struct {
	ActiveRules            []RuleMatch        `json:"-"`
	ActiveEncryptedPlugins []EncryptedPlugins `json:"-"`
	sources                []ScopedSource
	hasRules               bool
	activated              bool
	requiredSettings       Permission
	sortOrigins            []Origin
	requiredSorts          int
	RequiredEncryptionKeys []string          `json:"-"`
	PluginSources          []*Plugins        `json:"-"`
	Access                 *Access           `json:"access"`
	Input                  *Input            `json:"input,omitempty"`
	Timeouts               *Timeouts         `json:"timeouts,omitempty"`
	CompilerVersion        int               `json:"compilerVersion"`
	Plugins                *Plugins          `json:"plugins"`
	Routing                Routing           `json:"routing"`
	RequestPermission      RequestPermission `json:"requestPermission"`
	Schema                 string            `json:"schema"`
}

type Input struct {
	ASCIIOnly  bool        `json:"asciiOnly,omitzero"`
	MediaTypes *MediaTypes `json:"mediaTypes,omitempty"`
}

// MaxMediaTypes is how many entries a media type list holds.
const MaxMediaTypes = 64

// MediaTypes limits attachments by media type. An entry is a media type, such as image/png, or
// every type of a class, such as image/*.
type MediaTypes struct {
	// Allow, when present, admits only attachments of its types: an empty list admits none.
	Allow []string `json:"allow,omitzero"`
	// Deny refuses attachments of its types.
	Deny []string `json:"deny,omitzero"`
}

// applies reports whether the input section checks anything.
func (in *Input) applies() bool {
	return in != nil && (in.ASCIIOnly || in.MediaTypes != nil)
}

func (in *Input) validate() error {
	if in == nil || in.MediaTypes == nil {
		return nil
	}
	types := in.MediaTypes
	if types.Allow == nil && types.Deny == nil {
		return configError("input.mediaTypes requires allow or deny")
	}
	for _, list := range []struct {
		name   string
		values []string
	}{{"allow", types.Allow}, {"deny", types.Deny}} {
		if len(list.values) > MaxMediaTypes {
			return configError("input.mediaTypes.%s lists at most %d types", list.name, MaxMediaTypes)
		}
		seen := map[string]bool{}
		for _, value := range list.values {
			if !validMediaTypePattern(value) {
				return configError("input.mediaTypes.%s has %q, which is not a lowercase media type such as image/png or class such as image/*", list.name, value)
			}
			if seen[value] {
				return configError("input.mediaTypes.%s lists %q twice", list.name, value)
			}
			seen[value] = true
		}
	}
	return nil
}

func validMediaTypePattern(value string) bool {
	class, subtype, ok := strings.Cut(value, "/")
	if !ok || len(value) > 255 || value != strings.ToLower(value) || class == "*" {
		return false
	}
	if subtype == "*" {
		value = class + "/x"
	}
	parsed, params, err := mime.ParseMediaType(value)
	return err == nil && len(params) == 0 && parsed == value
}

// mediaTypeMatches reports whether a type or class pattern takes value, which may itself be a
// class such as image/*.
func mediaTypeMatches(pattern, value string) bool {
	return pattern == value || strings.HasSuffix(pattern, "/*") && !strings.HasSuffix(value, "/*") && strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
}

// combine returns the checks of both sections: ASCII where either requires it, the types that
// both allow, and the types that either denies.
func (in *Input) combine(other *Input) *Input {
	if in == nil {
		in = &Input{}
	}
	out := &Input{ASCIIOnly: in.ASCIIOnly || other.ASCIIOnly, MediaTypes: in.MediaTypes}
	if other.MediaTypes == nil {
		return out
	}
	if out.MediaTypes == nil {
		out.MediaTypes = other.MediaTypes
		return out
	}
	a, b := out.MediaTypes, other.MediaTypes
	combined := &MediaTypes{Allow: a.Allow, Deny: sortedUnion(a.Deny, b.Deny)}
	switch {
	case a.Allow == nil:
		combined.Allow = b.Allow
	case b.Allow != nil:
		combined.Allow = []string{}
		for _, x := range a.Allow {
			for _, y := range b.Allow {
				switch {
				case mediaTypeMatches(x, y):
					combined.Allow = append(combined.Allow, y)
				case mediaTypeMatches(y, x):
					combined.Allow = append(combined.Allow, x)
				}
			}
		}
		combined.Allow = sortedUnion(combined.Allow, nil)
	}
	out.MediaTypes = combined
	return out
}

func sortedUnion(a, b []string) []string {
	if a == nil && b == nil {
		return nil
	}
	out := append(append([]string{}, a...), b...)
	sort.Strings(out)
	return slices.Compact(out)
}

// Refuses reports whether the media types refuse an attachment whose class, such as image, and
// full type, such as image/png, are known as far as they are: an empty type is unknown. An
// attachment whose type is unknown is refused wherever its type could decide.
func (m *MediaTypes) Refuses(class, value string) bool {
	if m == nil {
		return false
	}
	could := func(pattern string) bool {
		switch {
		case value != "":
			return mediaTypeMatches(pattern, value)
		case class != "":
			return strings.HasPrefix(pattern, class+"/")
		}
		return true
	}
	for _, pattern := range m.Deny {
		if could(pattern) {
			return true
		}
	}
	if m.Allow == nil {
		return false
	}
	for _, pattern := range m.Allow {
		if value != "" && mediaTypeMatches(pattern, value) || value == "" && class != "" && pattern == class+"/*" {
			return false
		}
	}
	return true
}

type Timeouts struct {
	TotalSeconds      *int `json:"totalSeconds,omitempty"`
	OutputIdleSeconds *int `json:"outputIdleSeconds,omitempty"`
}

func (t *Timeouts) Total() time.Duration {
	if t == nil || t.TotalSeconds == nil {
		return MaxRequestTimeout
	}
	return time.Duration(*t.TotalSeconds) * time.Second
}

func (t *Timeouts) OutputIdle() time.Duration {
	if t == nil || t.OutputIdleSeconds == nil {
		return DefaultOutputIdleTimeout
	}
	return time.Duration(*t.OutputIdleSeconds) * time.Second
}

// Retries repeat a call to the same deployment and credential. Fallbacks move
// to the next pair in routing order, so a request calls at most three pairs.
// Query sorts candidates. Sorting never adds a deployment that selectors,
// filters or credentials exclude.
// MissingEncryptionKeys is empty when no policy sets it, which fails.
type Routing struct {
	AllowedCatalogNodes   *AllowedCatalogNodes `json:"allowedCatalogNodes"`
	Fallbacks             int                  `json:"fallbacks"`
	MissingEncryptionKeys string               `json:"missingEncryptionKeys,omitempty"`
	Query                 *Query               `json:"query"`
	Retries               int                  `json:"retries"`
}

// SkipsMissingKeys reports whether a candidate whose encryption key the
// request did not send leaves only itself out.
func (r Routing) SkipsMissingKeys() bool { return r.MissingEncryptionKeys == MissingKeysSkip }

type AllowedCatalogNodes struct {
	Authors     []string `json:"authors,omitzero"`
	Deployments []string `json:"deployments,omitzero"`
	Models      []string `json:"models,omitzero"`
	Providers   []string `json:"providers,omitzero"`
	Routes      []string `json:"routes,omitzero"`
}

type Access struct {
	Schedule *Schedule `json:"schedule,omitempty"`
	Networks *Networks `json:"networks,omitempty"`
}

// Schedule refuses requests during weekly periods. It has no allow list,
// because periods in several time zones have no common form to intersect in,
// so the allow lists of several policies could not combine into one.
type Schedule struct {
	Deny []DenyWindow `json:"deny,omitzero"`
}

// Networks limits requests by the client's address. An entry is an address or
// a CIDR range.
type Networks struct {
	// Allow, when present, admits only clients in its networks. A composed
	// config holds the networks that every policy allows, so an empty list
	// admits none.
	Allow []string `json:"allow,omitzero"`
	// Deny refuses clients in its networks.
	Deny []string `json:"deny,omitzero"`

	// allow and deny are the parsed entries, sorted and without one inside
	// another, so at most one can hold an address: the last that starts at or
	// before it.
	allow, deny []netip.Prefix
}

type DenyWindow struct {
	Days     []string `json:"days"`
	End      string   `json:"end"`
	Start    string   `json:"start"`
	TimeZone string   `json:"timeZone"`

	endMinute   int
	location    *time.Location
	startMinute int
	weekdays    map[time.Weekday]bool
}

type Plugins struct {
	Export         *exportconfig.Config `json:"export,omitempty"`
	Redaction      *Redaction           `json:"redaction,omitempty"`
	TextExtraction TextExtraction       `json:"textExtraction,omitempty"`
}

// TextExtraction maps a kind of file to its text extraction mode. A key is a family of files,
// text, office or pdf, or one media type that a family holds, such as text/csv, whose mode then
// decides for its files in place of the family's. A file that no key takes is not set, so a
// later family never applies to a policy that does not name it.
type TextExtraction map[string]string

// Text extraction modes, from the weakest to the strongest: a policy that sets a stronger one
// for a file overrides a weaker one, and off applies to a file that no policy sets.
const (
	// TextExtractionOff sends the file as a file, which only a deployment that reads it takes.
	TextExtractionOff = "off"
	// TextExtractionAuto turns a file into prompt text where the deployment does not read it,
	// or where input checks or redaction must read it.
	TextExtractionAuto = "auto"
	// TextExtractionAlways turns the file into prompt text.
	TextExtractionAlways = "always"
)

var textExtractionModes = []string{TextExtractionOff, TextExtractionAuto, TextExtractionAlways}

// strongerTextExtraction returns the stronger of two modes, where "" is none.
func strongerTextExtraction(a, b string) string {
	if slices.Index(textExtractionModes, b) > slices.Index(textExtractionModes, a) {
		return b
	}
	return a
}

// textExtractionUnits are the families of text extraction. Each combines on its own, so a
// requirement for one family leaves the default of another in place. A media type is a setting
// of its family.
const textExtractionUnits = permissionTextExtraction | permissionOfficeExtraction | permissionPDFExtraction

var textExtractionFamilyUnits = map[filetype.Family]Permission{
	filetype.Text:   permissionTextExtraction,
	filetype.Office: permissionOfficeExtraction,
	filetype.PDF:    permissionPDFExtraction,
}

// textExtractionFamily names the family that a key is or belongs to, or "" for a key that text
// extraction does not read.
func textExtractionFamily(key string) filetype.Family {
	if family := filetype.Family(key); textExtractionFamilyUnits[family] != 0 {
		return family
	}
	if !validMediaTypePattern(key) || strings.HasSuffix(key, "/*") {
		return ""
	}
	return filetype.FamilyOf(key)
}

// textExtractionUnit returns the unit of a key's family.
func textExtractionUnit(key string) Permission {
	return textExtractionFamilyUnits[textExtractionFamily(key)]
}

// set returns the mode that these settings alone give the files of a key: the key's own mode,
// or for a media type the mode of its family.
func (t TextExtraction) set(key string) (string, bool) {
	mode, ok := t[key]
	if !ok {
		if family := string(textExtractionFamily(key)); family != key {
			mode, ok = t[family]
		}
	}
	return mode, ok
}

// Mode returns the mode of a file, or TextExtractionOff where nothing sets one: the gateway
// changes no file unless a policy says so.
func (t TextExtraction) Mode(file filetype.Type) string {
	if mode, ok := t[file.MediaType]; ok {
		return mode
	}
	if mode, ok := t[string(file.Family)]; ok {
		return mode
	}
	return TextExtractionOff
}

// Extracts reports whether a file becomes prompt text wherever its deployment does not read it.
func (t TextExtraction) Extracts(file filetype.Type) bool {
	return file.Family != "" && t.Mode(file) != TextExtractionOff
}

func (t TextExtraction) units() Permission {
	var units Permission
	for key := range t {
		units |= textExtractionUnit(key)
	}
	return units
}

func (t TextExtraction) validate() error {
	if len(t) == 0 {
		return configError("plugins.textExtraction must set the mode of text, office, pdf or a media type")
	}
	for _, key := range slices.Sorted(maps.Keys(t)) {
		if textExtractionFamily(key) == "" {
			return configError("plugins.textExtraction has %q, which is not text, office, pdf or a media type that text extraction reads, such as text/csv", key)
		}
		if !slices.Contains(textExtractionModes, t[key]) {
			return configError("plugins.textExtraction.%s must be off, auto or always", key)
		}
	}
	return nil
}

type Redaction struct {
	digestOnce     sync.Once
	digest         [32]byte
	CustomPatterns []string            `json:"customPatterns,omitempty"`
	Presets        []string            `json:"presets"`
	Literals       []redaction.Literal `json:"literals,omitempty"`
}

// pluginUnits are the plugins that combine on their own: a required plugin
// setting replaces only the defaults of the same plugin.
const pluginUnits = permissionRedaction | textExtractionUnits | permissionExport

func (p *Plugins) units() Permission {
	var units Permission
	if p != nil && p.Redaction != nil {
		units |= permissionRedaction
	}
	if p != nil {
		units |= p.TextExtraction.units()
	}
	if p != nil && p.Export != nil {
		units |= permissionExport
	}
	return units
}

// only returns the plugins among units, sharing their settings, or nil when
// none of them is set.
func (p *Plugins) only(units Permission) *Plugins {
	set := p.units()
	if set&units == 0 {
		return nil
	}
	if set&^units == 0 {
		return p
	}
	part := &Plugins{}
	if units&permissionRedaction != 0 {
		part.Redaction = p.Redaction
	}
	if units&set&textExtractionUnits != 0 {
		part.TextExtraction = TextExtraction{}
		for key, mode := range p.TextExtraction {
			if units&textExtractionUnit(key) != 0 {
				part.TextExtraction[key] = mode
			}
		}
	}
	if units&permissionExport != 0 {
		part.Export = p.Export
	}
	return part
}

func (c *Config) validate() error {
	if c == nil || c.Schema != "stogas.key-config.compiled.v1" || c.CompilerVersion != CompilerVersion {
		return configError("unsupported schema or compiler version")
	}
	if c.Routing.Retries < 0 || c.Routing.Retries > MaxRetries {
		return configError("routing.retries must be an integer from 0 to 3")
	}
	if c.Routing.Fallbacks < 0 || c.Routing.Fallbacks > MaxFallbacks {
		return configError("routing.fallbacks must be an integer from 0 to 2")
	}
	if value := c.Routing.MissingEncryptionKeys; value != "" && value != MissingKeysFail && value != MissingKeysSkip {
		return configError("routing.missingEncryptionKeys must be fail or skip")
	}
	if c.Timeouts != nil {
		for _, field := range []struct {
			name  string
			value *int
		}{{"totalSeconds", c.Timeouts.TotalSeconds}, {"outputIdleSeconds", c.Timeouts.OutputIdleSeconds}} {
			if field.value != nil && (*field.value < 1 || *field.value > int(MaxRequestTimeout/time.Second)) {
				return configError("timeouts.%s must be an integer from 1 to 3600", field.name)
			}
		}
	}
	if err := c.Routing.AllowedCatalogNodes.validate(); err != nil {
		return err
	}
	if err := c.Routing.Query.validate(); err != nil {
		return err
	}

	if err := c.Access.validate(); err != nil {
		return err
	}
	if err := c.Input.validate(); err != nil {
		return err
	}
	if err := c.Plugins.validate(); err != nil {
		return err
	}
	return nil
}

func (a *AllowedCatalogNodes) validate() error {
	if a == nil {
		return nil
	}
	lists := [][]string{a.Authors, a.Deployments, a.Models, a.Providers, a.Routes}
	for _, values := range lists {
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if !nodeIDPattern.MatchString(value) {
				return configError("allowed catalog node ID is invalid")
			}
			if _, exists := seen[value]; exists {
				return configError("allowed catalog node IDs are not unique")
			}
			seen[value] = struct{}{}
		}
	}
	return nil
}

// validateNodeIDs requires a nonempty list of unique, well formed catalog IDs.
func validateNodeIDs(ids []string) error {
	if len(ids) == 0 {
		return configError("a catalog ID list must not be empty")
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !nodeIDPattern.MatchString(id) || seen[id] {
			return configError("catalog IDs must be valid and unique")
		}
		seen[id] = true
	}
	return nil
}

func (a *Access) validate() error {
	if a == nil {
		return nil
	}
	if a.Schedule == nil && a.Networks == nil {
		return configError("access requires schedule or networks")
	}
	if err := a.Networks.validate(); err != nil {
		return err
	}
	if a.Schedule == nil {
		return nil
	}
	// An empty list is the neutral value that replaces a default.
	if a.Schedule.Deny == nil {
		return configError("access.schedule requires deny")
	}
	locations := make(map[string]*time.Location)
	for index := range a.Schedule.Deny {
		if err := a.Schedule.Deny[index].validate(locations); err != nil {
			return err
		}
	}
	return nil
}

// denyPeriods returns the periods of the schedule, if any.
func (a *Access) denyPeriods() []DenyWindow {
	if a == nil || a.Schedule == nil {
		return nil
	}
	return a.Schedule.Deny
}

func (w *DenyWindow) validate(locations map[string]*time.Location) error {
	if w == nil || len(w.Days) == 0 || len(w.Days) > 7 {
		return configError("deny window days are invalid")
	}
	start, ok := clockMinute(w.Start)
	if !ok {
		return configError("deny window start is invalid")
	}
	end, ok := clockEndMinute(w.End)
	if !ok || start >= end {
		return configError("deny window end is invalid")
	}
	if len(w.TimeZone) > 64 || !timeZonePattern.MatchString(w.TimeZone) {
		return configError("deny window time zone is invalid")
	}
	location := locations[w.TimeZone]
	if location == nil {
		var err error
		location, err = time.LoadLocation(w.TimeZone)
		if err != nil {
			return configError("deny window time zone is invalid")
		}
		locations[w.TimeZone] = location
	}
	weekdays := make(map[time.Weekday]bool, len(w.Days))
	for _, day := range w.Days {
		weekday, ok := policyWeekday(day)
		if !ok || weekdays[weekday] {
			return configError("deny window days are invalid")
		}
		weekdays[weekday] = true
	}
	w.startMinute = start
	w.endMinute = end
	w.location = location
	w.weekdays = weekdays
	return nil
}

func (p *Plugins) validate() error {
	if p != nil {
		if err := p.Export.Validate(); err != nil {
			return configError("invalid export configuration")
		}
		if p.TextExtraction != nil {
			if err := p.TextExtraction.validate(); err != nil {
				return err
			}
		}
	}
	if p == nil || p.Redaction == nil {
		if p == nil {
			return nil
		}
		if p.TextExtraction != nil || p.Export != nil {
			return nil
		}
		return configError("plugins require explicit configuration")
	}
	selected := p.Redaction
	if err := redaction.ValidateLiterals(selected.Literals); err != nil {
		return configError("invalid redaction literals")
	}
	if selected.Presets == nil {
		return configError("redaction presets are missing")
	}
	if len(selected.CustomPatterns) > MaxCustomPatterns {
		return configError("redaction custom pattern count is invalid")
	}
	seen := map[string]bool{}
	for _, pattern := range selected.Presets {
		if !redactionPresets[pattern] || seen[pattern] {
			return configError("redaction preset is invalid")
		}
		seen[pattern] = true
	}
	seen = map[string]bool{}
	for _, pattern := range selected.CustomPatterns {
		if pattern == "" || len(pattern) > MaxCustomPatternBytes || seen[pattern] {
			return configError("custom redaction pattern is invalid")
		}
		seen[pattern] = true
	}
	return nil
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
		return configError("access.networks.allow requires at least one address or range")
	}
	var err error
	if n.allow, err = parseNetworks("allow", n.Allow); err != nil {
		return err
	}
	if n.deny, err = parseNetworks("deny", n.Deny); err != nil {
		return err
	}
	if n.Allow != nil && len(subtractNetworks(n.allow, n.deny)) == 0 {
		return configError("access.networks.deny holds every network that allow lists")
	}
	return nil
}

// parseNetworks reads addresses and CIDR ranges. A range must name its first
// address, and an IPv4 network takes its IPv4 form, because the gateway reads
// an IPv4 client in that form.
func parseNetworks(list string, entries []string) ([]netip.Prefix, error) {
	networks := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		var network netip.Prefix
		if strings.Contains(entry, "/") {
			parsed, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, configError("access.networks.%s has %q, which is not an IP address or CIDR range", list, entry)
			}
			network = parsed
		} else {
			address, err := netip.ParseAddr(entry)
			if err != nil || address.Zone() != "" {
				return nil, configError("access.networks.%s has %q, which is not an IP address or CIDR range", list, entry)
			}
			network = netip.PrefixFrom(address, address.BitLen())
		}
		if network.Addr().Is4In6() {
			return nil, configError("access.networks.%s has %q, which must use its IPv4 form", list, entry)
		}
		if network != network.Masked() {
			return nil, configError("access.networks.%s has %q, which must start at %s", list, entry, network.Masked())
		}
		if slices.Contains(networks, network) {
			return nil, configError("access.networks.%s lists %s twice", list, network)
		}
		networks = append(networks, network)
	}
	return disjointNetworks(networks), nil
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

// combine returns the networks of both lists: the addresses that both allow
// and the addresses that either denies.
func (n *Networks) combine(other *Networks) *Networks {
	if n == nil {
		return other
	}
	out := &Networks{allow: n.allow, deny: disjointNetworks(slices.Concat(n.deny, other.deny))}
	switch {
	case n.Allow == nil:
		out.allow = other.allow
	case other.Allow != nil:
		out.allow = intersectNetworks(n.allow, other.allow)
	}
	// Allow and Deny stay nil where no policy set them, because an empty
	// allow list admits no client.
	if n.Allow != nil || other.Allow != nil {
		out.Allow = networkStrings(out.allow)
	}
	if n.Deny != nil || other.Deny != nil {
		out.Deny = networkStrings(out.deny)
	}
	return out
}

func networkStrings(networks []netip.Prefix) []string {
	out := make([]string, len(networks))
	for index, network := range networks {
		out[index] = network.String()
	}
	return out
}

// NetworkDenied reports whether the networks of the policies refuse the client
// address: one outside the networks that every policy allows, or inside one
// that a policy denies. The gateway reads an IPv4 client in its IPv4 form. A
// client without a known address, such as one of the onion service, could have
// any address: it is certainly inside only an allow list that holds 0.0.0.0/0
// and ::/0, and certainly outside only an empty deny list.
func (c *Config) NetworkDenied(client netip.Addr) bool {
	if c == nil || c.Access == nil || c.Access.Networks == nil {
		return false
	}
	networks := c.Access.Networks
	if !client.IsValid() {
		everyAddress := len(networks.allow) == 2 && networks.allow[0].Bits() == 0 && networks.allow[1].Bits() == 0
		return networks.Allow != nil && !everyAddress || len(networks.deny) > 0
	}
	client = client.Unmap()
	if networks.Allow != nil {
		if _, ok := networkHolding(networks.allow, client); !ok {
			return true
		}
	}
	_, denied := networkHolding(networks.deny, client)
	return denied
}

func (c *Config) DeniedAt(now time.Time) bool {
	if c == nil {
		return false
	}
	periods := c.Access.denyPeriods()
	for index := range periods {
		if periods[index].covers(now) {
			return true
		}
	}
	return false
}

func (w *DenyWindow) covers(now time.Time) bool {
	local := now.In(w.location)
	minute := local.Hour()*60 + local.Minute()
	return w.weekdays[local.Weekday()] && minute >= w.startMinute && minute < w.endMinute
}

func (a *AllowedCatalogNodes) Allows(authorID, modelID, deploymentID, routeID, providerID string) bool {
	if a == nil {
		return true
	}
	return allowedNode(a.Authors, authorID) &&
		allowedNode(a.Models, modelID) &&
		allowedNode(a.Deployments, deploymentID) &&
		allowedNode(a.Routes, routeID) &&
		allowedNode(a.Providers, providerID)
}

func allowedNode(allowed []string, value string) bool {
	if allowed == nil {
		return true
	}
	for _, candidate := range allowed {
		if candidate == value {
			return true
		}
	}
	return false
}

type Value struct {
	Type    string
	Boolean bool
	Integer *big.Int
	Decimal *Decimal
	String  string
	Strings []string
}

type Values interface {
	PolicyValue(path string) (Value, bool)
	// PolicyTokenPrice returns the price per million tokens of a token meter
	// for a request whose prompt has promptTokens tokens.
	PolicyTokenPrice(meter string, promptTokens int64) (Value, bool)
}

func compareValues(left, right Value) int {
	if left.Type != right.Type {
		return 0
	}
	switch left.Type {
	case "boolean":
		return boolCompare(left.Boolean, right.Boolean)
	case "decimal":
		if left.Decimal == nil || right.Decimal == nil {
			return 0
		}
		return left.Decimal.Cmp(right.Decimal)
	case "integer":
		if left.Integer == nil || right.Integer == nil {
			return 0
		}
		return left.Integer.Cmp(right.Integer)
	case "string":
		return strings.Compare(left.String, right.String)
	default:
		return 0
	}
}

func boolCompare(left, right bool) int {
	if left == right {
		return 0
	}
	if !left {
		return -1
	}
	return 1
}

func clockMinute(value string) (int, bool) {
	parsed, err := time.Parse("15:04", value)
	if err != nil || parsed.Format("15:04") != value {
		return 0, false
	}
	return parsed.Hour()*60 + parsed.Minute(), true
}

func clockEndMinute(value string) (int, bool) {
	if value == "24:00" {
		return 24 * 60, true
	}
	return clockMinute(value)
}

func policyWeekday(value string) (time.Weekday, bool) {
	switch value {
	case "sun":
		return time.Sunday, true
	case "mon":
		return time.Monday, true
	case "tue":
		return time.Tuesday, true
	case "wed":
		return time.Wednesday, true
	case "thu":
		return time.Thursday, true
	case "fri":
		return time.Friday, true
	case "sat":
		return time.Saturday, true
	default:
		return 0, false
	}
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func configError(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, arguments...))
}

var exactFieldTypes = map[string]string{
	"deployment.promptCacheMinimumTokens":         "integer",
	"deployment.reasoningDefault":                 "string",
	"model.openWeights":                           "boolean",
	"deployment.inputLimits.requestBytes":         "integer",
	"deployment.inputLimits.images.bytes":         "integer",
	"deployment.inputLimits.images.count":         "integer",
	"deployment.inputLimits.images.pixels":        "integer",
	"deployment.inputLimits.images.totalBytes":    "integer",
	"deployment.inputLimits.documents.bytes":      "integer",
	"deployment.inputLimits.documents.count":      "integer",
	"deployment.inputLimits.documents.pages":      "integer",
	"deployment.inputLimits.documents.totalBytes": "integer",
	"deployment.sampling.frequencyPenalty":        "boolean",
	"deployment.sampling.logitBias":               "boolean",
	"deployment.sampling.presencePenalty":         "boolean",
	"deployment.sampling.repetitionPenalty":       "boolean",
	"deployment.sampling.seed":                    "boolean",
	"deployment.sampling.temperature":             "boolean",
	"deployment.sampling.topK":                    "boolean",
	"deployment.sampling.topP":                    "boolean",
	"author.companyId":                            "string", "author.headquarteredCountry": "string", "author.name": "string", "author.id": "string",
	"deployment.approvalRequired": "boolean", "deployment.contextWindowTokens": "integer", "deployment.maxInputTokens": "integer",
	"deployment.dataHandling.endToEndEncrypted": "boolean", "deployment.dataHandling.processingLocation": "string",
	"deployment.dataHandling.processingWithin": "string_list", "deployment.dataHandling.retentionDays": "integer",
	"deployment.dataHandling.storageLocation": "string", "deployment.dataHandling.storageWithin": "string_list",
	"deployment.dataHandling.tee": "boolean", "deployment.dataHandling.teeVerified": "boolean",
	"deployment.dataHandling.trainingUse": "boolean", "deployment.dataHandling.zeroDataRetention": "boolean",
	"deployment.hosting": "string", "deployment.companies": "string_list", "deployment.dataHandling.sharedWith": "string_list",
	"deployment.dataHandling.certifications": "string_list",
	"deployment.inputModalities":             "string_list", "deployment.maxOutputTokens": "integer",
	"deployment.modelId": "string", "deployment.outputModalities": "string_list",
	"deployment.reasoning": "string", "deployment.reasoningEfforts": "string_list",
	"deployment.reasoningMaxTokens.maximum": "integer", "deployment.reasoningMaxTokens.minimum": "integer",
	"deployment.retirementDate": "string", "deployment.upstream.chuteId": "string",
	"deployment.upstream.deploymentType": "string", "deployment.upstream.gpuCount": "integer",
	"deployment.upstream.inferenceGeo": "string",
	"deployment.upstream.model":        "string", "deployment.upstream.modelFormat": "string",
	"deployment.upstream.modelVersion": "string", "deployment.upstream.reasoningMode": "string",
	"deployment.upstream.serviceTier": "string", "deployment.weightPrecision": "string",
	"deployment.id": "string", "model.authorId": "string", "model.groupIds": "string_list",
	"model.maxOutputTokens": "integer", "model.name": "string", "model.reasoning": "string",
	"model.reasoningEfforts": "string_list", "model.reasoningMaxTokens.maximum": "integer",
	"model.reasoningMaxTokens.minimum": "integer", "model.releaseDate": "string", "model.id": "string",
	"provider.companyId": "string", "provider.headquarteredCountry": "string",
	"provider.name": "string", "provider.id": "string",
	"request.bodyBytes": "integer", "request.clientTools": "string_list", "request.hostedTools": "string_list",
	"request.interface": "string", "request.model": "string", "request.systemMessages": "boolean",
	"request.time": "timestamp", "route.documentFormats.extensions": "string_list",
	"route.documentFormats.mediaTypes": "string_list", "route.interfaces": "string_list",
	"route.providerId": "string", "route.id": "string",
}

func init() {
	for _, capability := range []string{
		"explicitPromptCaching", "functionCalling", "implicitPromptCaching",
		"parallelFunctionCalling", "streaming", "structuredOutputs", "systemMessages",
		"toolChoice", "toolResultAttachments",
	} {
		exactFieldTypes["deployment.capabilities."+capability] = "boolean"
	}
	// Long prompt prices vary by deployment; blendedPrice reads them for a
	// stated prompt size.
	for _, meter := range []string{
		"cache_write_1h_input_tokens", "cache_write_5m_input_tokens", "cache_write_input_tokens",
		"cached_input_tokens", "input_tokens", "output_tokens", "reasoning_tokens",
	} {
		exactFieldTypes["deployment.pricing."+meter+".per_mill_tokens"] = "decimal"
	}
}

func FieldType(path string) (string, bool) {
	fieldType, ok := exactFieldTypes[path]
	return fieldType, ok
}

func FieldPaths() []string {
	paths := make([]string, 0, len(exactFieldTypes))
	for path := range exactFieldTypes {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

// RedactionDigest identifies the matcher that the redaction settings compile
// to, hashing them once across requests. A matcher depends on them alone, so
// plugin sections that differ only in export or text extraction share one.
func (p *Plugins) RedactionDigest() [32]byte {
	if p == nil || p.Redaction == nil {
		return sha256.Sum256(nil)
	}
	r := p.Redaction
	r.digestOnce.Do(func() {
		raw, _ := json.Marshal(struct {
			Version   int
			Redaction *Redaction
		}{CompilerVersion, r})
		r.digest = sha256.Sum256(raw)
	})
	return r.digest
}

func (c *Config) Activated() bool { return c != nil && c.activated }
