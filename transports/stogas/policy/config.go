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
	MaxSorts          = 4
	MaxRetries        = 3
	MaxFallbacks      = 2
	DefaultFallbacks  = 2
	MaxRequestTimeout = time.Hour
	// Without a policy value only the total limit applies. Models reason for
	// minutes without output, and expiry neither stops nor refunds the call.
	DefaultOutputIdleTimeout = MaxRequestTimeout
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
	// copiedBytes is the size of the sources that composition copied without
	// the rules that the chain skips.
	copiedBytes            int64
	activated              bool
	requiredSettings       Permission
	sortOrigins            []Origin
	requiredSorts          int
	RequiredEncryptionKeys []string   `json:"-"`
	PluginSources          []*Plugins `json:"-"`
	// pluginPolicies holds, for each plugin section, the position of its policy.
	pluginPolicies    []int
	Access            *Access           `json:"access"`
	Input             *Input            `json:"input,omitempty"`
	Timeouts          *Timeouts         `json:"timeouts,omitempty"`
	CompilerVersion   int               `json:"compilerVersion"`
	Plugins           *Plugins          `json:"plugins"`
	Routing           Routing           `json:"routing"`
	RequestPermission RequestPermission `json:"requestPermission"`
	Schema            string            `json:"schema"`
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

// The lists admit candidates by the catalog IDs of their author, model,
// deployment, route and provider. Retries repeat a call to the same
// deployment and credential. Fallbacks move to the next pair in routing
// order, so a request calls at most three pairs. Query sorts candidates.
// Sorting never adds a deployment that lists, filters or credentials exclude.
// MissingEncryptionKeys is empty when no policy sets it, which fails.
type Routing struct {
	Authors               *Lists `json:"authors,omitempty"`
	Models                *Lists `json:"models,omitempty"`
	Deployments           *Lists `json:"deployments,omitempty"`
	Routes                *Lists `json:"routes,omitempty"`
	Providers             *Lists `json:"providers,omitempty"`
	Fallbacks             int    `json:"fallbacks"`
	MissingEncryptionKeys string `json:"missingEncryptionKeys,omitempty"`
	Query                 *Query `json:"query"`
	Retries               int    `json:"retries"`
}

// SkipsMissingKeys reports whether a candidate whose encryption key the
// request did not send leaves only itself out.
func (r Routing) SkipsMissingKeys() bool { return r.MissingEncryptionKeys == MissingKeysSkip }

// routingList is one kind of catalog ID that routing lists take, with the
// permission that sets it.
type routingList struct {
	kind, noun string
	permission Permission
	lists      func(*Routing) **Lists
}

var routingLists = [...]routingList{
	{"authors", "author", permissionAuthors, func(r *Routing) **Lists { return &r.Authors }},
	{"models", "model", permissionModels, func(r *Routing) **Lists { return &r.Models }},
	{"deployments", "deployment", permissionDeployments, func(r *Routing) **Lists { return &r.Deployments }},
	{"routes", "route", permissionRoutes, func(r *Routing) **Lists { return &r.Routes }},
	{"providers", "provider", permissionProviders, func(r *Routing) **Lists { return &r.Providers }},
}

// HasLists reports whether any list of catalog IDs applies.
func (r *Routing) HasLists() bool {
	return r.Authors != nil || r.Models != nil || r.Deployments != nil || r.Routes != nil || r.Providers != nil
}

// Admits reports whether the lists accept a candidate with these catalog IDs.
// An ID that the catalog in effect does not list matches nothing.
func (r *Routing) Admits(authorID, modelID, deploymentID, routeID, providerID string) bool {
	return r.Authors.admits(authorID) && r.Models.admits(modelID) && r.Deployments.admits(deploymentID) &&
		r.Routes.admits(routeID) && r.Providers.admits(providerID)
}

func (r *Routing) validateLists() error {
	for _, list := range routingLists {
		if err := (*list.lists(r)).validate("routing."+list.kind, list.noun+" ID", "a catalog ID", nodeIDPattern.MatchString); err != nil {
			return err
		}
	}
	return nil
}

type Access struct {
	Schedule   *Schedule `json:"schedule,omitempty"`
	Networks   *Networks `json:"networks,omitempty"`
	Countries  *Lists    `json:"countries,omitempty"`
	Transports *Lists    `json:"transports,omitempty"`
}

// Schedule refuses requests during weekly periods. It has no allow list,
// because periods in several time zones have no common form to intersect in,
// so the allow lists of several policies could not combine into one.
type Schedule struct {
	Deny []DenyWindow `json:"deny,omitzero"`
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
	PromptCaching  string               `json:"promptCaching,omitempty"`
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
const pluginUnits = permissionRedaction | textExtractionUnits | permissionExport | permissionPromptCaching

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
	if p != nil && p.PromptCaching != "" {
		units |= permissionPromptCaching
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
	if units&permissionPromptCaching != 0 {
		part.PromptCaching = p.PromptCaching
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
	if err := c.Routing.validateLists(); err != nil {
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
	if a.Schedule == nil && a.Networks == nil && a.Countries == nil && a.Transports == nil {
		return configError("access requires schedule, networks, countries or transports")
	}
	if err := a.Networks.validate(); err != nil {
		return err
	}
	if err := a.Countries.validate("access.countries", "country", "an ISO 3166-1 alpha-2 country code or a region such as eu", countryEntry); err != nil {
		return err
	}
	if a.Countries != nil {
		// A region in deny can hold every country of an allow list that names
		// none of the same entries.
		a.Countries = &Lists{Allow: countriesOf(a.Countries.Allow), Deny: countriesOf(a.Countries.Deny)}
		if err := a.Countries.validate("access.countries", "country", "", CountryCode); err != nil {
			return err
		}
	}
	if err := a.Transports.validate("access.transports", "connection mode", "https, attested_tls or e2ee", func(mode string) bool {
		return slices.Contains(transports, mode)
	}); err != nil {
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
		if p.PromptCaching != "" {
			if err := validatePromptCaching(p.PromptCaching); err != nil {
				return err
			}
		}
	}
	if p == nil || p.Redaction == nil {
		if p == nil {
			return nil
		}
		if p.TextExtraction != nil || p.Export != nil || p.PromptCaching != "" {
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
	"deployment.dataHandling.isolatedPromptCache": "boolean", "deployment.dataHandling.certifications": "string_list",
	"deployment.hosting": "string", "deployment.companies": "string_list", "deployment.dataHandling.sharedWith": "string_list",
	"deployment.inputModalities": "string_list", "deployment.maxOutputTokens": "integer",
	"deployment.modelId": "string", "deployment.outputModalities": "string_list",
	"deployment.reasoning": "string", "deployment.reasoningEfforts": "string_list",
	"deployment.reasoningMaxTokens.maximum": "integer", "deployment.reasoningMaxTokens.minimum": "integer",
	"deployment.retirementDate": "string", "deployment.upstream.chuteId": "string",
	"deployment.upstream.deploymentType": "string", "deployment.upstream.gpuCount": "integer",
	"deployment.upstream.inferenceGeo": "string",
	"deployment.upstream.model":        "string", "deployment.upstream.modelFormat": "string",
	"deployment.upstream.modelVersion": "string", "deployment.upstream.reasoningMode": "string",
	"deployment.upstream.serviceTier": "string", "deployment.weightPrecision": "string",
	"credential.accountOptions": "string_list", "credential.declaredAccountOptions": "string_list",
	"credential.kind": "string", "deployment.id": "string", "model.authorId": "string", "model.groupIds": "string_list",
	"model.maxOutputTokens": "integer", "model.name": "string", "model.reasoning": "string",
	"model.reasoningEfforts": "string_list", "model.reasoningMaxTokens.maximum": "integer",
	"model.reasoningMaxTokens.minimum": "integer", "model.releaseDate": "string", "model.id": "string",
	"provider.companyId": "string", "provider.headquarteredCountry": "string",
	"provider.name": "string", "provider.id": "string",
	"request.bodyBytes": "integer", "request.clientTools": "string_list", "request.hostedTools": "string_list",
	"request.interface": "string", "request.mcpServers": "string_list", "request.mcpServersWithoutApproval": "string_list",
	"request.mcpTools": "string_list",
	"request.model":    "string", "request.store": "boolean", "request.storedInput": "boolean",
	"request.systemMessages": "boolean", "request.time": "timestamp",
	"route.documentFormats.extensions": "string_list", "route.documentFormats.mediaTypes": "string_list",
	"route.interfaces": "string_list", "route.providerId": "string", "route.id": "string",
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
