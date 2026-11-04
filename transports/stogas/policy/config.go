package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

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
	EncryptionKeys         map[string]string `json:"-"`
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
// Query sorts candidates; a policy's routing.order becomes its leading
// deployments list. Sorting never adds a deployment that selectors, filters
// or credentials exclude.
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
	Deny []DenyWindow `json:"deny"`
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
	TextExtraction *string              `json:"textExtraction,omitempty"`
}

// Text extraction modes, from the weakest to the strongest: a policy that sets a stronger one
// overrides a weaker one.
const (
	// TextExtractionOff sends text files as they are.
	TextExtractionOff = "off"
	// TextExtractionAuto turns a text file into prompt text where the deployment does not read
	// it as a file, or where input checks or redaction must read it.
	TextExtractionAuto = "auto"
	// TextExtractionAlways turns every text file into prompt text.
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

type Redaction struct {
	digestOnce     sync.Once
	digest         [32]byte
	CustomPatterns []string            `json:"customPatterns,omitempty"`
	Presets        []string            `json:"presets"`
	Literals       []redaction.Literal `json:"literals,omitempty"`
}

// pluginUnits are the plugins that combine on their own: a required plugin
// setting replaces only the defaults of the same plugin.
const pluginUnits = permissionRedaction | permissionTextExtraction | permissionExport

func (p *Plugins) units() Permission {
	var units Permission
	if p != nil && p.Redaction != nil {
		units |= permissionRedaction
	}
	if p != nil && p.TextExtraction != nil {
		units |= permissionTextExtraction
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
	if units&permissionTextExtraction != 0 {
		part.TextExtraction = p.TextExtraction
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

func validateOrder(order []string) error {
	if validateNodeIDs(order) != nil {
		return configError("routing.order must list unique deployment IDs")
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
	if a.Deny == nil {
		return configError("deny windows require an array")
	}
	locations := make(map[string]*time.Location)
	for index := range a.Deny {
		window := &a.Deny[index]
		if err := window.validate(locations); err != nil {
			return err
		}
	}
	return nil
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
		if p.TextExtraction != nil && !slices.Contains(textExtractionModes, *p.TextExtraction) {
			return configError("plugins.textExtraction must be off, auto or always")
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

func (c *Config) DeniedAt(now time.Time) bool {
	if c == nil || c.Access == nil {
		return false
	}
	for index := range c.Access.Deny {
		if c.Access.Deny[index].covers(now) {
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
	"author.aliases": "string_list", "author.headquarteredCountry": "string", "author.name": "string", "author.id": "string",
	"deployment.approvalRequired": "boolean", "deployment.contextWindowTokens": "integer", "deployment.maxInputTokens": "integer",
	"deployment.dataHandling.endToEndEncrypted": "boolean", "deployment.dataHandling.processingLocation": "string",
	"deployment.dataHandling.processingWithin": "string_list", "deployment.dataHandling.retentionDays": "integer",
	"deployment.dataHandling.storageLocation": "string", "deployment.dataHandling.storageWithin": "string_list",
	"deployment.dataHandling.tee": "boolean", "deployment.dataHandling.teeVerified": "boolean",
	"deployment.dataHandling.trainingUse": "boolean", "deployment.dataHandling.zeroDataRetention": "boolean",
	"deployment.inputModalities": "string_list", "deployment.maxOutputTokens": "integer",
	"deployment.modelId": "string", "deployment.outputModalities": "string_list",
	"deployment.reasoning": "string", "deployment.reasoningEfforts": "string_list",
	"deployment.reasoningMaxTokens.maximum": "integer", "deployment.reasoningMaxTokens.minimum": "integer",
	"deployment.retirementDate": "string", "deployment.upstream.chuteId": "string",
	"deployment.upstream.deploymentType": "string", "deployment.upstream.gpuCount": "integer",
	"deployment.upstream.hosting": "string", "deployment.upstream.inferenceGeo": "string",
	"deployment.upstream.model": "string", "deployment.upstream.modelFormat": "string",
	"deployment.upstream.modelVersion": "string", "deployment.upstream.reasoningMode": "string",
	"deployment.upstream.serviceTier": "string", "deployment.weightPrecision": "string",
	"deployment.id": "string", "model.aliases": "string_list", "model.authorId": "string", "model.groupIds": "string_list",
	"model.maxOutputTokens": "integer", "model.name": "string", "model.reasoning": "string",
	"model.reasoningEfforts": "string_list", "model.reasoningMaxTokens.maximum": "integer",
	"model.reasoningMaxTokens.minimum": "integer", "model.releaseDate": "string", "model.id": "string",
	"provider.aliases": "string_list", "provider.credentialModes": "string_list", "provider.headquarteredCountry": "string",
	"provider.name": "string", "provider.id": "string",
	"request.bodyBytes": "integer", "request.hostedTools": "string_list", "request.interface": "string",
	"request.model": "string", "request.time": "timestamp",
	"route.documentFormats.extensions": "string_list", "route.documentFormats.mediaTypes": "string_list",
	"route.interfaces": "string_list", "route.providerId": "string", "route.id": "string",
}

func init() {
	for _, capability := range []string{
		"explicitPromptCaching", "functionCalling", "implicitPromptCaching",
		"parallelFunctionCalling", "streaming", "structuredOutputs", "systemMessages",
		"toolChoice",
	} {
		exactFieldTypes["deployment.capabilities."+capability] = "boolean"
	}
	// Long prompt prices vary by deployment; blended_price reads them for a
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
