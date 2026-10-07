package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

const (
	CompilerVersion          = 1
	MaxCompiledBytes         = 512 << 10
	MaxSorts                 = 3
	MaxPreDispatchCandidates = 3
	MaxCustomPatterns        = 3
	MaxCustomPatternBytes    = 512
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
)

type Config struct {
	ActiveRules            []RuleMatch       `json:"-"`
	ActiveEncryptedPlugins []*SourceDocument `json:"-"`
	sources                []ScopedSource
	hasRules               bool
	activated              bool
	requiredSettings       Permission
	EncryptionKeys         map[string]string `json:"-"`
	RequiredEncryptionKeys []string          `json:"-"`
	PluginSources          []*Plugins        `json:"-"`
	Access                 *Access           `json:"access"`
	Input                  *Input            `json:"input,omitempty"`
	CompilerVersion        int               `json:"compilerVersion"`
	Plugins                *Plugins          `json:"plugins"`
	Routing                Routing           `json:"routing"`
	RequestPermission      RequestPermission `json:"requestPermission"`
	Schema                 string            `json:"schema"`
}

type Input struct {
	ASCIIOnly bool `json:"asciiOnly"`
}

type Routing struct {
	AllowedCatalogNodes      *AllowedCatalogNodes `json:"allowedCatalogNodes"`
	MaxPreDispatchCandidates int                  `json:"maxPreDispatchCandidates"`
	Query                    *Query               `json:"query"`
	SortDefault              bool                 `json:"sortDefault"`
}

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
	digestOnce           sync.Once
	digest               [32]byte
	StogasExport         *exportconfig.Config `json:"stogasExport,omitempty"`
	StogasRedaction      *Redaction           `json:"stogasRedaction,omitempty"`
	StogasTextExtraction *bool                `json:"stogasTextExtraction,omitempty"`
}

type Redaction struct {
	CustomPatterns []string            `json:"customPatterns,omitempty"`
	Presets        []string            `json:"presets"`
	Literals       []redaction.Literal `json:"literals,omitempty"`
}

func (c *Config) validate() error {
	if c == nil || c.Schema != "stogas.key-config.compiled.v1" || c.CompilerVersion != CompilerVersion {
		return configError("unsupported schema or compiler version")
	}
	if c.Routing.MaxPreDispatchCandidates < 1 || c.Routing.MaxPreDispatchCandidates > MaxPreDispatchCandidates {
		return configError("pre-dispatch candidate count is invalid")
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
		if len(values) == 0 {
			continue
		}
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
	if len(w.TimeZone) > 64 {
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
		if err := p.StogasExport.Validate(); err != nil {
			return configError("invalid stogasExport configuration")
		}
	}
	if p == nil || p.StogasRedaction == nil {
		if p == nil {
			return nil
		}
		if p.StogasTextExtraction != nil || p.StogasExport != nil {
			return nil
		}
		return configError("plugins require explicit configuration")
	}
	selected := p.StogasRedaction
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
		window := &c.Access.Deny[index]
		local := now.In(window.location)
		minute := local.Hour()*60 + local.Minute()
		if window.weekdays[local.Weekday()] && minute >= window.startMinute && minute < window.endMinute {
			return true
		}
	}
	return false
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
	"author.aliases": "string_list", "author.name": "string", "author.id": "string",
	"deployment.aliases": "string_list", "deployment.contextWindowTokens": "integer", "deployment.maxInputTokens": "integer",
	"deployment.dataHandling.endToEndEncrypted": "boolean", "deployment.dataHandling.processingLocation": "string",
	"deployment.dataHandling.retentionDays": "integer", "deployment.dataHandling.storageLocation": "string",
	"deployment.dataHandling.tee": "boolean", "deployment.dataHandling.teeVerified": "boolean",
	"deployment.dataHandling.trainingUse":       "boolean",
	"deployment.dataHandling.zeroDataRetention": "boolean", "deployment.deprecationDate": "string",
	"deployment.fileInputs.extensions": "string_list", "deployment.fileInputs.mediaTypes": "string_list",
	"deployment.inputModalities": "string_list", "deployment.maxOutputTokens": "integer",
	"deployment.modelId": "string", "deployment.outputModalities": "string_list",
	"deployment.reasoning": "string", "deployment.reasoningEfforts": "string_list",
	"deployment.reasoningMaxTokens.maximum": "integer", "deployment.reasoningMaxTokens.minimum": "integer",
	"deployment.routeIds": "string_list", "deployment.upstream.chuteId": "string",
	"deployment.upstream.deploymentType": "string", "deployment.upstream.gpuCount": "integer",
	"deployment.upstream.hosting": "string", "deployment.upstream.inferenceGeo": "string",
	"deployment.upstream.model": "string", "deployment.upstream.modelFormat": "string",
	"deployment.upstream.modelVersion": "string", "deployment.upstream.reasoningMode": "string",
	"deployment.upstream.serviceTier": "string", "deployment.upstream.speed": "string",
	"deployment.weightPrecision": "string",
	"deployment.id":              "string", "model.aliases": "string_list", "model.authorId": "string",
	"model.maxOutputTokens": "integer", "model.name": "string", "model.reasoning": "string",
	"model.reasoningEfforts": "string_list", "model.reasoningMaxTokens.maximum": "integer",
	"model.reasoningMaxTokens.minimum": "integer", "model.releaseDate": "string", "model.id": "string",
	"provider.aliases": "string_list", "provider.credentialModes": "string_list",
	"provider.name": "string", "provider.id": "string",
	"request.bodyBytes": "integer", "request.model": "string", "request.route": "string", "request.time": "timestamp",
	"route.interfaces": "string_list", "route.providerId": "string", "route.id": "string",
}

func init() {
	for _, capability := range []string{
		"cancellation", "explicitPromptCaching", "functionCalling", "implicitPromptCaching",
		"parallelFunctionCalling", "streaming", "structuredOutputs", "systemMessages",
		"toolChoice", "urlContext",
	} {
		exactFieldTypes["deployment.capabilities."+capability] = "boolean"
	}
}

var tokenPricingMeters = stringSet(
	"cache_write_1h_input_tokens", "cache_write_5m_input_tokens", "cache_write_input_tokens",
	"cached_input_tokens", "input_tokens", "output_tokens", "reasoning_tokens",
)

var tokenPricingRates = stringSet(
	"per_mill_context_gt_272k", "per_mill_context_lte_272k", "per_mill_tokens",
)

func FieldType(path string) (string, bool) {
	if fieldType, ok := exactFieldTypes[path]; ok {
		return fieldType, true
	}
	parts := strings.Split(path, ".")
	if len(parts) != 4 || parts[0] != "deployment" || parts[1] != "pricing" {
		return "", false
	}
	meter, rate := parts[2], parts[3]
	if tokenPricingMeters[meter] && tokenPricingRates[rate] {
		return "decimal", true
	}
	return "", false
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

// CacheDigest hashes immutable plugin settings once across requests.
func (p *Plugins) CacheDigest() [32]byte {
	if p == nil {
		return sha256.Sum256(nil)
	}
	p.digestOnce.Do(func() {
		raw, _ := json.Marshal(struct {
			Version int
			Plugins *Plugins
		}{CompilerVersion, p})
		p.digest = sha256.Sum256(raw)
	})
	return p.digest
}

func (c *Config) Activated() bool { return c != nil && c.activated }
