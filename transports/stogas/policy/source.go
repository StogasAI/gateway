package policy

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

const MaxSourceBytes = 256 << 10
const MaxStoredSourceBytes = (MaxSourceBytes*4+2)/3 + 512

var policyName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)

// Source is immutable. Control owns limits and editing permissions; Config
// contains the instructions the gateway enforces. A shared source never gains
// defaults that depend on its organization/grant/key position.
type Source struct {
	Rules            []Rule
	settings         Permission
	defaultSettings  bool
	defaultOrdering  *ordering
	encryptedPlugins *SourceDocument
	// RequiredEncryptionKeyIDs names the roots of the plugins that opening
	// this source decrypted.
	RequiredEncryptionKeyIDs []string
	Config                   *Config
	Digest                   string
	Delegation               *Delegation
	// excludes is set when a rule lists resources whose keys skip it.
	excludes bool
	// work is what the policy's expressions and rules charge their cost to.
	work *policyWork
}

// ordering is a policy's routing.sort. Every ordering applies: each criterion
// orders the ties of the ones before it.
type ordering struct {
	sorts []Sort
	// rule names the default rule that set this ordering.
	rule string
}

// Ordering scopes form one chain from the organization to the request. Role
// and member policies apply beside it, and a credential policy applies to
// only some candidates, so they cannot set one.
var orderingRanks = map[Scope]int{OrganizationScope: 0, FolderScope: 1, GrantScope: 2, KeyScope: 3, RequestScope: 4}

// takeOrdering moves a default rule's ordering to its policy, so composition
// places it without activating rules.
func (s *Source) takeOrdering(rule string) *ordering {
	routing := &s.Config.Routing
	taken := &ordering{rule: rule}
	if query := routing.Query; query != nil {
		taken.sorts, query.OrderBy = query.OrderBy, nil
		if len(query.Filters) == 0 {
			routing.Query = nil
		}
	}
	s.settings &^= permissionSort
	return taken
}

// SourceDocument retains the checked canonical bytes until compilation. Its
// immutable identity lets callers find an existing source before compiling it.
type SourceDocument struct {
	canonical []byte
	digest    string
	// encrypted holds, in name order, the plugins whose settings a customer
	// key encrypts; readablePlugins is the plugins section without them.
	encrypted       []encryptedPlugin
	readablePlugins json.RawMessage
	// pluginDelta is how much longer the plugins section is once decrypted.
	pluginDelta  int
	fields       map[string]json.RawMessage
	rules        map[string]ruleDocument
	usedSections Permission
}

// encryptedPlugin is a plugin that holds values under customer keys: the
// whole plugin, or values inside it. Opening puts each plaintext in its place.
type encryptedPlugin struct {
	name string
	unit Permission
	// skeleton is the plugin's value as saved, each sealed value in its place.
	skeleton jsontext.Value
	sealed   []sealedValue
	// delta is how much longer the plugin is once opened.
	delta int
}

// sealedValue is one value of a plugin under a customer key.
type sealedValue struct {
	// at is the value's place in the plugin: member names and array indexes.
	at []string
	// purpose names the plugin and the members down to the value, without
	// array indexes: a value cannot move to another setting, and reordering a
	// list keeps its values readable.
	purpose  string
	envelope customerkey.Envelope
}

// plaintextBytes is the decrypted value's length: the decoded ciphertext
// without its 16-byte tag.
func (v sealedValue) plaintextBytes() int { return len(v.envelope.Blob)*3/4 - 16 }

// encryptablePlugins are the plugins whose values a customer key can encrypt.
// Text extraction holds no secret.
var encryptablePlugins = []struct {
	name string
	unit Permission
}{{"export", permissionExport}, {"redaction", permissionRedaction}}

// maxSealedDepth bounds how deep inside a plugin the parser looks for sealed
// values. The plugins' own settings nest five levels deep.
const maxSealedDepth = 8

// exportHeaders is the purpose of a destination's headers. Their secrets are
// sealed only with the URL they go to: a sealed header map beside a readable
// URL could be copied beside another URL, which would receive the secrets.
const exportHeaders = "plugins/export/destinations/headers"

// EncryptedPlugins is the encrypted plugin settings of one policy or rule
// that apply to a request: the plugins in Units.
type EncryptedPlugins struct {
	Document *SourceDocument
	Units    Permission
	// policy is the position of the policy that holds them.
	policy int
}

// EncryptionKeyIDs names the roots that open the applied plugins.
func (e EncryptedPlugins) EncryptionKeyIDs() []string { return e.Document.encryptionKeyIDs(e.Units) }

type sourceBody struct {
	Schema     *string         `json:"$schema"`
	Rules      json.RawMessage `json:"rules"`
	Limits     json.RawMessage `json:"limits"`
	Delegation *Delegation     `json:"delegation"`
	Access     *Access         `json:"access"`
	Input      *Input          `json:"input"`
	Timeouts   *Timeouts       `json:"timeouts"`
	Plugins    json.RawMessage `json:"plugins"`
	Routing    *struct {
		Authors     *Lists  `json:"authors"`
		Models      *Lists  `json:"models"`
		Deployments *Lists  `json:"deployments"`
		Routes      *Lists  `json:"routes"`
		Providers   *Lists  `json:"providers"`
		Filter      *string `json:"filter"`
		Sort        []Sort  `json:"sort"`
		Retries     *int    `json:"retries"`
		Fallbacks   *int    `json:"fallbacks"`
		Missing     *string `json:"missingEncryptionKeys"`
	} `json:"routing"`
}

func (d *SourceDocument) Digest() string        { return d.digest }
func (d *SourceDocument) CanonicalJSON() []byte { return bytes.Clone(d.canonical) }
func (d *SourceDocument) Encrypted() bool       { return len(d.encrypted) > 0 }

// EncryptedUnits are the plugins whose settings this document encrypts.
func (d *SourceDocument) EncryptedUnits() Permission {
	var units Permission
	for _, plugin := range d.encrypted {
		units |= plugin.unit
	}
	return units
}

// EncryptionKeyIDs names, once each, the roots of every encrypted plugin.
func (d *SourceDocument) EncryptionKeyIDs() []string { return d.encryptionKeyIDs(pluginUnits) }

func (d *SourceDocument) encryptionKeyIDs(units Permission) []string {
	var ids []string
	for _, plugin := range d.encrypted {
		if plugin.unit&units != 0 {
			ids = plugin.keyIDs(ids)
		}
	}
	return ids
}

// keyIDs adds the roots of the plugin's sealed values to ids, once each.
func (p encryptedPlugin) keyIDs(ids []string) []string {
	for _, value := range p.sealed {
		if !slices.Contains(ids, value.envelope.KeyID) {
			ids = append(ids, value.envelope.KeyID)
		}
	}
	return ids
}

// EncryptedPlugin is one encrypted plugin of a document. A policy check opens
// the plugins whose roots it has and names the others.
type EncryptedPlugin struct {
	Name   string
	Unit   Permission
	KeyIDs []string
}

func (d *SourceDocument) EncryptedPlugins() []EncryptedPlugin {
	plugins := make([]EncryptedPlugin, len(d.encrypted))
	for i, plugin := range d.encrypted {
		plugins[i] = EncryptedPlugin{Name: plugin.name, Unit: plugin.unit, KeyIDs: plugin.keyIDs(nil)}
	}
	return plugins
}

// ParseSourceDocument bounds input before canonicalizing. PostgreSQL jsonb
// includes insignificant whitespace; the canonical document has the content cap.
func ParseSourceDocument(raw []byte) (*SourceDocument, error) {
	return parseSourceDocument(raw, nil)
}

func parseSourceDocument(raw []byte, envelopes map[[32]byte]encryptedPlugin) (*SourceDocument, error) {
	if len(raw) == 0 || len(raw) > 2*MaxStoredSourceBytes {
		return nil, configError("source configuration size is invalid")
	}
	// jsontext canonicalization saturates overflowing numbers. JCS identities
	// must instead reject values outside finite IEEE 754, before normalization.
	decoder := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := decoder.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, configError("invalid source configuration JSON")
		}
		if token.Kind() == '0' {
			if _, err := token.Float(); err != nil {
				return nil, configError("source numbers must be finite IEEE 754 values")
			}
		}
	}
	canonical := jsontext.Value(bytes.Clone(raw))
	if err := canonical.Canonicalize(); err != nil || len(canonical)+1 > MaxStoredSourceBytes {
		return nil, configError("invalid source configuration JSON or size")
	}
	var doc map[string]json.RawMessage
	if err := jsonv2.Unmarshal(canonical, &doc); err != nil {
		return nil, configError("invalid source configuration")
	}
	return sourceDocument(append(canonical, '\n'), doc, envelopes)
}

// Fields come from the canonical document. Reuse them for rule fragments and
// readable compilation instead of decoding the ciphertext at every layer.
func sourceDocument(canonical []byte, fields map[string]json.RawMessage, envelopes map[[32]byte]encryptedPlugin) (*SourceDocument, error) {
	if fields == nil {
		return nil, configError("source configuration requires an object")
	}
	for name := range fields {
		if sourceJSONFields(reflect.TypeFor[sourceBody]())[name] == nil {
			return nil, configError("unknown policy field %q", name)
		}
	}
	document := &SourceDocument{fields: fields, canonical: canonical}
	contentBytes := len(canonical)
	if plugins := fields["plugins"]; len(plugins) > 0 {
		if err := document.parsePlugins(plugins, envelopes); err != nil {
			return nil, err
		}
		contentBytes += document.pluginDelta
	}
	// Flat rules share the source's content budget. Ciphertext length counts
	// decoded plugin bytes, just as it does for the root plugin section.
	var err error
	document.rules, err = parseRuleDocuments(fields["rules"], envelopes)
	if err != nil {
		return nil, err
	}
	for _, rule := range document.rules {
		contentBytes += rule.source.pluginDelta
	}
	if contentBytes > MaxSourceBytes {
		return nil, configError("source configuration exceeds size limit")
	}
	// Logs, receipts and Control's policy_version.sha512 name this digest, so like
	// every RFC 8785 identity it excludes the document file's trailing newline.
	// Customers write this content, so its hash resists collisions at ML-DSA-65's level.
	sum := sha512.Sum512(bytes.TrimSuffix(canonical, []byte{'\n'}))
	document.digest = hex.EncodeToString(sum[:])
	document.usedSections = document.sections()
	return document, nil
}

// parsePlugins finds the plugins that hold values under a customer key, each
// as {"encrypted": envelope} in place of the value: the whole plugin or any
// value inside it. The rest of the section stays readable and compiles with
// the policy's other settings.
func (d *SourceDocument) parsePlugins(raw json.RawMessage, envelopes map[[32]byte]encryptedPlugin) error {
	d.readablePlugins = raw
	var section map[string]json.RawMessage
	if jsonv2.Unmarshal(raw, &section) != nil || section == nil {
		// Readable compilation reports the invalid section.
		return nil
	}
	if section["encrypted"] != nil {
		return configError("encrypt plugins.export, plugins.redaction or a value inside one, not the plugins section")
	}
	for _, plugin := range encryptablePlugins {
		member := section[plugin.name]
		if member == nil {
			continue
		}
		identity := sha256.Sum256(member)
		parsed, cached := envelopes[identity]
		if !cached {
			parsed = encryptedPlugin{skeleton: jsontext.Value(member)}
			if err := parsed.find(parsed.skeleton, nil, "plugins/"+plugin.name); err != nil {
				return err
			}
			if len(parsed.sealed) == 0 {
				continue
			}
			if envelopes != nil {
				envelopes[identity] = parsed
			}
		}
		parsed.name, parsed.unit = plugin.name, plugin.unit
		d.encrypted = append(d.encrypted, parsed)
		d.pluginDelta += parsed.delta
		delete(section, plugin.name)
	}
	if d.Encrypted() {
		d.readablePlugins = nil
		if len(section) > 0 {
			d.readablePlugins = canonicalObject(section)
		}
	}
	return nil
}

// find adds the sealed values in raw, which sits at at in the plugin, to p.
// Values that are not JSON or not settings are left to readable compilation.
func (p *encryptedPlugin) find(raw jsontext.Value, at []string, purpose string) error {
	switch raw.Kind() {
	case '{':
		var members map[string]jsontext.Value
		if jsonv2.Unmarshal(raw, &members) != nil {
			return nil
		}
		if envelope := members["encrypted"]; len(members) == 1 && envelope.Kind() == '{' {
			if purpose == exportHeaders || strings.HasPrefix(purpose, exportHeaders+"/") {
				return configError("encrypt a destination's headers together with its url")
			}
			value := sealedValue{at: slices.Clone(at), purpose: purpose}
			// v2 matches field names exactly. Every envelope member is required
			// and Validate rejects its zero value, including JSON null.
			if jsonv2.Unmarshal(envelope, &value.envelope, jsonv2.RejectUnknownMembers(true)) != nil || value.envelope.Validate(MaxSourceBytes) != nil {
				return configError("invalid encrypted value in %s", purpose)
			}
			p.sealed = append(p.sealed, value)
			p.delta += value.plaintextBytes() - len(raw)
			return nil
		}
		if len(at) == maxSealedDepth {
			return nil
		}
		names := slices.Sorted(maps.Keys(members))
		for _, name := range names {
			if err := p.find(members[name], append(at[:len(at):len(at)], name), purpose+"/"+name); err != nil {
				return err
			}
		}
	case '[':
		var items []jsontext.Value
		if jsonv2.Unmarshal(raw, &items) != nil || len(at) == maxSealedDepth {
			return nil
		}
		for index, item := range items {
			if err := p.find(item, append(at[:len(at):len(at)], strconv.Itoa(index)), purpose); err != nil {
				return err
			}
		}
	}
	return nil
}

// open decrypts the plugin's sealed values and returns the plugin with each
// plaintext in its place. opened collects every buffer that holds plaintext.
func (p encryptedPlugin) open(organizationID string, key customerkey.Keys, opened *[][]byte) (jsontext.Value, error) {
	plaintexts := make(map[string]jsontext.Value, len(p.sealed))
	prefixes := map[string]bool{}
	for _, value := range p.sealed {
		plaintext, err := key.Open(value.envelope, organizationID, value.purpose, MaxSourceBytes)
		if err != nil {
			return nil, err
		}
		*opened = append(*opened, plaintext)
		if !jsontext.Value(plaintext).IsValid() {
			return nil, configError("invalid encrypted value JSON")
		}
		plaintexts[pathKey(value.at)] = plaintext
		for i := range value.at {
			prefixes[pathKey(value.at[:i])] = true
		}
	}
	combined, err := place(p.skeleton, nil, plaintexts, prefixes)
	if err != nil {
		return nil, configError("invalid encrypted value JSON")
	}
	*opened = append(*opened, combined)
	return combined, nil
}

// place returns raw, at at in the plugin, with each plaintext at its path.
// Only the containers on a path to a plaintext are encoded again.
func place(raw jsontext.Value, at []string, plaintexts map[string]jsontext.Value, prefixes map[string]bool) (jsontext.Value, error) {
	path := pathKey(at)
	if plaintext, ok := plaintexts[path]; ok {
		return plaintext, nil
	}
	if !prefixes[path] {
		return raw, nil
	}
	if raw.Kind() == '[' {
		var items []jsontext.Value
		if err := jsonv2.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		for index, item := range items {
			placed, err := place(item, append(at[:len(at):len(at)], strconv.Itoa(index)), plaintexts, prefixes)
			if err != nil {
				return nil, err
			}
			items[index] = placed
		}
		return jsonv2.Marshal(items)
	}
	var members map[string]jsontext.Value
	if err := jsonv2.Unmarshal(raw, &members); err != nil {
		return nil, err
	}
	for name, member := range members {
		placed, err := place(member, append(at[:len(at):len(at)], name), plaintexts, prefixes)
		if err != nil {
			return nil, err
		}
		members[name] = placed
	}
	return jsonv2.Marshal(members, jsonv2.Deterministic(true))
}

// pathKey names a place in a plugin without ambiguity.
func pathKey(at []string) string {
	if len(at) == 0 {
		return "[]"
	}
	key, _ := json.Marshal(at)
	return string(key)
}

// canonicalObject joins canonical members into a canonical JSON object.
func canonicalObject(fields map[string]json.RawMessage) json.RawMessage {
	return bytes.TrimSuffix(canonicalSourceFields(fields), []byte{'\n'})
}

// All field names are the ASCII source-schema names and all values are already
// canonical JSON. Selecting a subset preserves JCS without rescanning values.
func canonicalSourceFields(fields map[string]json.RawMessage) []byte {
	names := make([]string, 0, len(fields))
	size := 3
	for name, value := range fields {
		names = append(names, name)
		size += len(name) + len(value) + 4
	}
	sort.Strings(names)
	raw := make([]byte, 0, size)
	raw = append(raw, '{')
	for i, name := range names {
		if i > 0 {
			raw = append(raw, ',')
		}
		raw = append(raw, '"')
		raw = append(raw, name...)
		raw = append(raw, '"', ':')
		raw = append(raw, fields[name]...)
	}
	return append(raw, '}', '\n')
}

// CompileSource prepares a saved, normalized source document. Financial fields
// remain opaque here because PostgreSQL enforces every applicable live counter.
func CompileSource(raw []byte) (*Source, error) {
	document, err := ParseSourceDocument(raw)
	if err != nil {
		return nil, err
	}
	if document.Encrypted() {
		return nil, configError("encrypted plugins require the matching customer key")
	}
	return document.compile(nil, &celCompiler{prepare: true})
}

// RoutingSource prepares readable settings without opening plugin ciphertext.
// Activate retains the applicable envelopes for selected-only transformation.
func (d *SourceDocument) RoutingSource() (*Source, error) {
	source, err := d.compile(nil, &celCompiler{prepare: true})
	if err == nil && d.Encrypted() {
		source.encryptedPlugins = d
	}
	return source, err
}

// Compile readable settings. Encrypted plugins keep their separate document
// and are opened only when the caller has the required customer key.
func (d *SourceDocument) compile(plugins map[[32]byte]*Plugins, compiler *celCompiler) (*Source, error) {
	var err error
	fields := make(map[string]json.RawMessage, len(d.fields))
	for name, value := range d.fields {
		if name != "plugins" && name != "rules" {
			fields[name] = value
		}
	}
	canonical := canonicalSourceFields(fields)
	var doc sourceBody
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, configError("invalid source configuration: %v", err)
	}
	if doc.Schema != nil && *doc.Schema != "https://stogas.ai/schemas/policy-v1.json" {
		return nil, configError("unsupported source schema")
	}
	// Null cannot silently turn an explicitly supplied requirement off.
	if err := validateSourceMembers(canonical, reflect.TypeOf(doc)); err != nil {
		return nil, err
	}
	config := &Config{Schema: "stogas.key-config.compiled.v1", CompilerVersion: CompilerVersion, Access: doc.Access, Input: doc.Input, Timeouts: doc.Timeouts,
		Routing: Routing{Fallbacks: DefaultFallbacks}}
	source := &Source{Config: config, Digest: d.digest, Delegation: doc.Delegation, work: compiler.work()}
	source.settings = settingsMask(d.ownSections())

	if doc.Routing != nil {
		sorts := doc.Routing.Sort
		if doc.Routing.Filter != nil || sorts != nil {
			filter := ""
			if doc.Routing.Filter != nil {
				filter = *doc.Routing.Filter
			}
			if doc.Routing.Filter != nil && strings.TrimSpace(filter) == "" {
				return nil, configError("routing filter must not be empty")
			}
			if filter != "" || len(sorts) > 0 {
				config.Routing.Query, err = compileRouting(filter, sorts, compiler)
				if err != nil {
					return nil, err
				}
			}
		}
		config.Routing.Authors, config.Routing.Models, config.Routing.Deployments = doc.Routing.Authors, doc.Routing.Models, doc.Routing.Deployments
		config.Routing.Routes, config.Routing.Providers = doc.Routing.Routes, doc.Routing.Providers
		if doc.Routing.Retries != nil {
			config.Routing.Retries = *doc.Routing.Retries
		}
		if doc.Routing.Fallbacks != nil {
			config.Routing.Fallbacks = *doc.Routing.Fallbacks
		}
		if doc.Routing.Missing != nil {
			if value := *doc.Routing.Missing; value != MissingKeysFail && value != MissingKeysSkip {
				return nil, configError("routing.missingEncryptionKeys must be fail or skip")
			}
			config.Routing.MissingEncryptionKeys = *doc.Routing.Missing
		}
	}

	if err := config.validate(); err != nil {
		return nil, err
	}
	if raw := d.readablePlugins; len(raw) > 0 {
		identity := sha256.Sum256(raw)
		config.Plugins = plugins[identity]
		if config.Plugins == nil {
			config.Plugins, err = compileSourcePlugins(raw)
			if err != nil {
				return nil, err
			}
			if plugins != nil {
				plugins[identity] = config.Plugins
			}
		}
	}
	source.Rules, err = compileRules(d.rules, plugins, compiler)
	if err != nil {
		return nil, err
	}
	for _, rule := range source.Rules {
		source.excludes = source.excludes || rule.Exclude != nil
		if rule.Value.settings&permissionSort == 0 {
			continue
		}
		if source.defaultOrdering != nil {
			return nil, configError("set a default routing.sort in one rule with mode default and no when")
		}
		source.defaultOrdering = rule.Value.takeOrdering(rule.Name)
	}
	if compiler.prepare {
		// A stored policy that only a combined view shows passed these bounds
		// when it was saved.
		if err := source.checkSections(); err != nil {
			return nil, err
		}
	}
	return source, nil
}

func compileSourcePlugins(raw []byte) (*Plugins, error) {
	var doc struct {
		Classification []string             `json:"classification"`
		Export         *exportconfig.Config `json:"export"`
		PromptCaching  *string              `json:"promptCaching"`
		Redaction      *sourceRedaction     `json:"redaction"`
		TextExtraction TextExtraction       `json:"textExtraction"`
	}
	if err := decodeStrict(raw, &doc); err != nil {
		return nil, configError("invalid plugins: %v", err)
	}
	if err := validateSourceMembers(raw, reflect.TypeOf(doc)); err != nil {
		return nil, err
	}
	if doc.Redaction == nil && doc.TextExtraction == nil && doc.Export == nil && doc.PromptCaching == nil && doc.Classification == nil {
		return nil, configError("plugins require explicit configuration")
	}
	selected, err := compileSourceRedaction(doc.Redaction)
	if err != nil {
		return nil, err
	}
	result := &Plugins{Classification: doc.Classification, Redaction: selected, TextExtraction: doc.TextExtraction, Export: doc.Export}
	if doc.PromptCaching != nil {
		if err := validatePromptCaching(*doc.PromptCaching); err != nil {
			return nil, err
		}
		result.PromptCaching = *doc.PromptCaching
	}
	return result, result.validate()
}

type sourceRedaction struct {
	Presets       []string `json:"presets"`
	CustomPattern *string  `json:"customPattern"`
	Literals      []struct {
		Values     []string `json:"values"`
		IgnoreCase bool     `json:"ignoreCase"`
		WholeWord  *bool    `json:"wholeWord"`
		Fuzzy      bool     `json:"fuzzy"`
	} `json:"literals"`
	Parts  []string `json:"parts"`
	Action *string  `json:"action"`
}

func compileSourceRedaction(source *sourceRedaction) (*Redaction, error) {
	if source == nil {
		return nil, nil
	}
	if source.Presets != nil && len(source.Presets) == 0 {
		return nil, configError("redaction presets require at least one preset")
	}
	selected := &Redaction{Presets: []string{}}
	for _, name := range source.Presets {
		if !redactionPresets[name] {
			return nil, configError("unknown redaction preset %q", name)
		}
		if slices.Contains(selected.Presets, name) {
			return nil, configError("duplicate redaction preset %q", name)
		}
		selected.Presets = append(selected.Presets, name)
	}
	sort.Strings(selected.Presets)
	if source.CustomPattern != nil {
		selected.CustomPatterns = []string{*source.CustomPattern}
	}
	if source.Literals != nil && len(source.Literals) == 0 {
		return nil, configError("invalid literal groups")
	}
	for _, group := range source.Literals {
		if len(group.Values) == 0 || len(selected.Literals)+len(group.Values) > redaction.MaxLiterals {
			return nil, configError("literal groups require 1–1,000 values in total")
		}
		for _, text := range group.Values {
			selected.Literals = append(selected.Literals, redaction.Literal{Text: text, IgnoreCase: group.IgnoreCase, WholeWord: group.WholeWord, Fuzzy: group.Fuzzy})
		}
	}
	if len(selected.Literals) > 0 {
		if err := redaction.ValidateLiterals(selected.Literals); err != nil {
			return nil, err
		}
		selected.Literals = redaction.NormalizeLiterals(selected.Literals)
	}
	if source.Parts != nil {
		if len(source.Parts) == 0 {
			return nil, configError("redaction parts require at least one part")
		}
		parts, err := redactionParts(source.Parts)
		if err != nil {
			return nil, err
		}
		selected.Parts = canonicalRedactionParts(parts)
	}
	if source.Action != nil {
		if _, known := RedactionActions[*source.Action]; !known {
			return nil, configError("unknown redaction action %q", *source.Action)
		}
		// The default action has one spelling, so that equal redactions share a matcher.
		if *source.Action != "replace" {
			selected.Action = *source.Action
		}
	}
	compiled := &Plugins{Redaction: selected}
	if err := compiled.validate(); err != nil {
		return nil, err
	}
	return selected, nil
}

// canonicalRedactionParts names parts in one spelling: nothing for the whole request, which is
// the default, and "request" wherever every request part is read.
func canonicalRedactionParts(parts redaction.Parts) []string {
	if parts == redaction.RequestParts {
		return nil
	}
	var names []string
	for _, name := range RedactionParts {
		named := redaction.PartsOf(redaction.PartResponse)
		if part, ok := redactionRequestParts[name]; ok {
			named = redaction.PartsOf(part)
		} else if name == "request" {
			named = redaction.RequestParts
		}
		whole := parts&redaction.RequestParts == redaction.RequestParts
		if parts&named != named || whole && name != "request" && name != "response" {
			continue
		}
		names = append(names, name)
	}
	return names
}

// OpenSource compiles the complete plaintext policy inside the gateway. Source
// identity remains the stored ciphertext digest, so freshness does not disclose
// or depend on a plaintext digest outside protected memory.
func OpenSource(raw []byte, organizationID string, key customerkey.Keys) (*Source, error) {
	document, err := ParseSourceDocument(raw)
	if err != nil {
		return nil, err
	}
	return document.Open(organizationID, key)
}

// Open compiles the whole policy with every encrypted plugin decrypted, as a
// request policy or a policy check needs it.
func (d *SourceDocument) Open(organizationID string, key customerkey.Keys) (*Source, error) {
	if !d.Encrypted() {
		return d.compile(nil, &celCompiler{prepare: true})
	}
	// The readable settings hide nothing, so their errors keep their detail.
	source, err := d.compile(nil, &celCompiler{prepare: true})
	if err != nil {
		return nil, err
	}
	source.Config.Plugins, source.RequiredEncryptionKeyIDs, err = d.openPlugins(organizationID, key, pluginUnits, d.readablePlugins)
	if err != nil {
		return nil, err
	}
	source.Digest = d.digest
	return source, source.checkSections()
}

// OpenPlugins decrypts only the plugins in units, for a request that applies
// them. Its configuration holds those plugins alone: the policy's readable
// plugins already compose with its other settings.
func (d *SourceDocument) OpenPlugins(organizationID string, key customerkey.Keys, units Permission) (*Source, error) {
	plugins, ids, err := d.openPlugins(organizationID, key, units, nil)
	if err != nil {
		return nil, err
	}
	config := &Config{Schema: "stogas.key-config.compiled.v1", CompilerVersion: CompilerVersion, Routing: Routing{Fallbacks: DefaultFallbacks}, Plugins: plugins}
	return &Source{Config: config, Digest: d.digest, RequiredEncryptionKeyIDs: ids}, nil
}

// openPlugins decrypts each plugin in units with its own purpose and compiles
// it with the readable plugins, if any. Settings that fail to decrypt or
// compile report no detail, so that errors cannot show hidden values.
func (d *SourceDocument) openPlugins(organizationID string, key customerkey.Keys, units Permission, readable json.RawMessage) (*Plugins, []string, error) {
	section := map[string]json.RawMessage{}
	if len(readable) > 0 && jsonv2.Unmarshal(readable, &section) != nil {
		return nil, nil, configError("invalid plugins")
	}
	var opened [][]byte
	defer func() {
		for _, plaintext := range opened {
			clear(plaintext)
		}
	}()
	var ids []string
	for _, plugin := range d.encrypted {
		if plugin.unit&units == 0 {
			continue
		}
		plaintext, err := plugin.open(organizationID, key, &opened)
		if err != nil {
			return nil, nil, err
		}
		section[plugin.name] = json.RawMessage(plaintext)
		ids = plugin.keyIDs(ids)
	}
	if len(ids) == 0 {
		return nil, nil, configError("no encrypted plugin applies")
	}
	combined := canonicalSourceFields(section)
	defer clear(combined)
	plugins, err := compileSourcePlugins(combined)
	if err != nil {
		return nil, nil, configError("invalid encrypted plugin configuration")
	}
	return plugins, ids, nil
}

// encoding/json accepts case-insensitive aliases even with
// DisallowUnknownFields. Use the declared JSON tags as the sole field list,
// keeping source validation identical in Go, WASM, and the JSON Schema editor.
// RawMessage sections retain their own typed validation at their owner.
func validateSourceMembers(raw []byte, shape reflect.Type) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	var visit func(any, reflect.Type) error
	visit = func(value any, shape reflect.Type) error {
		for shape != nil && shape.Kind() == reflect.Pointer {
			shape = shape.Elem()
		}
		if shape == reflect.TypeFor[json.RawMessage]() {
			shape = nil
		}
		switch value := value.(type) {
		case nil:
			return configError("source policy fields cannot be null")
		case map[string]any:
			for name, child := range value {
				var childShape reflect.Type
				if shape != nil {
					switch shape.Kind() {
					case reflect.Struct:
						childShape = sourceJSONFields(shape)[name]
						if childShape == nil {
							return configError("unknown policy field %q", name)
						}
					case reflect.Map:
						childShape = shape.Elem()
					}
				}
				if err := visit(child, childShape); err != nil {
					return err
				}
			}
		case []any:
			var childShape reflect.Type
			if shape != nil && (shape.Kind() == reflect.Slice || shape.Kind() == reflect.Array) {
				childShape = shape.Elem()
			}
			for _, child := range value {
				if err := visit(child, childShape); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(value, shape)
}

var sourceFieldShapes sync.Map // reflect.Type -> immutable map of JSON tags

func sourceJSONFields(shape reflect.Type) map[string]reflect.Type {
	if fields, ok := sourceFieldShapes.Load(shape); ok {
		return fields.(map[string]reflect.Type)
	}
	fields := make(map[string]reflect.Type, shape.NumField())
	for i := 0; i < shape.NumField(); i++ {
		field := shape.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	stored, _ := sourceFieldShapes.LoadOrStore(shape, fields)
	return stored.(map[string]reflect.Type)
}

type Scope string

const (
	OrganizationScope Scope = "organization"
	FolderScope       Scope = "folder"
	GrantScope        Scope = "grant"
	RoleScope         Scope = "role"
	MemberScope       Scope = "member"
	CredentialScope   Scope = "credential"
	KeyScope          Scope = "key"
	RequestScope      Scope = "request"
)

func (s Scope) Valid() bool {
	switch s {
	case OrganizationScope, FolderScope, GrantScope, RoleScope, MemberScope, CredentialScope, KeyScope:
		return true
	}
	return false
}

// Resource names a resource whose policy applies to a key.
type Resource struct {
	Scope Scope
	ID    string
}

// ScopedSource separates applicability from shared immutable policy content.
// Identical policies may belong to different resources and organizations.
type ScopedSource struct {
	Scope Scope
	// ID names the resource. Rules that exclude it are skipped; a chain that
	// names no resources skips none.
	ID    string
	Value *Source
	// Activation adds a matched rule's settings with the rule's name and the
	// position of its policy.
	rule   string
	policy int
}

// Origin locates a composed setting by the position of its policy among the
// composed sources and, for a setting from a rule, the rule's name. Positions
// identify policies because equal content may belong to several resources.
type Origin struct {
	Source int
	Rule   string
}

// OriginScope is the scope of the policy at origin.
func (c *Config) OriginScope(origin Origin) Scope {
	return c.sources[origin.Source].Scope
}

func (c *Config) origin(index int) Origin {
	if entry := c.sources[index]; entry.rule != "" {
		return Origin{Source: entry.policy, Rule: entry.rule}
	}
	return Origin{Source: index}
}

// policyPosition is the position of the policy that holds the composed entry
// at index: the entry itself, or the policy of a rule's settings.
func policyPosition(entry ScopedSource, index int) int {
	if entry.rule != "" {
		return entry.policy
	}
	return index
}

// WorkLimitOrigin locates the policy whose expressions used up their
// allowance, and its scope.
func (c *Config) WorkLimitOrigin(err error) (Origin, Scope, bool) {
	var limit *WorkLimitError
	if c == nil || !errors.As(err, &limit) {
		return Origin{}, "", false
	}
	for i, entry := range c.sources {
		if entry.rule == "" && entry.Value != nil && entry.Value.work == limit.work {
			return Origin{Source: i}, entry.Scope, true
		}
	}
	return Origin{}, "", false
}

// allowedSettings returns the units a source may set. A default yields each
// unit that a required setting holds.
func (c *Config) allowedSettings(source *Source) Permission {
	if source.defaultSettings {
		return requestPermissions &^ c.requiredSettings
	}
	return requestPermissions
}

// FilterOrigin locates the composed routing filter at index.
func (c *Config) FilterOrigin(index int) (Origin, bool) {
	for i, entry := range c.sources {
		query := entry.Value.Config.Routing.Query
		if query == nil || c.allowedSettings(entry.Value)&permissionFilter == 0 {
			continue
		}
		if index < len(query.Filters) {
			return c.origin(i), true
		}
		index -= len(query.Filters)
	}
	return Origin{}, false
}

// DenyOrigin locates the first policy whose schedule refuses a request at
// now.
func (c *Config) DenyOrigin(now time.Time) (Origin, bool) {
	for i, entry := range c.sources {
		if c.allowedSettings(entry.Value)&permissionSchedule != 0 && entry.Value.Config.Access.schedule().refuses(now) {
			return c.origin(i), true
		}
	}
	return Origin{}, false
}

// ListsOrigin locates the first policy whose routing lists exclude a
// candidate.
func (c *Config) ListsOrigin(authorID, modelID, deploymentID, routeID, providerID string) (Origin, bool) {
	ids := [len(routingLists)]string{authorID, modelID, deploymentID, routeID, providerID}
	for i, entry := range c.sources {
		allowed := c.allowedSettings(entry.Value)
		for kind, list := range routingLists {
			if allowed&list.permission != 0 && !(*list.lists(&entry.Value.Config.Routing)).admits(ids[kind]) {
				return c.origin(i), true
			}
		}
	}
	return Origin{}, false
}

// FallbacksOrigin locates the policy that sets the composed fallback count.
func (c *Config) FallbacksOrigin() (Origin, bool) {
	for i, entry := range c.sources {
		if c.allowedSettings(entry.Value)&entry.Value.settings&permissionFallbacks != 0 &&
			entry.Value.Config.Routing.Fallbacks == c.Routing.Fallbacks {
			return c.origin(i), true
		}
	}
	return Origin{}, false
}

// MissingKeysOrigin locates the policy that decides what a candidate does
// when the request did not send an encryption key that it needs.
func (c *Config) MissingKeysOrigin() (Origin, bool) {
	for i, entry := range c.sources {
		if c.allowedSettings(entry.Value)&entry.Value.settings&permissionMissingKeys != 0 &&
			entry.Value.Config.Routing.MissingEncryptionKeys == c.Routing.MissingEncryptionKeys {
			return c.origin(i), true
		}
	}
	return Origin{}, false
}

// ReplacedDefault is a setting of a matched default rule that a requirement of
// the same kind replaces on one activated request and deployment.
type ReplacedDefault struct {
	// Setting names the section as policies write it, such as
	// plugins.redaction.
	Setting string
	// Default locates the default rule.
	Default Origin
	// By locates the first requirement in the chain that sets the same kind:
	// a policy's own settings, or a required rule that matched. Others counts
	// the rest.
	By     Origin
	Others int
}

type replaceableSetting struct {
	name string
	kind Permission
}

// replaceableSettings names each kind of setting that a requirement replaces,
// in name order. Orderings are never replaced: a default ordering orders the
// ties that the others leave.
var replaceableSettings = func() []replaceableSetting {
	var settings []replaceableSetting
	kinds := requestPermissions &^ permissionSort &^ permissionEncryptedPlugins
	for name, kind := range permissionSections {
		if kind&(kind-1) == 0 && kind&kinds == kind {
			settings = append(settings, replaceableSetting{name, kind})
		}
	}
	slices.SortFunc(settings, func(a, b replaceableSetting) int { return strings.Compare(a.name, b.name) })
	return settings
}()

// ReplacedDefaults lists, on an activated request, each setting of a matched
// default rule that a requirement replaces, by rule in the chain's order. It
// says for one request and deployment what the policy page can say only of
// every request.
func (c *Config) ReplacedDefaults() []ReplacedDefault {
	if c == nil {
		return nil
	}
	var out []ReplacedDefault
	for i, entry := range c.sources {
		replaced := entry.Value.settings & c.requiredSettings
		if !entry.Value.defaultSettings || replaced == 0 {
			continue
		}
		for _, setting := range replaceableSettings {
			if replaced&setting.kind == 0 {
				continue
			}
			found := ReplacedDefault{Setting: setting.name, Default: c.origin(i), Others: -1}
			for j, requirement := range c.sources {
				if !requirement.Value.defaultSettings && requirement.Value.settings&setting.kind != 0 {
					if found.Others < 0 {
						found.By = c.origin(j)
					}
					found.Others++
				}
			}
			out = append(out, found)
		}
	}
	return out
}

// SortOrigins locates the policy, and for a default ordering its rule, that
// sets each composed routing.sort criterion. The first RequiredSorts are
// required; the rest are defaults.
func (c *Config) SortOrigins() []Origin { return c.sortOrigins }

// RequiredSorts counts the required criteria that lead the composed sort. A
// request's provider order comes after them, before the defaults.
func (c *Config) RequiredSorts() int { return c.requiredSorts }

// ChainDigest names the settings that a chain composes: each policy's scope
// and content and, after them, the names of its rules that the chain skips.
// Keys with equal policies share composed settings unless a rule excludes a
// resource of only some of them.
func ChainDigest(sources []ScopedSource) string {
	values := make([][]string, len(sources))
	for i, source := range sources {
		values[i] = []string{string(source.Scope), source.Value.Digest}
		if !source.Value.excludes {
			continue
		}
		for _, rule := range source.Value.Rules {
			if _, skipped := rule.excludedBy(sources); skipped {
				values[i] = append(values[i], rule.Name)
			}
		}
	}
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ComposeSources shares immutable expression trees, access windows and plugin
// sections. It never concatenates large inherited PII dictionaries into a key.
// Policies that each compile always compose: every bound is one policy's own,
// so no policy's edit can make another's requests fail to combine.
func ComposeSources(chain []ScopedSource) (*Config, error) {
	sources, err := applyExclusions(chain)
	if err != nil {
		return nil, err
	}
	out, err := composeApplied(sources)
	if err != nil {
		return nil, err
	}
	for i, entry := range sources {
		if entry.Value != chain[i].Value {
			out.copiedBytes += int64(unsafe.Sizeof(*entry.Value)) + int64(cap(entry.Value.Rules))*int64(unsafe.Sizeof(Rule{}))
		}
	}
	return out, nil
}

// composeApplied composes a chain whose skipped rules are already left out.
func composeApplied(sources []ScopedSource) (*Config, error) {
	out, err := composeSettings(sources)
	if err != nil {
		return nil, err
	}
	out.sources = append([]ScopedSource{}, sources...)
	for _, entry := range sources {
		out.hasRules = out.hasRules || len(entry.Value.Rules) > 0 || entry.Value.encryptedPlugins != nil
	}
	return out, nil
}

func composeSettings(sources []ScopedSource) (*Config, error) {
	if len(sources) == 0 || sources[0].Scope != OrganizationScope {
		return nil, configError("organization source is required")
	}
	out := &Config{Schema: "stogas.key-config.compiled.v1", CompilerVersion: CompilerVersion, RequestPermission: RequestPermission(requestPermissions), Routing: Routing{Fallbacks: DefaultFallbacks}}
	if sources[0].Value == nil {
		return nil, configError("organization source is required")
	}
	for _, entry := range sources {
		if entry.Value != nil && !entry.Value.defaultSettings {
			out.requiredSettings |= entry.Value.settings
		}
	}
	hasRequestPermission := false
	var filters []*CELExpression
	// Required orderings apply from the broadest scope to the request, then
	// defaults from the request to the broadest scope.
	var required, defaults []placedOrdering
	// The smallest value among the policies that set one applies.
	var retries, fallbacks *int
	// A candidate whose encryption key the request did not send fails the
	// request unless a policy skips it and none fails it.
	missingKeys := ""
	seenPlugins := map[*Plugins]bool{}
	seenPeriods := map[string]bool{}
	var networks []*Networks
	var countries, transportLists []*Lists
	var catalogLists [len(routingLists)][]*Lists
	for index, entry := range sources {
		scope, source := entry.Scope, entry.Value
		if !scope.Valid() && scope != RequestScope || source == nil {
			return nil, configError("invalid policy source scope or content")
		}
		for _, id := range source.RequiredEncryptionKeyIDs {
			if !slices.Contains(out.RequiredEncryptionKeys, id) {
				out.RequiredEncryptionKeys = append(out.RequiredEncryptionKeys, id)
			}
		}
		if err := source.Delegation.validateScope(scope); err != nil {
			return nil, err
		}
		if scope == CredentialScope && source.requestWide() {
			return nil, configError("credential policies cannot set routing.sort, routing.fallbacks or timeouts.totalSeconds")
		}
		if source.orders() {
			rank, ok := orderingRanks[scope]
			if !ok {
				return nil, configError("%s policies cannot set routing.sort", scope)
			}
			// Rule parts carry no ordering: compile moved each default
			// ordering to its policy.
			if query := source.Config.Routing.Query; source.settings&permissionSort != 0 && query != nil && len(query.OrderBy) > 0 {
				required = append(required, placedOrdering{query.OrderBy, Origin{Source: index}, rank})
			}
			if source.defaultOrdering != nil {
				defaults = append(defaults, placedOrdering{source.defaultOrdering.sorts, Origin{Source: index, Rule: source.defaultOrdering.rule}, rank})
			}
		}
		config := source.Config
		allowed := out.allowedSettings(source)
		if source.Delegation != nil && source.Delegation.Requests != nil {
			hasRequestPermission = true
			out.RequestPermission &= *source.Delegation.Requests
		}
		if in := config.Input; in != nil {
			if allowed&permissionASCIIOnly != 0 && in.ASCIIOnly {
				out.Input = out.Input.combine(&Input{ASCIIOnly: true})
			}
			if allowed&permissionMediaTypes != 0 && in.MediaTypes != nil {
				out.Input = out.Input.combine(&Input{MediaTypes: in.MediaTypes})
			}
		}
		if config.Timeouts != nil {
			if out.Timeouts == nil {
				out.Timeouts = &Timeouts{}
			}
			if value := config.Timeouts.TotalSeconds; allowed&permissionTotalTimeout != 0 && value != nil && (out.Timeouts.TotalSeconds == nil || *value < *out.Timeouts.TotalSeconds) {
				out.Timeouts.TotalSeconds = value
			}
			if value := config.Timeouts.OutputIdleSeconds; allowed&permissionOutputIdleTimeout != 0 && value != nil && (out.Timeouts.OutputIdleSeconds == nil || *value < *out.Timeouts.OutputIdleSeconds) {
				out.Timeouts.OutputIdleSeconds = value
			}
		}
		// A request must fall in a period of every allow list and in no deny
		// period of any policy.
		if schedule := config.Access.schedule(); allowed&permissionSchedule != 0 && schedule != nil {
			combined := func() *Schedule {
				if out.Access == nil {
					out.Access = &Access{}
				}
				if out.Access.Schedule == nil {
					out.Access.Schedule = &Schedule{}
				}
				return out.Access.Schedule
			}
			for _, window := range schedule.Deny {
				if raw, _ := json.Marshal(window); !seenPeriods[string(raw)] {
					combined().Deny = append(combined().Deny, window)
					seenPeriods[string(raw)] = true
				}
			}
			for _, allow := range schedule.allows {
				if raw, _ := json.Marshal(allow); !seenPeriods["allow"+string(raw)] {
					combined().allows = append(combined().allows, allow)
					seenPeriods["allow"+string(raw)] = true
				}
			}
		}
		// A client must be in an allowed network of every policy that lists
		// them, and in no denied network of any policy.
		if allowed&permissionNetworks != 0 && config.Access != nil && config.Access.Networks != nil {
			networks = append(networks, config.Access.Networks)
		}
		if allowed&permissionCountries != 0 && config.Access != nil && config.Access.Countries != nil {
			countries = append(countries, config.Access.Countries)
		}
		// A request must use a mode that every policy allows and that no
		// policy denies.
		if allowed&permissionTransports != 0 && config.Access != nil && config.Access.Transports != nil {
			transportLists = append(transportLists, config.Access.Transports)
		}
		// A candidate must be in every allow list of a kind and in no deny list.
		for kind, list := range routingLists {
			if lists := *list.lists(&config.Routing); lists != nil && allowed&list.permission != 0 {
				catalogLists[kind] = append(catalogLists[kind], lists)
			}
		}
		set := allowed & source.settings
		if set&permissionRetries != 0 && (retries == nil || *retries > config.Routing.Retries) {
			retries = &config.Routing.Retries
		}
		if set&permissionFallbacks != 0 && (fallbacks == nil || *fallbacks > config.Routing.Fallbacks) {
			fallbacks = &config.Routing.Fallbacks
		}
		if set&permissionMissingKeys != 0 && missingKeys != MissingKeysFail {
			missingKeys = config.Routing.MissingEncryptionKeys
		}
		if q := config.Routing.Query; q != nil && allowed&permissionFilter != 0 {
			filters = append(filters, q.Filters...)
		}
		// A default yields only the plugins that a requirement sets.
		if plugins := config.Plugins.only(allowed & pluginUnits); plugins != nil && !seenPlugins[plugins] {
			out.PluginSources = append(out.PluginSources, plugins)
			out.pluginPolicies = append(out.pluginPolicies, policyPosition(entry, index))
			seenPlugins[plugins] = true
		}
	}
	if !hasRequestPermission {
		out.RequestPermission = 0
	}
	for kind, list := range routingLists {
		*list.lists(&out.Routing) = combineLists(catalogLists[kind])
	}
	if networks != nil || countries != nil || transportLists != nil {
		if out.Access == nil {
			out.Access = &Access{}
		}
		out.Access.Networks = combineNetworks(networks)
		out.Access.Countries = combineLists(countries)
		out.Access.Transports = combineLists(transportLists)
	}
	if retries != nil {
		out.Routing.Retries = *retries
	}
	if fallbacks != nil {
		out.Routing.Fallbacks = *fallbacks
	}
	out.Routing.MissingEncryptionKeys = missingKeys
	sorts, err := out.placeSorts(required, defaults)
	if err != nil {
		return nil, err
	}
	if sorts == nil {
		sorts = []Sort{}
	}
	if len(filters) > 0 || len(sorts) > 0 {
		out.Routing.Query = &Query{OrderBy: sorts, Filters: filters}
	}
	return out, nil
}

func (s *Source) orders() bool {
	return s.settings&permissionSort != 0 || s.defaultOrdering != nil
}

// placedOrdering is one policy's ordering with its origin and chain rank.
type placedOrdering struct {
	sorts  []Sort
	origin Origin
	rank   int
}

// placeSorts joins the required orderings, broadest first, and then the
// defaults, closest first, so a narrower policy breaks the ties that a
// broader requirement leaves, and its defaults outrank broader defaults. A
// criterion equal to an earlier one cannot break its ties, so it is left out.
func (c *Config) placeSorts(required, defaults []placedOrdering) ([]Sort, error) {
	for _, list := range [][]placedOrdering{required, defaults} {
		slices.SortStableFunc(list, func(a, b placedOrdering) int { return a.rank - b.rank })
		for i := 1; i < len(list); i++ {
			if list[i].rank == list[i-1].rank {
				return nil, configError("several policies of one scope set routing.sort")
			}
		}
	}
	var sorts []Sort
	seen := map[string]bool{}
	add := func(placed placedOrdering) {
		for _, criterion := range placed.sorts {
			if key := criterion.key(); !seen[key] {
				seen[key] = true
				sorts = append(sorts, criterion)
				c.sortOrigins = append(c.sortOrigins, placed.origin)
			}
		}
	}
	for _, placed := range required {
		add(placed)
	}
	c.requiredSorts = len(sorts)
	for i := len(defaults) - 1; i >= 0; i-- {
		add(defaults[i])
	}
	return sorts, nil
}

// A credential policy applies only to that credential's candidates, so its
// order, fallback count or total wait would differ from those of other
// credentials.
func (s *Source) requestWide() bool {
	set := s.orders() || s.settings&requestWidePermissions != 0
	for _, rule := range s.Rules {
		set = set || rule.Value.settings&requestWidePermissions != 0
	}
	return set
}
