package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

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
	Rules                   []Rule
	settings                Permission
	defaultSettings         bool
	encryptedPlugins        *SourceDocument
	EncryptionKeys          map[string]string
	RequiredEncryptionKeyID string
	Config                  *Config
	Digest                  string
	Delegation              *Delegation
	HasCandidates           bool
	previewRuleBytes        int
	size                    sourceSize
}

// SourceDocument retains the checked canonical bytes until compilation. Its
// immutable identity lets callers find an existing source before compiling it.
type SourceDocument struct {
	canonical        []byte
	digest           string
	encrypted        *customerkey.Envelope
	fields           map[string]json.RawMessage
	rules            map[string]ruleDocument
	usedSections     Permission
	envelopeBytes    int
	previewRuleBytes int
	size             sourceSize
}

type encryptedPlugin struct {
	envelope customerkey.Envelope
	bytes    int
}

// Budget distinct source settings and plugin sections. Ciphertext counts by
// decoded plaintext length; its contents cannot prove equality before opening.
type sourceSize struct {
	digest   string
	settings int
	nodes    int
	plugins  map[[32]byte]int
}

// SourceBudget bounds distinct policy content and compilation across a request's
// alternatives. Its zero value is ready for use; it is local to one request.
type SourceBudget struct {
	bytes   int
	nodes   int
	sources map[string]int
	plugins map[[32]byte]bool
	err     error
}

var ErrSourceBudget = fmt.Errorf("%w: combined policy exceeds its compilation budget", ErrInvalidConfig)

func (b *SourceBudget) AddDocument(document *SourceDocument) error {
	if b == nil || document == nil {
		return nil
	}
	return b.add(document.size)
}

func (b *SourceBudget) AddConfig(config *Config) error {
	if b == nil || config == nil {
		return nil
	}
	for _, entry := range config.sources {
		if err := b.AddSource(entry.Value); err != nil {
			return err
		}
	}
	return b.err
}

func (b *SourceBudget) AddSource(source *Source) error {
	if b == nil || source == nil {
		return nil
	}
	return b.add(source.size)
}

func (b *SourceBudget) add(size sourceSize) error {
	if b.err != nil {
		return b.err
	}
	priorNodes, seen := b.sources[size.digest]
	additional := 0
	if !seen {
		additional = size.settings
		for digest, bytes := range size.plugins {
			if !b.plugins[digest] {
				additional += bytes
			}
		}
	}
	if b.bytes+additional > MaxCompiledBytes {
		b.err = fmt.Errorf("%w: combined policy exceeds the size limit", ErrSourceBudget)
		return b.err
	}
	additionalNodes := max(0, size.nodes-priorNodes)
	if b.nodes+additionalNodes > MaxCombinedCELNodes {
		b.err = fmt.Errorf("%w: combined policy exceeds the %d-node CEL compilation limit", ErrSourceBudget, MaxCombinedCELNodes)
		return b.err
	}
	if b.sources == nil {
		b.sources, b.plugins = make(map[string]int), make(map[[32]byte]bool)
	}
	b.sources[size.digest] = max(priorNodes, size.nodes)
	b.bytes += additional
	b.nodes += additionalNodes
	for digest := range size.plugins {
		b.plugins[digest] = true
	}
	return nil
}

type sourceBody struct {
	Schema     *string `json:"$schema"`
	Encryption *struct {
		Keys map[string]string `json:"keys"`
	} `json:"encryption"`
	Rules      json.RawMessage `json:"rules"`
	Limits     json.RawMessage `json:"limits"`
	Delegation *Delegation     `json:"delegation"`
	Access     *Access         `json:"access"`
	Input      *Input          `json:"input"`
	Plugins    json.RawMessage `json:"plugins"`
	Routing    *struct {
		Allowed   *AllowedCatalogNodes `json:"allowedCatalogNodes"`
		Filter    *string              `json:"filter"`
		Sort      []Sort               `json:"sort"`
		Fallbacks *struct {
			Candidates int `json:"maxPreDispatchCandidates"`
		} `json:"fallbacks"`
	} `json:"routing"`
}

func (d *SourceDocument) Digest() string        { return d.digest }
func (d *SourceDocument) CanonicalJSON() []byte { return bytes.Clone(d.canonical) }
func (d *SourceDocument) Encrypted() bool       { return d.encrypted != nil }
func (d *SourceDocument) EncryptionKeyID() string {
	if d.encrypted == nil {
		return ""
	}
	return d.encrypted.KeyID
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
	var pluginIdentity [32]byte
	if plugins := fields["plugins"]; len(plugins) > 0 {
		pluginIdentity = sha256.Sum256(plugins)
		if cached, ok := envelopes[pluginIdentity]; ok {
			document.encrypted, document.envelopeBytes = &cached.envelope, cached.bytes
		} else {
			var section map[string]json.RawMessage
			if jsonv2.Unmarshal(plugins, &section) == nil && section["encrypted"] != nil {
				var envelope customerkey.Envelope
				// v2 matches field names exactly. Every envelope member is required
				// and Validate rejects its zero value, including JSON null.
				if len(section) != 1 || jsonv2.Unmarshal(section["encrypted"], &envelope, jsonv2.RejectUnknownMembers(true)) != nil || envelope.Validate(MaxSourceBytes) != nil {
					return nil, configError("invalid encrypted plugins")
				}
				document.encrypted = &envelope
				document.envelopeBytes = len(section["encrypted"])
				if envelopes != nil {
					envelopes[pluginIdentity] = encryptedPlugin{envelope, document.envelopeBytes}
				}
			}
		}
		if document.Encrypted() {
			contentBytes += len(document.encrypted.Blob)*3/4 - 16 - len(plugins)
		}
	}
	// Flat rules share the source's content budget. Ciphertext length counts
	// decoded plugin bytes, just as it does for the root plugin section.
	var err error
	document.rules, err = parseRuleDocuments(fields["rules"], envelopes)
	if err != nil {
		return nil, err
	}
	document.previewRuleBytes = len(fields["rules"])
	for _, rule := range document.rules {
		if child := rule.source; child.Encrypted() {
			contentBytes += len(child.encrypted.Blob)*3/4 - 16 - len(child.fields["plugins"])
			document.previewRuleBytes -= child.envelopeBytes
		}
	}
	if contentBytes > MaxSourceBytes {
		return nil, configError("source configuration exceeds size limit")
	}
	sum := sha256.Sum256(canonical)
	document.digest = hex.EncodeToString(sum[:])
	document.size = sourceSize{digest: document.digest, settings: len(canonical), plugins: make(map[[32]byte]int)}
	if raw := fields["plugins"]; raw != nil {
		document.size.settings -= len(raw)
		size := len(raw)
		if document.Encrypted() {
			size = len(document.encrypted.Blob)*3/4 - 16
		}
		document.size.plugins[pluginIdentity] = size
	}
	for _, rule := range document.rules {
		document.size.settings -= len(rule.source.fields["plugins"])
		for digest, size := range rule.source.size.plugins {
			document.size.plugins[digest] = size
		}
	}
	document.usedSections = document.sections()
	return document, nil
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
	initialNodes := compiler.nodes
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
	if doc.Schema != nil && *doc.Schema != "https://stogas.ai/schemas/key-config-v1.json" {
		return nil, configError("unsupported source schema")
	}
	if doc.Encryption != nil && customerkey.ValidateRegistry(doc.Encryption.Keys) != nil {
		return nil, configError("encryption keys require unique identifiers and lowercase labels")
	}
	// Null cannot silently turn an explicitly supplied requirement off.
	if err := validateSourceMembers(canonical, reflect.TypeOf(doc)); err != nil {
		return nil, err
	}
	config := &Config{Schema: "stogas.key-config.compiled.v1", CompilerVersion: CompilerVersion, Access: doc.Access, Input: doc.Input,
		Routing: Routing{MaxPreDispatchCandidates: 1}}
	source := &Source{Config: config, Digest: d.digest, Delegation: doc.Delegation, size: d.size}
	source.settings = settingsMask(d.ownSections())
	if doc.Encryption != nil {
		source.EncryptionKeys = doc.Encryption.Keys
	}

	if doc.Routing != nil {
		if doc.Routing.Filter != nil || doc.Routing.Sort != nil {
			filter := ""
			if doc.Routing.Filter != nil {
				filter = *doc.Routing.Filter
			}
			if doc.Routing.Filter != nil && strings.TrimSpace(filter) == "" {
				return nil, configError("routing filter must not be empty")
			}
			if filter != "" || len(doc.Routing.Sort) > 0 {
				config.Routing.Query, err = compileRouting(filter, doc.Routing.Sort, compiler)
				if err != nil {
					return nil, err
				}
			}
		}
		config.Routing.AllowedCatalogNodes = doc.Routing.Allowed
		if doc.Routing.Fallbacks != nil {
			source.HasCandidates = true
			config.Routing.MaxPreDispatchCandidates = doc.Routing.Fallbacks.Candidates
		}
	}

	if err := config.validate(); err != nil {
		return nil, err
	}
	if raw := d.fields["plugins"]; len(raw) > 0 && !d.Encrypted() {
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
		source.previewRuleBytes += rule.previewBytes
	}
	source.size.nodes = compiler.nodes - initialNodes
	return source, nil
}

func compileSourcePlugins(raw []byte) (*Plugins, error) {
	var doc struct {
		Export         *exportconfig.Config       `json:"stogasExport"`
		Redaction      map[string]json.RawMessage `json:"stogasRedaction"`
		TextExtraction *bool                      `json:"stogasTextExtraction"`
	}
	if err := decodeStrict(raw, &doc); err != nil {
		return nil, configError("invalid plugins: %v", err)
	}
	if err := validateSourceMembers(raw, reflect.TypeOf(doc)); err != nil {
		return nil, err
	}
	if doc.Redaction == nil && doc.TextExtraction == nil && doc.Export == nil {
		return nil, configError("plugins require explicit configuration")
	}
	selected, err := compileSourceRedaction(doc.Redaction)
	if err != nil {
		return nil, err
	}
	result := &Plugins{StogasRedaction: selected, StogasTextExtraction: doc.TextExtraction, StogasExport: doc.Export}
	return result, result.validate()
}

func compileSourceRedaction(values map[string]json.RawMessage) (*Redaction, error) {
	if values == nil {
		return nil, nil
	}
	selected := &Redaction{Presets: []string{}}
	for name, value := range values {
		switch name {
		case "customPattern":
			var pattern string
			if err := json.Unmarshal(value, &pattern); err != nil {
				return nil, configError("invalid custom pattern")
			}
			selected.CustomPatterns = []string{pattern}
		case "literals":
			var groups []struct {
				Values     []string `json:"values"`
				IgnoreCase bool     `json:"ignoreCase"`
				WholeWord  *bool    `json:"wholeWord"`
				Fuzzy      bool     `json:"fuzzy"`
			}
			if err := decodeStrict(value, &groups); err != nil || len(groups) == 0 {
				return nil, configError("invalid literal groups")
			}
			if err := validateSourceMembers(value, reflect.TypeOf(groups)); err != nil {
				return nil, err
			}
			for _, group := range groups {
				if len(group.Values) == 0 || len(selected.Literals)+len(group.Values) > redaction.MaxLiterals {
					return nil, configError("literal groups require 1–1,000 values in total")
				}
				for _, text := range group.Values {
					selected.Literals = append(selected.Literals, redaction.Literal{Text: text, IgnoreCase: group.IgnoreCase, WholeWord: group.WholeWord, Fuzzy: group.Fuzzy})
				}
			}
			if err := redaction.ValidateLiterals(selected.Literals); err != nil {
				return nil, err
			}
			selected.Literals = redaction.NormalizeLiterals(selected.Literals)
		default:
			if !redactionPresets[name] {
				return nil, configError("unknown redaction preset %s", name)
			}
			var enabled bool
			if err := json.Unmarshal(value, &enabled); err != nil {
				return nil, configError("invalid redaction preset")
			}
			if enabled {
				selected.Presets = append(selected.Presets, name)
			}
		}
	}
	sort.Strings(selected.Presets)
	compiled := &Plugins{StogasRedaction: selected}
	if err := compiled.validate(); err != nil {
		return nil, err
	}
	return selected, nil
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

func (d *SourceDocument) Open(organizationID string, key customerkey.Keys) (*Source, error) {
	if d.encrypted == nil {
		return d.compile(nil, &celCompiler{prepare: true})
	}
	envelope := *d.encrypted
	plaintext, err := key.Open(envelope, organizationID, "plugins", MaxSourceBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	if !jsontext.Value(plaintext).IsValid() {
		return nil, configError("invalid encrypted plugin JSON")
	}
	source, err := d.compile(nil, &celCompiler{prepare: true})
	if err != nil {
		return nil, configError("invalid encrypted plugin configuration")
	}
	source.Config.Plugins, err = compileSourcePlugins(plaintext)
	if err != nil {
		return nil, configError("invalid encrypted plugin configuration")
	}
	source.Digest, source.RequiredEncryptionKeyID = d.digest, envelope.KeyID
	// Opening does not change the saved collection's byte accounting. A new
	// nonce or padding still consumed ciphertext processing before decryption.
	nodes := source.size.nodes
	source.size = d.size
	source.size.nodes = nodes
	return source, nil
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

// ScopedSource separates applicability from shared immutable policy content.
// Identical policies may belong to different resources and organizations.
type ScopedSource struct {
	Scope Scope
	Value *Source
}

func ChainDigest(sources []ScopedSource) string {
	values := make([][2]string, len(sources))
	for i, source := range sources {
		values[i] = [2]string{string(source.Scope), source.Value.Digest}
	}
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(append(raw, '\n'))
	return hex.EncodeToString(sum[:])
}

// ComposeSources shares immutable expression trees, access windows and plugin
// sections. It never concatenates large inherited PII dictionaries into a key.
func ComposeSources(sources []ScopedSource) (*Config, error) {
	var budget SourceBudget
	for _, entry := range sources {
		if entry.Value != nil {
			if err := budget.add(entry.Value.size); err != nil {
				return nil, err
			}
		}
	}
	out, err := composeSettings(sources)
	if err != nil {
		return nil, err
	}
	out.sources = append([]ScopedSource{}, sources...)
	for _, entry := range sources {
		out.hasRules = out.hasRules || len(entry.Value.Rules) > 0 || entry.Value.encryptedPlugins != nil
		if encrypted := entry.Value.encryptedPlugins; encrypted != nil && !customerkey.Registered(out.EncryptionKeys, encrypted.EncryptionKeyID()) {
			return nil, customerkey.ErrKey
		}
		for _, rule := range entry.Value.Rules {
			if rule.Encrypted != nil && !customerkey.Registered(out.EncryptionKeys, rule.Encrypted.EncryptionKeyID()) {
				return nil, customerkey.ErrKey
			}
		}
	}
	return out, nil
}

func composeSettings(sources []ScopedSource) (*Config, error) {
	if len(sources) == 0 || sources[0].Scope != OrganizationScope {
		return nil, configError("organization source is required")
	}
	out := &Config{Schema: "stogas.key-config.compiled.v1", CompilerVersion: CompilerVersion, RequestPermission: RequestPermission(requestPermissions), Routing: Routing{MaxPreDispatchCandidates: 1}}
	if sources[0].Value == nil {
		return nil, configError("organization source is required")
	}
	out.EncryptionKeys = sources[0].Value.EncryptionKeys
	ruleBytes := 0
	for _, entry := range sources {
		if entry.Value != nil {
			ruleBytes += entry.Value.previewRuleBytes
		}
		if entry.Value != nil && !entry.Value.defaultSettings {
			out.requiredSettings |= entry.Value.settings
		}
	}
	if ruleBytes > MaxCompiledBytes {
		return nil, configError("combined policy exceeds the size limit")
	}
	hasRequestPermission := false
	var filters []*CELExpression
	sorts := []Sort{}
	var candidates *int
	seenPlugins := map[*Plugins]bool{}
	seenWindows := map[string]bool{}
	for _, entry := range sources {
		scope, source := entry.Scope, entry.Value
		if !scope.Valid() && scope != RequestScope || source == nil {
			return nil, configError("invalid policy source scope or content")
		}
		if scope != OrganizationScope && source.EncryptionKeys != nil {
			return nil, configError("only organization policy may register encryption keys")
		}
		if source.RequiredEncryptionKeyID != "" {
			if !customerkey.Registered(out.EncryptionKeys, source.RequiredEncryptionKeyID) {
				return nil, customerkey.ErrKey
			}
			if !slices.Contains(out.RequiredEncryptionKeys, source.RequiredEncryptionKeyID) {
				out.RequiredEncryptionKeys = append(out.RequiredEncryptionKeys, source.RequiredEncryptionKeyID)
			}
		}
		if err := source.Delegation.validateScope(scope); err != nil {
			return nil, err
		}
		config := source.Config
		allowed := requestPermissions
		if source.defaultSettings {
			allowed &^= out.requiredSettings
		}
		if source.Delegation != nil && source.Delegation.Request != nil {
			hasRequestPermission = true
			out.RequestPermission &= *source.Delegation.Request
		}
		if allowed&permissionInput != 0 && config.Input != nil && config.Input.ASCIIOnly {
			out.Input = config.Input
		}
		if allowed&permissionAccess != 0 && config.Access != nil {
			if out.Access == nil {
				out.Access = &Access{}
			}
			for _, window := range config.Access.Deny {
				raw, _ := json.Marshal(window)
				if !seenWindows[string(raw)] {
					out.Access.Deny = append(out.Access.Deny, window)
					seenWindows[string(raw)] = true
				}
			}
		}
		if allowed&permissionNodes != 0 {
			out.Routing.AllowedCatalogNodes = intersectAllowedNodes(out.Routing.AllowedCatalogNodes, config.Routing.AllowedCatalogNodes)
		}
		if allowed&permissionFallbacks != 0 && source.HasCandidates && (candidates == nil || *candidates > config.Routing.MaxPreDispatchCandidates) {
			candidates = &config.Routing.MaxPreDispatchCandidates
		}
		if q := config.Routing.Query; q != nil {
			if allowed&permissionFilter != 0 {
				filters = append(filters, q.Filters...)
			}
			if allowed&permissionSort != 0 && len(q.OrderBy) > 0 {
				if len(sorts) > 0 && !(&Query{OrderBy: sorts}).SameOrder(q) {
					return nil, configError("applicable policies require different routing sort orders")
				}
				sorts = q.OrderBy
				out.Routing.SortDefault = source.defaultSettings
			}
		}
		if allowed&pluginPermissions != 0 && config.Plugins != nil && !seenPlugins[config.Plugins] {
			out.PluginSources = append(out.PluginSources, config.Plugins)
			seenPlugins[config.Plugins] = true
		}
	}
	if !hasRequestPermission {
		out.RequestPermission = 0
	}
	if candidates != nil {
		out.Routing.MaxPreDispatchCandidates = *candidates
	}
	if len(filters) > 0 || len(sorts) > 0 {
		out.Routing.Query = &Query{OrderBy: sorts, Filters: filters}
	}
	if err := out.validateCombined(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Config) ValidatePlugins() error {
	if _, err := c.ExportConfig(); err != nil {
		return err
	}
	// Validate aggregate redaction limits without retaining a copied dictionary.
	if len(c.PluginSources) > 1 {
		var literals []redaction.Literal
		patterns := map[string]bool{}
		for _, plugins := range c.PluginSources {
			p := plugins.StogasRedaction
			if p == nil {
				continue
			}
			literals = append(literals, p.Literals...)
			for _, pattern := range p.CustomPatterns {
				patterns[pattern] = true
			}
		}
		if len(patterns) > MaxCustomPatterns {
			return configError("combined custom patterns exceed limit")
		}
		if err := redaction.ValidateLiterals(redaction.NormalizeLiterals(literals)); err != nil {
			return err
		}

	}
	return nil
}

func (c *Config) validateCombined() error {
	if err := c.ValidatePlugins(); err != nil {
		return err
	}
	// Access windows have already been initialized once in their source. Calling
	// validate here would mutate shared maps while other requests read them.
	if err := c.Routing.Query.validate(); err != nil {
		return err
	}
	if err := c.Routing.AllowedCatalogNodes.validate(); err != nil {
		return err
	}
	return nil
}
