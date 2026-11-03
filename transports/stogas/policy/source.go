package policy

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
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
	"time"

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
	EncryptionKeys   map[string]string
	// RequiredEncryptionKeyIDs names the roots of the plugins that opening
	// this source decrypted.
	RequiredEncryptionKeyIDs []string
	Config                   *Config
	Digest                   string
	Delegation               *Delegation
	previewRuleBytes         int
	size                     sourceSize
}

// ordering is a policy's routing.sort, with routing.order as its leading
// deployments list. Every ordering applies: each criterion orders the ties of
// the ones before it.
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
	s.settings &^= orderingPermissions
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
	pluginDelta      int
	fields           map[string]json.RawMessage
	rules            map[string]ruleDocument
	usedSections     Permission
	envelopeBytes    int
	previewRuleBytes int
	size             sourceSize
}

// encryptedPlugin is one plugin's settings under a customer key.
type encryptedPlugin struct {
	name     string
	unit     Permission
	envelope customerkey.Envelope
	// bytes counts the envelope's JSON, which previews leave to their host.
	bytes int
}

// plaintextBytes is the decrypted settings' length: the decoded ciphertext
// without its 16-byte tag.
func (p encryptedPlugin) plaintextBytes() int { return len(p.envelope.Blob)*3/4 - 16 }

// encryptablePlugins are the plugins whose settings a customer key can
// encrypt, each on its own. A text extraction switch has no secret, and its
// ciphertext's length would show which way it is set.
var encryptablePlugins = []struct {
	name string
	unit Permission
}{{"export", permissionExport}, {"redaction", permissionRedaction}}

// pluginPurpose binds a plugin's ciphertext to that plugin, so that moving it
// under another plugin cannot decrypt it.
func pluginPurpose(name string) string { return "plugins/" + name }

// EncryptedPlugins is the encrypted plugin settings of one policy or rule
// that apply to a request: the plugins in Units.
type EncryptedPlugins struct {
	Document *SourceDocument
	Units    Permission
}

// EncryptionKeyIDs names the roots that open the applied plugins.
func (e EncryptedPlugins) EncryptionKeyIDs() []string { return e.Document.encryptionKeyIDs(e.Units) }

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
	Timeouts   *Timeouts       `json:"timeouts"`
	Plugins    json.RawMessage `json:"plugins"`
	Routing    *struct {
		Allowed   *AllowedCatalogNodes `json:"allowedCatalogNodes"`
		Filter    *string              `json:"filter"`
		Sort      []Sort               `json:"sort"`
		Order     []string             `json:"order"`
		Retries   *int                 `json:"retries"`
		Fallbacks *int                 `json:"fallbacks"`
		Missing   *string              `json:"missingEncryptionKeys"`
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
		if plugin.unit&units != 0 && !slices.Contains(ids, plugin.envelope.KeyID) {
			ids = append(ids, plugin.envelope.KeyID)
		}
	}
	return ids
}

// EncryptedPlugin is one encrypted plugin of a document. A policy check opens
// the plugins whose root it has and names the others.
type EncryptedPlugin struct {
	Name     string
	Unit     Permission
	Envelope customerkey.Envelope
}

func (d *SourceDocument) EncryptedPlugins() []EncryptedPlugin {
	plugins := make([]EncryptedPlugin, len(d.encrypted))
	for i, plugin := range d.encrypted {
		plugins[i] = EncryptedPlugin{Name: plugin.name, Unit: plugin.unit, Envelope: plugin.envelope}
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
	var pluginIdentity [32]byte
	if plugins := fields["plugins"]; len(plugins) > 0 {
		pluginIdentity = sha256.Sum256(plugins)
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
	document.previewRuleBytes = len(fields["rules"])
	for _, rule := range document.rules {
		contentBytes += rule.source.pluginDelta
		document.previewRuleBytes -= rule.source.envelopeBytes
	}
	if contentBytes > MaxSourceBytes {
		return nil, configError("source configuration exceeds size limit")
	}
	// Logs, receipts and Control's policy_version.sha512 name this digest, so like
	// every RFC 8785 identity it excludes the document file's trailing newline.
	// Customers write this content, so its hash resists collisions at ML-DSA-65's level.
	sum := sha512.Sum512(bytes.TrimSuffix(canonical, []byte{'\n'}))
	document.digest = hex.EncodeToString(sum[:])
	document.size = sourceSize{digest: document.digest, settings: len(canonical), plugins: make(map[[32]byte]int)}
	if raw := fields["plugins"]; raw != nil {
		document.size.settings -= len(raw)
		document.size.plugins[pluginIdentity] = len(raw) + document.pluginDelta
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

// parsePlugins finds the plugins whose settings a customer key encrypts. Each
// holds only its envelope, as {"encrypted": envelope}; the rest of the section
// stays readable and compiles with the policy's other settings.
func (d *SourceDocument) parsePlugins(raw json.RawMessage, envelopes map[[32]byte]encryptedPlugin) error {
	d.readablePlugins = raw
	var section map[string]json.RawMessage
	if jsonv2.Unmarshal(raw, &section) != nil || section == nil {
		// Readable compilation reports the invalid section.
		return nil
	}
	if section["encrypted"] != nil {
		return configError("encrypt plugins.export or plugins.redaction on its own")
	}
	for _, plugin := range encryptablePlugins {
		member := section[plugin.name]
		if member == nil {
			continue
		}
		identity := sha256.Sum256(member)
		parsed, cached := envelopes[identity]
		if !cached {
			var fields map[string]json.RawMessage
			if jsonv2.Unmarshal(member, &fields) != nil || fields["encrypted"] == nil {
				continue
			}
			// v2 matches field names exactly. Every envelope member is required
			// and Validate rejects its zero value, including JSON null.
			if len(fields) != 1 || jsonv2.Unmarshal(fields["encrypted"], &parsed.envelope, jsonv2.RejectUnknownMembers(true)) != nil || parsed.envelope.Validate(MaxSourceBytes) != nil {
				return configError("invalid encrypted %s plugin", plugin.name)
			}
			parsed.bytes = len(fields["encrypted"])
			if envelopes != nil {
				envelopes[identity] = parsed
			}
		}
		parsed.name, parsed.unit = plugin.name, plugin.unit
		d.encrypted = append(d.encrypted, parsed)
		d.envelopeBytes += parsed.bytes
		d.pluginDelta += parsed.plaintextBytes() - len(member)
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
	config := &Config{Schema: "stogas.key-config.compiled.v1", CompilerVersion: CompilerVersion, Access: doc.Access, Input: doc.Input, Timeouts: doc.Timeouts,
		Routing: Routing{Fallbacks: DefaultFallbacks}}
	source := &Source{Config: config, Digest: d.digest, Delegation: doc.Delegation, size: d.size}
	source.settings = settingsMask(d.ownSections())
	if doc.Encryption != nil {
		source.EncryptionKeys = doc.Encryption.Keys
	}

	if doc.Routing != nil {
		sorts := doc.Routing.Sort
		if doc.Routing.Order != nil {
			if err := validateOrder(doc.Routing.Order); err != nil {
				return nil, err
			}
			// routing.order is the deployments list that leads routing.sort.
			sorts = append([]Sort{{Deployments: doc.Routing.Order}}, sorts...)
		}
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
		config.Routing.AllowedCatalogNodes = doc.Routing.Allowed
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
		source.previewRuleBytes += rule.previewBytes
		if rule.Value.settings&orderingPermissions == 0 {
			continue
		}
		if source.defaultOrdering != nil {
			return nil, configError("set a default routing.sort in one rule with mode default and no when")
		}
		source.defaultOrdering = rule.Value.takeOrdering(rule.Name)
	}
	source.size.nodes = compiler.nodes - initialNodes
	return source, nil
}

func compileSourcePlugins(raw []byte) (*Plugins, error) {
	var doc struct {
		Export         *exportconfig.Config       `json:"export"`
		Redaction      map[string]json.RawMessage `json:"redaction"`
		TextExtraction *bool                      `json:"textExtraction"`
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
	result := &Plugins{Redaction: selected, TextExtraction: doc.TextExtraction, Export: doc.Export}
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
	compiled := &Plugins{Redaction: selected}
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
	// Opening does not change the saved collection's byte accounting. A new
	// nonce or padding still consumed ciphertext processing before decryption.
	nodes := source.size.nodes
	source.size = d.size
	source.size.nodes = nodes
	return source, nil
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
	return &Source{Config: config, Digest: d.digest, RequiredEncryptionKeyIDs: ids, size: d.size}, nil
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
		plaintext, err := key.Open(plugin.envelope, organizationID, pluginPurpose(plugin.name), MaxSourceBytes)
		if err != nil {
			return nil, nil, err
		}
		opened = append(opened, plaintext)
		if !jsontext.Value(plaintext).IsValid() {
			return nil, nil, configError("invalid encrypted plugin JSON")
		}
		section[plugin.name] = plaintext
		if !slices.Contains(ids, plugin.envelope.KeyID) {
			ids = append(ids, plugin.envelope.KeyID)
		}
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

// ScopedSource separates applicability from shared immutable policy content.
// Identical policies may belong to different resources and organizations.
type ScopedSource struct {
	Scope Scope
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

func (c *Config) origin(index int) Origin {
	if entry := c.sources[index]; entry.rule != "" {
		return Origin{Source: entry.policy, Rule: entry.rule}
	}
	return Origin{Source: index}
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

// DenyOrigin locates the first deny period that covers now.
func (c *Config) DenyOrigin(now time.Time) (Origin, bool) {
	for i, entry := range c.sources {
		access := entry.Value.Config.Access
		if access == nil || c.allowedSettings(entry.Value)&permissionAccess == 0 {
			continue
		}
		for index := range access.Deny {
			if access.Deny[index].covers(now) {
				return c.origin(i), true
			}
		}
	}
	return Origin{}, false
}

// NodesOrigin locates the first allowed catalog nodes that exclude a candidate.
func (c *Config) NodesOrigin(authorID, modelID, deploymentID, routeID, providerID string) (Origin, bool) {
	for i, entry := range c.sources {
		if c.allowedSettings(entry.Value)&permissionNodes != 0 &&
			!entry.Value.Config.Routing.AllowedCatalogNodes.Allows(authorID, modelID, deploymentID, routeID, providerID) {
			return c.origin(i), true
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

// SortOrigins locates the policy, and for a default ordering its rule, that
// sets each composed routing.sort criterion. The first RequiredSorts are
// required; the rest are defaults.
func (c *Config) SortOrigins() []Origin { return c.sortOrigins }

// RequiredSorts counts the required criteria that lead the composed sort. A
// request's provider order comes after them, before the defaults.
func (c *Config) RequiredSorts() int { return c.requiredSorts }

func ChainDigest(sources []ScopedSource) string {
	values := make([][2]string, len(sources))
	for i, source := range sources {
		values[i] = [2]string{string(source.Scope), source.Value.Digest}
	}
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
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
		if !registered(out.EncryptionKeys, entry.Value.encryptedPlugins) {
			return nil, customerkey.ErrKey
		}
		for _, rule := range entry.Value.Rules {
			if !registered(out.EncryptionKeys, rule.Encrypted) {
				return nil, customerkey.ErrKey
			}
		}
	}
	return out, nil
}

// registered reports whether the organization policy registers the root of
// every encrypted plugin in document.
func registered(keys map[string]string, document *SourceDocument) bool {
	if document == nil {
		return true
	}
	for _, id := range document.EncryptionKeyIDs() {
		if !customerkey.Registered(keys, id) {
			return false
		}
	}
	return true
}

func composeSettings(sources []ScopedSource) (*Config, error) {
	if len(sources) == 0 || sources[0].Scope != OrganizationScope {
		return nil, configError("organization source is required")
	}
	out := &Config{Schema: "stogas.key-config.compiled.v1", CompilerVersion: CompilerVersion, RequestPermission: RequestPermission(requestPermissions), Routing: Routing{Fallbacks: DefaultFallbacks}}
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
	// Required orderings apply from the broadest scope to the request, then
	// defaults from the request to the broadest scope.
	var required, defaults []placedOrdering
	// The smallest value among the policies that set one applies.
	var retries, fallbacks *int
	// A candidate whose encryption key the request did not send fails the
	// request unless a policy skips it and none fails it.
	missingKeys := ""
	seenPlugins := map[*Plugins]bool{}
	seenWindows := map[string]bool{}
	for index, entry := range sources {
		scope, source := entry.Scope, entry.Value
		if !scope.Valid() && scope != RequestScope || source == nil {
			return nil, configError("invalid policy source scope or content")
		}
		if scope != OrganizationScope && source.EncryptionKeys != nil {
			return nil, configError("only organization policy may register encryption keys")
		}
		for _, id := range source.RequiredEncryptionKeyIDs {
			if !customerkey.Registered(out.EncryptionKeys, id) {
				return nil, customerkey.ErrKey
			}
			if !slices.Contains(out.RequiredEncryptionKeys, id) {
				out.RequiredEncryptionKeys = append(out.RequiredEncryptionKeys, id)
			}
		}
		if err := source.Delegation.validateScope(scope); err != nil {
			return nil, err
		}
		if scope == CredentialScope && source.requestWide() {
			return nil, configError("credential policies cannot set routing.order, routing.sort, routing.fallbacks or timeouts.totalSeconds")
		}
		if source.orders() {
			rank, ok := orderingRanks[scope]
			if !ok {
				return nil, configError("%s policies cannot set routing.order or routing.sort", scope)
			}
			// Rule parts carry no ordering: compile moved each default
			// ordering to its policy.
			if query := source.Config.Routing.Query; source.settings&orderingPermissions != 0 && query != nil && len(query.OrderBy) > 0 {
				required = append(required, placedOrdering{query.OrderBy, Origin{Source: index}, rank})
			}
			if source.defaultOrdering != nil {
				defaults = append(defaults, placedOrdering{source.defaultOrdering.sorts, Origin{Source: index, Rule: source.defaultOrdering.rule}, rank})
			}
		}
		config := source.Config
		allowed := out.allowedSettings(source)
		if source.Delegation != nil && source.Delegation.Request != nil {
			hasRequestPermission = true
			out.RequestPermission &= *source.Delegation.Request
		}
		if allowed&permissionInput != 0 && config.Input != nil && config.Input.ASCIIOnly {
			out.Input = config.Input
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
			seenPlugins[plugins] = true
		}
	}
	if !hasRequestPermission {
		out.RequestPermission = 0
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
	if err := out.validateCombined(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Source) orders() bool {
	return s.settings&orderingPermissions != 0 || s.defaultOrdering != nil
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
				return nil, configError("several policies of one scope set routing.order or routing.sort")
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

func (c *Config) ValidatePlugins() error {
	if _, err := c.ExportConfig(); err != nil {
		return err
	}
	// Validate aggregate redaction limits without retaining a copied dictionary.
	if len(c.PluginSources) > 1 {
		var literals []redaction.Literal
		patterns := map[string]bool{}
		for _, plugins := range c.PluginSources {
			p := plugins.Redaction
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
	// Each source checked its own filter and sort; the composed sort may hold
	// more criteria and several lists of one kind, from different policies.
	if err := c.Routing.AllowedCatalogNodes.validate(); err != nil {
		return err
	}
	return nil
}
