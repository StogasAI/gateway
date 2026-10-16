package policy

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

// Inspection shares the execution compiler. Persistence, resource access and
// counter projection belong to its caller; this package performs no I/O.
type Inspection struct {
	Compiled        *Config           `json:"compiled"`
	CompilerVersion int               `json:"compilerVersion"`
	Digest          string            `json:"digest"`
	Effective       map[string]any    `json:"effective,omitempty"`
	Conditions      map[string]string `json:"conditions,omitempty"`
	Notes           []InspectionNote  `json:"notes,omitempty"`
}

// InspectionNote names another policy that affects the edited one. "kept"
// lists sections that the policy no longer lets the edited one set; they still
// apply. "order" means that policy's ordering applies instead of the edited
// one's.
type InspectionNote struct {
	Kind     string   `json:"kind"`
	Scope    Scope    `json:"scope"`
	ID       string   `json:"id,omitempty"`
	Sections []string `json:"sections,omitempty"`
}

type InspectionSource struct {
	Scope  Scope           `json:"scope"`
	ID     string          `json:"id,omitempty"`
	Config json.RawMessage `json:"config"`
}

type InspectionEdit struct {
	Scope    Scope           `json:"scope"`
	ID       string          `json:"id,omitempty"`
	Previous json.RawMessage `json:"previous,omitempty"`
}

var ErrPolicyEditForbidden = errors.New("a parent policy does not permit this policy edit")

type policyEditError struct {
	scope, parent Scope
	sections      []string
}

func (e policyEditError) Error() string {
	return fmt.Sprintf("The %s policy does not let %s policies set %s", e.parent, e.scope, strings.Join(e.sections, ", "))
}

func (e policyEditError) Unwrap() error { return ErrPolicyEditForbidden }

func InspectSource(raw []byte) (*Inspection, error) {
	document, err := ParseSourceDocument(raw)
	if err != nil {
		return nil, err
	}
	source, err := document.compile(nil, &celCompiler{prepare: true})
	if err != nil {
		return nil, err
	}
	if err := validateInspectionPlugins(source.Config.Plugins); err != nil {
		return nil, err
	}
	for _, rule := range source.Rules {
		if err := validateInspectionPlugins(rule.Value.Config.Plugins); err != nil {
			return nil, err
		}
	}
	if source.Config.Input != nil && !source.Config.Input.ASCIIOnly {
		source.Config.Input = nil
	}
	conditions := make(map[string]string)
	for _, rule := range source.Rules {
		if rule.HasLimits {
			conditions[rule.Name] = rule.ConditionDigest()
		}
	}
	return &Inspection{Compiled: source.Config, CompilerVersion: CompilerVersion, Digest: source.Digest, Conditions: conditions}, nil
}

// Inspector compiles one bounded source at a time and then composes the result.
// It retains no source JSON except the document currently being edited. This
// lets constrained hosts inspect large opaque policies without copying an
// entire organization's ciphertext into one intermediate JSON document.
type Inspector struct {
	entries        []InspectionSource
	documents      []*SourceDocument
	sources        []ScopedSource
	plugins        map[[32]byte]*Plugins
	envelopes      map[[32]byte]encryptedPlugin
	seen           map[[32]byte]int
	edit           *InspectionEdit
	omitCiphertext bool
	ruleBytes      int
	budget         SourceBudget
}

// omitCiphertext lets bindings retain input envelopes in their host instead of
// copying them through the combined result. Source digests still cover them.
func NewInspector(edit *InspectionEdit, omitCiphertext bool) *Inspector {
	return &Inspector{edit: edit, omitCiphertext: omitCiphertext, seen: make(map[[32]byte]int), plugins: make(map[[32]byte]*Plugins), envelopes: make(map[[32]byte]encryptedPlugin)}
}

func (v *Inspector) Add(entry InspectionSource) error {
	if len(v.entries) >= 36 {
		return configError("at most 36 sources may apply")
	}
	identity := sha256.Sum256(entry.Config)
	var document *SourceDocument
	var source *Source
	if prior, ok := v.seen[identity]; ok {
		document, source = v.documents[prior], v.sources[prior].Value
		v.ruleBytes += document.previewRuleBytes
	} else {
		var err error
		document, err = parseSourceDocument(entry.Config, v.envelopes)
		if err != nil {
			return err
		}
		if err := v.budget.add(document.size); err != nil {
			return err
		}
		v.ruleBytes += document.previewRuleBytes
		if v.ruleBytes > MaxCompiledBytes {
			return configError("combined policy exceeds the size limit")
		}
		source, err = document.compile(v.plugins, &celCompiler{})
		if err != nil {
			return err
		}
		if err := v.budget.add(source.size); err != nil {
			return err
		}
		// Execution fields live in Source; only the source limits and rules
		// remain necessary to render the preview.
		document.canonical = nil
		for name := range document.fields {
			if name != "limits" {
				delete(document.fields, name)
			}
		}
		if v.omitCiphertext {
			if document.Encrypted() {
				document.encrypted.Blob = ""
			}
		}
		for _, rule := range document.rules {
			rule.source.canonical, rule.source.fields = nil, nil
			if rule.source.Encrypted() {
				// The preview owns the original envelope, unless the host retains it.
				rule.source.encrypted.Blob = ""
				if v.omitCiphertext {
					rule.fields["plugins"] = json.RawMessage(`{"encrypted":{}}`)
				}
			}
		}
		v.seen[identity] = len(v.entries)
	}
	if v.ruleBytes > MaxCompiledBytes {
		return configError("combined policy exceeds the size limit")
	}
	if !v.edit.covers(entry) {
		entry.Config = nil
	}
	v.entries = append(v.entries, entry)
	v.documents = append(v.documents, document)
	v.sources = append(v.sources, ScopedSource{Scope: entry.Scope, Value: source})
	return nil
}

// InspectSources composes stored sources for display. Validate each edited
// source with InspectSource before saving; unchanged expressions do not need
// execution programs to produce the combined view.
func InspectSources(entries []InspectionSource, edit *InspectionEdit) (*Inspection, error) {
	inspector := NewInspector(edit, false)
	for _, entry := range entries {
		if err := inspector.Add(entry); err != nil {
			return nil, err
		}
	}
	return inspector.Finish()
}

func (v *Inspector) Finish() (*Inspection, error) {
	entries, documents, sources, edit := v.entries, v.documents, v.sources, v.edit
	compiled, err := ComposeSources(sources)
	if err != nil {
		return nil, err
	}
	delegation, notes, err := inspectDelegation(entries, documents, sources, edit)
	if err != nil {
		return nil, err
	}
	delegation["request"] = compiled.RequestPermission
	effective := map[string]any{"delegation": delegation}
	if len(compiled.EncryptionKeys) > 0 {
		effective["encryption"] = map[string]any{"keys": compiled.EncryptionKeys}
	}
	if compiled.Input != nil {
		effective["input"] = compiled.Input
	}
	if compiled.Timeouts != nil {
		effective["timeouts"] = compiled.Timeouts
	}
	if compiled.Access != nil && len(compiled.Access.Deny) > 0 {
		effective["access"] = compiled.Access
	}
	routing := map[string]any{}
	if compiled.Routing.AllowedCatalogNodes != nil {
		routing["allowedCatalogNodes"] = sortedAllowedNodes(compiled.Routing.AllowedCatalogNodes)
	}
	if len(compiled.Routing.Order) > 0 {
		routing["order"] = compiled.Routing.Order
	}
	if compiled.orderScope != "" {
		from := InspectionSource{Scope: compiled.orderScope}
		for _, entry := range entries {
			if entry.Scope == from.Scope {
				from = entry
			}
		}
		reference := inspectionReference(from)
		reference["mode"] = map[bool]string{false: "required", true: "default"}[compiled.orderDefault]
		routing["orderFrom"] = reference
		for i, entry := range entries {
			if edit.covers(entry) && entry.Scope != from.Scope && sources[i].Value.orders() {
				notes = append(notes, InspectionNote{Kind: "order", Scope: from.Scope, ID: from.ID})
			}
		}
	}
	if compiled.Routing.Query != nil {
		if len(compiled.Routing.Query.Filters) > 0 {
			routing["filter"] = queryFilterSource(compiled.Routing.Query)
		}
		if len(compiled.Routing.Query.OrderBy) > 0 {
			routing["sort"] = compiled.Routing.Query.OrderBy
		}
	}
	var limits, opaque, rules []map[string]any
	opaqueRuleBytes := 0
	for i, entry := range entries {
		document := documents[i]
		for _, rule := range sources[i].Value.Rules {
			item := inspectionReference(entry)
			item["name"], item["config"] = rule.Name, document.rules[rule.Name].fields
			rules = append(rules, item)
			if rule.Encrypted != nil && !v.omitCiphertext {
				opaqueRuleBytes += rule.Encrypted.envelopeBytes
			}
		}
		if raw := document.fields["limits"]; len(raw) > 0 {
			limit := inspectionReference(entry)
			limit["config"] = raw
			limits = append(limits, limit)
		}
		settings := sources[i].Value.settings
		if settings&permissionRetries != 0 {
			routing["retries"] = compiled.Routing.Retries
		}
		if settings&permissionFallbacks != 0 {
			routing["fallbacks"] = compiled.Routing.Fallbacks
		}
		if document.Encrypted() {
			if !customerkey.Registered(compiled.EncryptionKeys, document.encrypted.KeyID) {
				return nil, configError("register the plugin encryption key identifier in the organization policy")
			}
			item := inspectionReference(entry)
			item["encrypted"] = document.encrypted
			opaque = append(opaque, item)
		}
	}
	if len(routing) > 0 {
		effective["routing"] = routing
	}
	if len(limits) > 0 {
		effective["limits"] = limits
	}
	if len(rules) > 0 {
		effective["rules"] = rules
	}
	plugins, err := inspectionPlugins(compiled.PluginSources)
	if err != nil {
		return nil, err
	}
	if plugins != nil {
		effective["plugins"] = plugins
	}
	// The preview may flatten plugin descriptions; runtime composition continues
	// sharing the original immutable plugin sections and their matchers.
	compiled.Plugins = plugins
	raw, err := json.Marshal(effective)
	if err != nil || len(raw)+1-opaqueRuleBytes > MaxCompiledBytes {
		return nil, configError("combined policy exceeds the size limit")
	}
	// Opaque sections have their own stored-source bounds. Their base64 bytes
	// are not compiled instructions and cannot be charged to this limit.
	if len(opaque) > 0 {
		effective["uncheckedPlugins"] = opaque
	}
	return &Inspection{Compiled: compiled, CompilerVersion: CompilerVersion, Digest: ChainDigest(sources), Effective: effective, Notes: notes}, nil
}

func inspectionReference(entry InspectionSource) map[string]any {
	value := map[string]any{"scope": entry.Scope}
	if entry.ID != "" {
		value["id"] = entry.ID
	}
	return value
}

func validateInspectionPlugins(plugins *Plugins) error {
	if plugins == nil || plugins.StogasRedaction == nil {
		return nil
	}
	patterns := make([]redaction.CustomPattern, 0, len(plugins.StogasRedaction.CustomPatterns))
	for _, pattern := range plugins.StogasRedaction.CustomPatterns {
		patterns = append(patterns, redaction.CustomPattern{Expression: pattern})
	}
	return redaction.ValidateCustomPatterns(patterns)
}

func inspectionPlugins(parts []*Plugins) (*Plugins, error) {
	if len(parts) == 0 {
		return nil, nil
	}
	presets, patterns := map[string]bool{}, map[string]bool{}
	selected := &Redaction{Presets: []string{}}
	plugins := &Plugins{}
	var exports []*exportconfig.Config
	for _, part := range parts {
		if part.StogasExport != nil {
			exports = append(exports, part.StogasExport)
		}
		if part.StogasTextExtraction != nil {
			enabled := *part.StogasTextExtraction || plugins.StogasTextExtraction != nil && *plugins.StogasTextExtraction
			plugins.StogasTextExtraction = &enabled
		}
		if part.StogasRedaction == nil {
			continue
		}
		plugins.StogasRedaction = selected
		for _, preset := range part.StogasRedaction.Presets {
			presets[preset] = true
		}
		for _, pattern := range part.StogasRedaction.CustomPatterns {
			patterns[pattern] = true
		}
		selected.Literals = append(selected.Literals, part.StogasRedaction.Literals...)
	}
	if len(exports) > 0 {
		var err error
		plugins.StogasExport, err = exportconfig.Combine(exports...)
		if err != nil {
			return nil, err
		}
	}
	for preset := range presets {
		selected.Presets = append(selected.Presets, preset)
	}
	for pattern := range patterns {
		selected.CustomPatterns = append(selected.CustomPatterns, pattern)
	}
	sort.Strings(selected.Presets)
	sort.Strings(selected.CustomPatterns)
	selected.Literals = redaction.NormalizeLiterals(selected.Literals)
	if err := plugins.validate(); err != nil {
		return nil, err
	}
	return plugins, validateInspectionPlugins(plugins)
}

func sortedAllowedNodes(value *AllowedCatalogNodes) *AllowedCatalogNodes {
	copy := *value
	for _, ids := range []*[]string{&copy.Authors, &copy.Models, &copy.Deployments, &copy.Routes, &copy.Providers} {
		if *ids != nil {
			*ids = append([]string{}, (*ids)...)
			sort.Strings(*ids)
		}
	}
	return &copy
}

func (e *InspectionEdit) covers(entry InspectionSource) bool {
	return e != nil && e.Scope == entry.Scope && (e.ID == "" || e.ID == entry.ID)
}

// A policy may keep sections that its parents no longer permit, but it cannot
// add or change them. A move passes no previous policy, so the new parents
// check every section.
func inspectDelegation(entries []InspectionSource, documents []*SourceDocument, sources []ScopedSource, edit *InspectionEdit) (map[string]any, []InspectionNote, error) {
	ids := make(map[Scope]string, len(entries))
	for _, entry := range entries {
		ids[entry.Scope] = entry.ID
	}
	permissions := map[Scope]Permission{}
	for _, scope := range []Scope{FolderScope, GrantScope, RoleScope, MemberScope, CredentialScope, KeyScope} {
		permissions[scope] = allPermissions
	}
	var notes []InspectionNote
	for i, entry := range entries {
		if edit.covers(entry) && entry.Scope != OrganizationScope {
			kept := documents[i].usedSections
			changed := kept
			if edit.Previous != nil {
				proposal, err := ParseSourceDocument(entry.Config)
				if err != nil {
					return nil, nil, err
				}
				// An unreadable previous policy keeps nothing.
				previous, _ := ParseSourceDocument(edit.Previous)
				changed = changedSections(proposal, previous)
			}
			for j, parent := range sources[:i] {
				allowed := parent.Value.Delegation.saved()[entry.Scope].Permission(entry.ID)
				if blocked := changed &^ allowed; blocked != 0 {
					return nil, nil, policyEditError{scope: entry.Scope, parent: entries[j].Scope, sections: blocked.sectionNames()}
				}
				if blocked := kept &^ allowed; blocked != 0 {
					notes = append(notes, InspectionNote{Kind: "kept", Scope: entries[j].Scope, ID: entries[j].ID, Sections: blocked.sectionNames()})
					kept &^= blocked
				}
			}
		}
		for target, rule := range sources[i].Value.Delegation.saved() {
			permissions[target] &= rule.Permission(ids[target])
		}
	}
	result := map[string]any{}
	for scope, permission := range permissions {
		if permission != allPermissions {
			result[delegationTarget(scope)] = permission
		}
	}
	return result, notes, nil
}

func delegationTarget(scope Scope) string {
	if scope == KeyScope {
		return "keys"
	}
	if scope == CredentialScope {
		return "credentials"
	}
	return string(scope) + "s"
}

func queryFilterSource(query *Query) string {
	if len(query.Filters) == 1 {
		return query.Filters[0].Source
	}
	values := make([]string, len(query.Filters))
	for i, filter := range query.Filters {
		values[i] = "(" + filter.Source + ")"
	}
	return strings.Join(values, " && ")
}
