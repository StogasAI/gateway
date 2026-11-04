package policy

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
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
// apply. "replaced" lists the edited policy's default settings that the
// policy's required settings replace, on every request, or with Rules only on
// the requests that those rules match.
type InspectionNote struct {
	Kind     string   `json:"kind"`
	Scope    Scope    `json:"scope"`
	ID       string   `json:"id,omitempty"`
	Sections []string `json:"sections,omitempty"`
	Rules    []string `json:"rules,omitempty"`
	// RuleCount counts the rules when there are more than Rules lists.
	RuleCount int `json:"ruleCount,omitempty"`
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
			for i := range document.encrypted {
				document.encrypted[i].envelope.Blob = ""
			}
		}
		for _, rule := range document.rules {
			rule.source.canonical, rule.source.fields = nil, nil
			if rule.source.Encrypted() {
				// The preview owns the original envelopes, unless the host retains them.
				for i := range rule.source.encrypted {
					rule.source.encrypted[i].envelope.Blob = ""
				}
				if v.omitCiphertext {
					var plugins map[string]json.RawMessage
					if json.Unmarshal(rule.fields["plugins"], &plugins) == nil {
						for _, plugin := range rule.source.encrypted {
							plugins[plugin.name] = json.RawMessage(`{"encrypted":{}}`)
						}
						rule.fields["plugins"] = canonicalObject(plugins)
					}
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
	if compiled.Routing.Query != nil {
		if len(compiled.Routing.Query.Filters) > 0 {
			routing["filter"] = queryFilterSource(compiled.Routing.Query)
		}
		if len(compiled.Routing.Query.OrderBy) > 0 {
			routing["sort"] = compiled.Routing.Query.OrderBy
			// Each run of criteria that one policy sets names the policy, and
			// a default run its rule. The editor links each policy object.
			var from []map[string]any
			for i, origin := range compiled.sortOrigins {
				if i > 0 && origin == compiled.sortOrigins[i-1] {
					from[len(from)-1]["criteria"] = from[len(from)-1]["criteria"].(int) + 1
					continue
				}
				run := map[string]any{"policy": inspectionReference(entries[origin.Source]), "criteria": 1}
				if origin.Rule != "" {
					run["rule"] = origin.Rule
				}
				from = append(from, run)
			}
			routing["sortFrom"] = from
		}
	}
	var limits, opaque, rules []map[string]any
	opaqueRuleBytes := 0
	required := requirements(sources)
	replacements := replacedDefaults(documents, sources, required)
	notes = append(notes, replacedNotes(entries, documents, sources, required, edit)...)
	replaced := map[int][]replacement{}
	for i, entry := range entries {
		document := documents[i]
		for _, rule := range sources[i].Value.Rules {
			config := document.rules[rule.Name].fields
			// A default ordering joins routing.sort, whose sortFrom names its
			// rule, so the rule lists only its other settings, if it has any.
			if ordering := sources[i].Value.defaultOrdering; ordering != nil && ordering.rule == rule.Name {
				if config = withoutOrdering(config); len(ruleSettings(config)) == 0 {
					continue
				}
			}
			item := map[string]any{"policy": inspectionReference(entry), "name": rule.Name, "config": config}
			if list := replacements[ruleKey{i, rule.Name}]; len(list) > 0 {
				replaced[len(rules)] = list
			}
			rules = append(rules, item)
			if rule.Encrypted != nil && !v.omitCiphertext {
				opaqueRuleBytes += rule.Encrypted.envelopeBytes
			}
		}
		if raw := document.fields["limits"]; len(raw) > 0 {
			limits = append(limits, map[string]any{"policy": inspectionReference(entry), "config": raw})
		}
		settings := sources[i].Value.settings
		if settings&permissionRetries != 0 {
			routing["retries"] = compiled.Routing.Retries
		}
		if settings&permissionFallbacks != 0 {
			routing["fallbacks"] = compiled.Routing.Fallbacks
		}
		if settings&permissionMissingKeys != 0 {
			routing["missingEncryptionKeys"] = compiled.Routing.MissingEncryptionKeys
		}
		for _, plugin := range document.encrypted {
			if !customerkey.Registered(compiled.EncryptionKeys, plugin.envelope.KeyID) {
				return nil, configError("register the plugin encryption key identifier in the organization policy")
			}
			opaque = append(opaque, map[string]any{"policy": inspectionReference(entry), "plugin": plugin.name, "encrypted": plugin.envelope})
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
	if setBy := inspectionSetBy(entries, sources, compiled); len(setBy) > 0 {
		effective["setBy"] = setBy
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
	// Which defaults a requirement replaces explains the composition rather
	// than adding to it, so it is not charged to the limit either. Each entry
	// names a requirement and leaves its condition to the rule's own item.
	for index, list := range replaced {
		values := make([]map[string]any, len(list))
		for i, r := range list {
			values[i] = map[string]any{"setting": r.setting, "policy": inspectionReference(entries[r.source])}
			if r.rule != "" {
				values[i]["rule"] = r.rule
			}
			if r.when != "" {
				values[i]["conditional"] = true
			}
			if r.others > 0 {
				values[i]["others"] = r.others
			}
		}
		rules[index]["replaced"] = values
	}
	return &Inspection{Compiled: compiled, CompilerVersion: CompilerVersion, Digest: ChainDigest(sources), Effective: effective, Notes: notes}, nil
}

// inspectionReference names a source policy. Limits, rules and encrypted
// sections nest it under "policy", so that their own fields stay distinct.
func inspectionReference(entry InspectionSource) map[string]any {
	value := map[string]any{"scope": entry.Scope}
	if entry.ID != "" {
		value["id"] = entry.ID
	}
	return value
}

func validateInspectionPlugins(plugins *Plugins) error {
	if plugins == nil || plugins.Redaction == nil {
		return nil
	}
	patterns := make([]redaction.CustomPattern, 0, len(plugins.Redaction.CustomPatterns))
	for _, pattern := range plugins.Redaction.CustomPatterns {
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
		if part.Export != nil {
			exports = append(exports, part.Export)
		}
		if part.TextExtraction != nil {
			enabled := *part.TextExtraction || plugins.TextExtraction != nil && *plugins.TextExtraction
			plugins.TextExtraction = &enabled
		}
		if part.Redaction == nil {
			continue
		}
		plugins.Redaction = selected
		for _, preset := range part.Redaction.Presets {
			presets[preset] = true
		}
		for _, pattern := range part.Redaction.CustomPatterns {
			patterns[pattern] = true
		}
		selected.Literals = append(selected.Literals, part.Redaction.Literals...)
	}
	if len(exports) > 0 {
		var err error
		plugins.Export, err = exportconfig.Combine(exports...)
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

// inspectionSetBy names the policies that set each combined setting outside
// rules. Where the smallest value or the stricter choice wins, that is the
// first policy that sets the winning value; where every policy's value
// combines, each policy that sets one. Ordering names its policy in
// routing.orderFrom.
func inspectionSetBy(entries []InspectionSource, sources []ScopedSource, compiled *Config) []map[string]any {
	var out []map[string]any
	add := func(setting string, mask Permission, all bool, same func(*Config) bool) {
		for i, entry := range sources {
			if entry.Value.settings&mask != 0 && same(entry.Value.Config) {
				out = append(out, map[string]any{"setting": setting, "policy": inspectionReference(entries[i])})
				if !all {
					return
				}
			}
		}
	}
	equal := func(value *int, other *int) bool { return value != nil && other != nil && *value == *other }
	always := func(*Config) bool { return true }
	if compiled.Access != nil && len(compiled.Access.Deny) > 0 {
		add("access", permissionAccess, true, func(c *Config) bool { return c.Access != nil && len(c.Access.Deny) > 0 })
	}
	if compiled.Input != nil {
		add("input", permissionInput, false, func(c *Config) bool { return c.Input != nil && c.Input.ASCIIOnly })
	}
	// Each plugin names the policies whose settings for it combine. A required
	// plugin replaces the defaults of that plugin alone.
	for _, plugin := range []struct {
		setting string
		unit    Permission
	}{{"plugins.export", permissionExport}, {"plugins.redaction", permissionRedaction}, {"plugins.textExtraction", permissionTextExtraction}} {
		for _, part := range compiled.PluginSources {
			if part.units()&plugin.unit != 0 {
				add(plugin.setting, plugin.unit, true, always)
				break
			}
		}
	}
	if compiled.Routing.AllowedCatalogNodes != nil {
		add("routing.allowedCatalogNodes", permissionNodes, true, func(c *Config) bool { return c.Routing.AllowedCatalogNodes != nil })
	}
	add("routing.fallbacks", permissionFallbacks, false, func(c *Config) bool { return c.Routing.Fallbacks == compiled.Routing.Fallbacks })
	if query := compiled.Routing.Query; query != nil && len(query.Filters) > 0 {
		add("routing.filter", permissionFilter, true, func(c *Config) bool { return c.Routing.Query != nil && len(c.Routing.Query.Filters) > 0 })
	}
	add("routing.missingEncryptionKeys", permissionMissingKeys, false, func(c *Config) bool {
		return c.Routing.MissingEncryptionKeys == compiled.Routing.MissingEncryptionKeys
	})
	add("routing.retries", permissionRetries, false, func(c *Config) bool { return c.Routing.Retries == compiled.Routing.Retries })
	if t := compiled.Timeouts; t != nil {
		add("timeouts.outputIdleSeconds", permissionOutputIdleTimeout, false, func(c *Config) bool {
			return c.Timeouts != nil && equal(c.Timeouts.OutputIdleSeconds, t.OutputIdleSeconds)
		})
		add("timeouts.totalSeconds", permissionTotalTimeout, false, func(c *Config) bool {
			return c.Timeouts != nil && equal(c.Timeouts.TotalSeconds, t.TotalSeconds)
		})
	}
	return out
}

type ruleKey struct {
	source int
	rule   string
}

// requirement is a required setting: a policy's own settings, which apply to
// every request, or a required rule's, which apply to the requests that its
// condition matches, or to every request without one.
type requirement struct {
	source int
	rule   string
	when   string
	kinds  Permission
}

// replacement names the requirement that replaces a default setting, and how
// many other requirements of the same reach replace it too. One that applies
// to every request comes first.
type replacement struct {
	setting string
	source  int
	rule    string
	when    string
	others  int
}

// maxNoteRules bounds the rule names that one note lists.
const maxNoteRules = 10

func requirements(sources []ScopedSource) []requirement {
	var required []requirement
	for i, entry := range sources {
		if entry.Value.settings != 0 {
			required = append(required, requirement{source: i, kinds: entry.Value.settings})
		}
		for _, rule := range entry.Value.Rules {
			if rule.Default || rule.Value.settings == 0 {
				continue
			}
			r := requirement{source: i, rule: rule.Name, kinds: rule.Value.settings}
			if rule.When != nil {
				r.when = rule.When.Source
			}
			required = append(required, r)
		}
	}
	return required
}

// replacedDefaults finds, for each default rule, its settings that a required
// setting of the same kind replaces, as request activation decides it: every
// policy's own settings and every required rule apply on the requests they
// match, and a default yields each kind that they set. Orderings are never
// replaced: a default ordering orders the ties that the others leave. Each
// replaced setting names one requirement, so the result grows with the
// defaults alone.
func replacedDefaults(documents []*SourceDocument, sources []ScopedSource, required []requirement) map[ruleKey][]replacement {
	type reach struct {
		always, sometimes   requirement
		alwaysN, sometimesN int
	}
	reaches := map[Permission]*reach{}
	out := map[ruleKey][]replacement{}
	for i, entry := range sources {
		for _, rule := range entry.Value.Rules {
			if !rule.Default {
				continue
			}
			key := ruleKey{i, rule.Name}
			for _, setting := range ruleSettings(documents[i].rules[rule.Name].fields) {
				kind := settingsMask(permissionSections[setting])
				if kind&orderingPermissions != 0 {
					continue
				}
				found := reaches[kind]
				if found == nil {
					found = &reach{}
					for _, r := range required {
						switch {
						case kind&r.kinds == 0:
						case r.when == "":
							if found.alwaysN == 0 {
								found.always = r
							}
							found.alwaysN++
						default:
							if found.sometimesN == 0 {
								found.sometimes = r
							}
							found.sometimesN++
						}
					}
					reaches[kind] = found
				}
				if found.alwaysN > 0 {
					out[key] = append(out[key], replacement{setting: setting, source: found.always.source, rule: found.always.rule, others: found.alwaysN - 1})
				} else if found.sometimesN > 0 {
					r := found.sometimes
					out[key] = append(out[key], replacement{setting: setting, source: r.source, rule: r.rule, when: r.when, others: found.sometimesN - 1})
				}
			}
		}
	}
	return out
}

// withoutOrdering copies a rule's fields without routing.order and
// routing.sort, and without routing when nothing else remains in it.
func withoutOrdering(fields map[string]json.RawMessage) map[string]json.RawMessage {
	var routing map[string]json.RawMessage
	if json.Unmarshal(fields["routing"], &routing) != nil {
		return fields
	}
	delete(routing, "order")
	delete(routing, "sort")
	out := maps.Clone(fields)
	if len(routing) == 0 {
		delete(out, "routing")
	} else if raw, err := json.Marshal(routing); err == nil {
		out["routing"] = raw
	}
	return out
}

// ruleSettings names a rule's settings as its fields hold them, sorted. Each
// plugin is its own setting, encrypted or not.
func ruleSettings(fields map[string]json.RawMessage) []string {
	var settings []string
	for name, raw := range fields {
		switch name {
		case "access", "input":
			settings = append(settings, name)
		case "plugins", "routing", "timeouts":
			var options map[string]json.RawMessage
			if json.Unmarshal(raw, &options) == nil {
				for option := range options {
					settings = append(settings, name+"."+option)
				}
			}
		}
	}
	sort.Strings(settings)
	return settings
}

// replacedNotes tells the edited policy which other policies' required
// settings replace its defaults: on every request, or with rules on the
// requests that they match. A setting replaced on every request is not
// repeated for the rules that replace it on some, orderings are never replaced,
// and the edited policy shows its own requirements.
func replacedNotes(entries []InspectionSource, documents []*SourceDocument, sources []ScopedSource, required []requirement, edit *InspectionEdit) []InspectionNote {
	edited := map[int]bool{}
	kinds := map[Permission][]string{}
	for i, entry := range entries {
		if !edit.covers(entry) {
			continue
		}
		edited[i] = true
		for _, rule := range sources[i].Value.Rules {
			if !rule.Default {
				continue
			}
			for _, setting := range ruleSettings(documents[i].rules[rule.Name].fields) {
				kind := settingsMask(permissionSections[setting])
				if kind&orderingPermissions == 0 && !slices.Contains(kinds[kind], setting) {
					kinds[kind] = append(kinds[kind], setting)
				}
			}
		}
	}
	always := map[int]map[string]bool{}
	sometimes := map[int]map[string]bool{}
	rules := map[int]map[string]bool{}
	add := func(sets map[int]map[string]bool, source int, value string) {
		if sets[source] == nil {
			sets[source] = map[string]bool{}
		}
		sets[source][value] = true
	}
	replacedAlways := map[string]bool{}
	for _, r := range required {
		for kind, settings := range kinds {
			if kind&r.kinds == 0 || r.when != "" {
				continue
			}
			for _, setting := range settings {
				replacedAlways[setting] = true
				if !edited[r.source] {
					add(always, r.source, setting)
				}
			}
		}
	}
	for _, r := range required {
		for kind, settings := range kinds {
			if kind&r.kinds == 0 || r.when == "" || edited[r.source] {
				continue
			}
			for _, setting := range settings {
				if !replacedAlways[setting] {
					add(sometimes, r.source, setting)
					add(rules, r.source, r.rule)
				}
			}
		}
	}
	keys := func(set map[string]bool) []string {
		values := make([]string, 0, len(set))
		for value := range set {
			values = append(values, value)
		}
		sort.Strings(values)
		return values
	}
	var notes []InspectionNote
	for i, entry := range entries {
		if settings := always[i]; settings != nil {
			notes = append(notes, InspectionNote{Kind: "replaced", Scope: entry.Scope, ID: entry.ID, Sections: keys(settings)})
		}
		if settings := sometimes[i]; settings != nil {
			note := InspectionNote{Kind: "replaced", Scope: entry.Scope, ID: entry.ID, Sections: keys(settings), Rules: keys(rules[i])}
			if len(note.Rules) > maxNoteRules {
				note.RuleCount, note.Rules = len(note.Rules), note.Rules[:maxNoteRules]
			}
			notes = append(notes, note)
		}
	}
	return notes
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
