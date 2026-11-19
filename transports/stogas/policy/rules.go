package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"
	"sort"
)

// Rules are unordered, named settings. Names identify conditional counters;
// neither a rule's name nor its position gives its settings precedence.
type Rule struct {
	Name      string
	When      *CELExpression
	Default   bool
	Value     *Source
	Encrypted *SourceDocument
	HasLimits bool
	// Exclude lists the resources whose keys skip the rule.
	Exclude map[Resource]struct{}
}

// exclusionKinds are the resources that a rule can exclude, under the names
// that delegation gives them. A credential is chosen for each attempt, and
// whoever manages members can give anyone a role, so neither can be listed.
var exclusionKinds = map[string]Scope{"folders": FolderScope, "grants": GrantScope, "members": MemberScope, "keys": KeyScope}

func parseExclusions(name string, raw json.RawMessage) (map[Resource]struct{}, error) {
	var lists map[string][]string
	if jsonv2.Unmarshal(raw, &lists) != nil || len(lists) == 0 {
		return nil, configError("rule %q exclude requires lists of folders, grants, members or keys", name)
	}
	excluded := map[Resource]struct{}{}
	for kind, ids := range lists {
		scope, ok := exclusionKinds[kind]
		if !ok || len(ids) == 0 {
			return nil, configError("rule %q exclude requires lists of folders, grants, members or keys", name)
		}
		for _, id := range ids {
			resource := Resource{scope, id}
			if _, listed := excluded[resource]; listed || !policyEntityID.MatchString(id) {
				return nil, configError("rule %q exclude requires distinct lowercase UUIDv7 IDs", name)
			}
			excluded[resource] = struct{}{}
		}
	}
	return excluded, nil
}

// excludedBy returns the first resource of the chain that the rule lists.
func (r Rule) excludedBy(chain []ScopedSource) (Resource, bool) {
	if r.Exclude == nil {
		return Resource{}, false
	}
	for _, entry := range chain {
		resource := Resource{entry.Scope, entry.ID}
		if _, listed := r.Exclude[resource]; listed {
			return resource, true
		}
	}
	return Resource{}, false
}

// excludable reports whether a policy of scope can exclude a kind of resource.
// A policy excludes only what lies under it, as it delegates: a folder holds
// grants and keys, and a grant its keys. Members use keys of every folder and
// grant, so each policy above them can list one.
func excludable(scope, kind Scope) bool {
	switch scope {
	case OrganizationScope:
		return true
	case FolderScope:
		return kind != FolderScope
	case GrantScope:
		return kind == MemberScope || kind == KeyScope
	}
	return false
}

func (s *Source) validateExclusions(scope Scope) error {
	for _, rule := range s.Rules {
		for resource := range rule.Exclude {
			if !excludable(scope, resource.Scope) {
				return configError("%s policies cannot exclude %ss from a rule", scope, resource.Scope)
			}
		}
	}
	return nil
}

// applyExclusions returns the chain without the rules that exclude one of its
// resources, so that a skipped rule requires, replaces and counts nothing. A
// source that loses rules is copied; its expressions, plugins and work
// allowance stay shared.
func applyExclusions(sources []ScopedSource) ([]ScopedSource, error) {
	applied := sources
	for i, entry := range sources {
		if entry.Value == nil || !entry.Value.excludes {
			continue
		}
		if err := entry.Value.validateExclusions(entry.Scope); err != nil {
			return nil, err
		}
		rules := slices.DeleteFunc(slices.Clone(entry.Value.Rules), func(rule Rule) bool {
			_, skipped := rule.excludedBy(sources)
			return skipped
		})
		if len(rules) == len(entry.Value.Rules) {
			continue
		}
		if len(applied) > 0 && &applied[0] == &sources[0] {
			applied = slices.Clone(sources)
		}
		source := *entry.Value
		source.Rules = rules
		applied[i].Value = &source
	}
	return applied, nil
}

type RuleMatch struct {
	Source int
	Name   string
}

var ErrUnknownCondition = errors.New("policy condition requires a catalog fact that is unavailable")

// UnknownConditionError locates a rule whose condition could not be decided.
type UnknownConditionError struct {
	Origin    Origin
	Condition string
}

func (e *UnknownConditionError) Error() string { return ErrUnknownCondition.Error() }
func (e *UnknownConditionError) Unwrap() error { return ErrUnknownCondition }

type ruleDocument struct {
	fields map[string]json.RawMessage
	source *SourceDocument
}

func parseRuleDocuments(raw json.RawMessage, envelopes map[[32]byte]encryptedPlugin) (map[string]ruleDocument, error) {
	if raw == nil {
		return nil, nil
	}
	var entries map[string]json.RawMessage
	if jsonv2.Unmarshal(raw, &entries) != nil || entries == nil || len(entries) == 0 {
		return nil, configError("rules require a nonempty object")
	}
	documents := make(map[string]ruleDocument, len(entries))
	for name, entry := range entries {
		if !policyName.MatchString(name) || name == "constructor" || name == "prototype" {
			return nil, configError("rule names require lowercase letters, digits, underscores or hyphens, starting with a letter")
		}
		var fields map[string]json.RawMessage
		if jsonv2.Unmarshal(entry, &fields) != nil || fields == nil {
			return nil, configError("rule %q requires an object", name)
		}
		settings := make(map[string]json.RawMessage, len(fields))
		for field, value := range fields {
			switch field {
			case "when", "mode", "exclude":
			case "limits", "routing", "plugins", "input", "access", "timeouts":
				settings[field] = value
			default:
				return nil, configError("unknown rule field %q", field)
			}
		}
		if len(settings) == 0 {
			return nil, configError("rule %q requires at least one setting", name)
		}
		document, err := sourceDocument(canonicalSourceFields(settings), settings, envelopes)
		if err != nil {
			return nil, err
		}
		documents[name] = ruleDocument{fields: fields, source: document}
	}
	return documents, nil
}

func compileRules(documents map[string]ruleDocument, plugins map[[32]byte]*Plugins, compiler *celCompiler) ([]Rule, error) {
	names := make([]string, 0, len(documents))
	for name := range documents {
		names = append(names, name)
	}
	sort.Strings(names)
	rules := make([]Rule, 0, len(names))
	for _, name := range names {
		document := documents[name]
		fields := document.fields
		rule := Rule{Name: name}
		if value, ok := fields["mode"]; ok {
			var mode string
			if json.Unmarshal(value, &mode) != nil || mode != "default" && mode != "required" {
				return nil, configError("rule mode must be required or default")
			}
			rule.Default = mode == "default"
		}
		if value, ok := fields["when"]; ok {
			var condition string
			if json.Unmarshal(value, &condition) != nil || condition == "" {
				return nil, configError("rule when requires a CEL condition")
			}
			var err error
			rule.When, err = compiler.compile(condition, true)
			if err != nil {
				return nil, err
			}
		}
		if value, ok := fields["exclude"]; ok {
			var err error
			rule.Exclude, err = parseExclusions(name, value)
			if err != nil {
				return nil, err
			}
		}
		rule.HasLimits = fields["limits"] != nil
		if rule.Default && rule.HasLimits {
			return nil, configError("shared limits must be required")
		}
		var err error
		rule.Value, err = document.source.compile(plugins, compiler)
		if err != nil {
			return nil, err
		}
		// One ordering applies to every request and candidate; sort expressions
		// can read request fields instead. One fallback count and one total
		// wait apply to every candidate, so only a condition on the request may
		// set them.
		if rule.Value.settings&permissionSort != 0 && (!rule.Default || rule.When != nil) {
			return nil, configError("rule %q can set routing.sort only with mode default and no when", name)
		}
		// Every default ordering of a chain applies, and composition places
		// each without reading rules.
		if rule.Value.settings&permissionSort != 0 && rule.Exclude != nil {
			return nil, configError("rule %q cannot set routing.sort with exclude", name)
		}
		if rule.When != nil && rule.When.candidate && rule.Value.settings&requestWidePermissions != 0 {
			return nil, configError("rule %q cannot set routing.fallbacks or timeouts.totalSeconds because its condition reads author, model, deployment, route, provider or credential fields", name)
		}
		if document.source.Encrypted() {
			// Its condition and readable settings can be evaluated without the
			// root. Open only the active, selected request's encrypted plugins.
			rule.Encrypted = document.source
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ConditionDigest separates counter populations after a condition edit while
// retaining their identity across whitespace and equivalent CEL formatting.
func (r Rule) ConditionDigest() string {
	condition := "true"
	if r.When != nil {
		condition = r.When.normalized
		if condition == "" {
			condition = r.When.Source
		}
	}
	digest := sha256.Sum256([]byte(condition))
	return hex.EncodeToString(digest[:])
}

// Activate resolves one candidate's rules before redaction or token counting.
// Each policy's budget is shared with its filters and sorting through Values. The
// returned configuration belongs to this request; cached sources stay immutable.
func (c *Config) Activate(values Values) (*Config, error) {
	if c == nil || !c.hasRules {
		return c, nil
	}
	active := append([]ScopedSource{}, c.sources...)
	var matches []RuleMatch
	var opaque []EncryptedPlugins
	for index, entry := range c.sources {
		for _, rule := range entry.Value.Rules {
			if rule.When == nil {
				if err := celBudget(values).charge(entry.Value.work, 1); err != nil {
					return nil, err
				}
			}
			if rule.When != nil {
				known, matched, _, err := rule.When.Evaluate(values, policyTime(values))
				if err != nil {
					return nil, err
				}
				if !known {
					return nil, &UnknownConditionError{Origin: Origin{Source: index, Rule: rule.Name}, Condition: rule.When.Source}
				}
				if !matched {
					continue
				}
			}
			part := *rule.Value
			part.defaultSettings = rule.Default
			part.encryptedPlugins = rule.Encrypted
			active = append(active, ScopedSource{Scope: entry.Scope, Value: &part, rule: rule.Name, policy: index})
			if rule.HasLimits {
				matches = append(matches, RuleMatch{Source: index, Name: rule.Name})
			}
		}
	}
	out, err := composeSettings(active)
	if err != nil {
		return nil, err
	}
	for i, entry := range active {
		// A default's encrypted plugin applies unless a requirement sets the
		// same plugin, as its readable plugins do.
		if document := entry.Value.encryptedPlugins; document != nil {
			if units := out.allowedSettings(entry.Value) & document.EncryptedUnits(); units != 0 {
				opaque = append(opaque, EncryptedPlugins{Document: document, Units: units, policy: policyPosition(entry, i)})
			}
		}
	}
	out.ActiveRules, out.ActiveEncryptedPlugins = matches, opaque
	out.sources, out.activated = active, true
	return out, nil
}

// pluginPermissions are every plugin section, the permission to encrypt one
// among them.
const pluginPermissions = pluginUnits | permissionEncryptedPlugins

// One order, fallback count and total wait apply to every candidate of a
// request. Each call's output idle wait and retries come from its own pair.
const requestWidePermissions = permissionSort | permissionFallbacks | permissionTotalTimeout

// settingsMask turns sections into the kinds of setting that combine. Each
// plugin is its own kind, encrypted or not.
func settingsMask(value Permission) Permission {
	return value & requestPermissions &^ permissionEncryptedPlugins
}

// ExpressionBytes charges every immutable program once per source.
func (s *Source) ExpressionBytes() int64 {
	if s == nil {
		return 0
	}
	seen := make(map[*CELExpression]bool)
	var total int64
	add := func(expression *CELExpression) {
		if expression != nil && !seen[expression] {
			seen[expression] = true
			total += expression.bytes
		}
	}
	s.Config.visitExpressions(add)
	if s.defaultOrdering != nil {
		for _, criterion := range s.defaultOrdering.sorts {
			add(criterion.expression)
		}
	}
	for _, rule := range s.Rules {
		add(rule.When)
		rule.Value.Config.visitExpressions(add)
	}
	return total
}
